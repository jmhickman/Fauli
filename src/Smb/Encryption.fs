/// SMB3 message encryption ([MS-SMB2] §3.1.4.3 / §2.2.41 TRANSFORM_HEADER).
/// AES-CCM / AES-GCM transform wrap and key derivation via NIST SP 800-108 KDF.
module internal Fauli.Smb.Encryption

open System
open System.Security.Cryptography
open System.Text
open Fauli.Domain
open Fauli.Smb.Signing

// ---------------------------------------------------------------------------
// Cipher identifiers ([MS-SMB2] §2.2.3.1.2)
// ---------------------------------------------------------------------------

/// Wire CipherId values from SMB2_ENCRYPTION_CAPABILITIES.
let cipherAes128Ccm = 0x0001us
let cipherAes128Gcm = 0x0002us
let cipherAes256Ccm = 0x0003us
let cipherAes256Gcm = 0x0004us

/// SMB2_SESSION_FLAG_ENCRYPT_DATA on SESSION_SETUP response SessionFlags.
let sessionFlagEncryptData = 0x0004us

/// SMB2_GLOBAL_CAP_ENCRYPTION on negotiate Capabilities.
let globalCapEncryption = 0x00000040u

/// TRANSFORM_HEADER Flags: encrypted (SMB 3.1.1+).
/// For SMB 3.0/3.0.2 the same 2-byte field carries EncryptionAlgorithm = AES128_CCM (0x0001).
let transformFlagEncrypted = 0x0001us

/// Map a negotiated CipherId to the domain cipher DU.
let cipherFromId (cipherId : uint16) : SmbCipher option =
    match cipherId with
    | id when id = cipherAes128Ccm -> Some Aes128Ccm
    | id when id = cipherAes128Gcm -> Some Aes128Gcm
    | id when id = cipherAes256Ccm -> Some Aes256Ccm
    | id when id = cipherAes256Gcm -> Some Aes256Gcm
    | _ -> None

let cipherIdOf (cipher : SmbCipher) : uint16 =
    match cipher with
    | Aes128Ccm -> cipherAes128Ccm
    | Aes128Gcm -> cipherAes128Gcm
    | Aes256Ccm -> cipherAes256Ccm
    | Aes256Gcm -> cipherAes256Gcm

let private isCcm (cipher : SmbCipher) : bool =
    match cipher with
    | Aes128Ccm | Aes256Ccm -> true
    | Aes128Gcm | Aes256Gcm -> false

let private nonceLength (cipher : SmbCipher) : int =
    if isCcm cipher then 11 else 12

let private keyBits (cipher : SmbCipher) : int =
    match cipher with
    | Aes128Ccm | Aes128Gcm -> 128
    | Aes256Ccm | Aes256Gcm -> 256

// ---------------------------------------------------------------------------
// Key derivation ([MS-SMB2] §3.1.4.2)
// ---------------------------------------------------------------------------

/// Derive C2S encryption key and S2C decryption key from the session key.
///
/// SMB 3.0 / 3.0.2:
///   EncryptionKey = KDF(SessionKey, "SMB2AESCCM\0", "ServerIn \0", L)
///   DecryptionKey = KDF(SessionKey, "SMB2AESCCM\0", "ServerOut\0", L)
/// SMB 3.1.1:
///   EncryptionKey = KDF(SessionKey, "SMBC2SCipherKey\0", PreauthHash, L)
///   DecryptionKey = KDF(SessionKey, "SMBS2CCipherKey\0", PreauthHash, L)
let deriveEncryptionKeys
        (dialect : Dialect)
        (sessionKey : byte array)
        (cipher : SmbCipher)
        (preauthHash : byte array option)
        : Result<byte array * byte array, AuthError> =
    let bits = keyBits cipher
    let keyLen = bits / 8
    let ki =
        if sessionKey.Length >= keyLen then Array.sub sessionKey 0 keyLen
        elif sessionKey.Length >= 16 then Array.sub sessionKey 0 16
        else sessionKey

    match dialect with
    | Dialect.SMB202 | Dialect.SMB21 ->
        Error (UnexpectedError "SMB encryption requires SMB 3.x")
    | Dialect.SMB311 ->
        let context =
            match preauthHash with
            | Some h when h.Length = 64 -> h
            | _ -> Array.zeroCreate<byte> 64
        let encLabel = Array.append (Encoding.ASCII.GetBytes "SMBC2SCipherKey") [| 0uy |]
        let decLabel = Array.append (Encoding.ASCII.GetBytes "SMBS2CCipherKey") [| 0uy |]
        let encKey = kdfCounterMode ki encLabel context bits
        let decKey = kdfCounterMode ki decLabel context bits
        if encKey.Length = keyLen && decKey.Length = keyLen then Ok (encKey, decKey)
        else Error (UnexpectedError "SMB 3.1.1 encryption KDF produced unexpected key length")
    | Dialect.SMB30 | Dialect.SMB302 ->
        // Note trailing space in "ServerIn " per MS-SMB2.
        let label = Array.append (Encoding.ASCII.GetBytes "SMB2AESCCM") [| 0uy |]
        let encCtx = Array.append (Encoding.ASCII.GetBytes "ServerIn ") [| 0uy |]
        let decCtx = Array.append (Encoding.ASCII.GetBytes "ServerOut") [| 0uy |]
        let encKey = kdfCounterMode ki label encCtx bits
        let decKey = kdfCounterMode ki label decCtx bits
        if encKey.Length = keyLen && decKey.Length = keyLen then Ok (encKey, decKey)
        else Error (UnexpectedError "SMB 3.0 encryption KDF produced unexpected key length")

/// Build SmbEncryption state when the session requires (or enforces) encryption.
let tryBuildEncryption
        (dialect : Dialect)
        (sessionKey : byte array)
        (cipherId : uint16)
        (preauthHash : byte array option)
        (encryptData : bool)
        : Result<SmbEncryption option, AuthError> =
    match encryptData with
    | false -> Ok None
    | true ->
        match cipherFromId cipherId with
        | None -> Error (UnexpectedError $"Unsupported SMB cipher id 0x{cipherId:X4}")
        | Some cipher ->
            match deriveEncryptionKeys dialect sessionKey cipher preauthHash with
            | Error e -> Error e
            | Ok (encKey, decKey) ->
                Ok
                    (Some
                        { Cipher = cipher
                          EncryptionKey = encKey
                          DecryptionKey = decKey })

// ---------------------------------------------------------------------------
// TRANSFORM_HEADER encrypt / decrypt
// ---------------------------------------------------------------------------

let private le16 (v : uint16) : byte array = BitConverter.GetBytes(v)
let private le32 (v : uint32) : byte array = BitConverter.GetBytes(v)
let private le64 (v : uint64) : byte array = BitConverter.GetBytes(v)

/// Build the 52-byte SMB2 TRANSFORM_HEADER with a zeroed Signature field.
/// Layout: ProtocolId(4) Signature(16) Nonce(16) OriginalMessageSize(4)
///         Reserved(2) FlagsOrAlg(2) SessionId(8) = 52 bytes.
let private buildTransformHeaderSkeleton (nonce16 : byte array) (plainLen : int) (flagsOrAlg : uint16) (sessionId : uint64) : byte array =
    let h = Array.zeroCreate<byte> 52
    Array.Copy(Fauli.Constants.smbTransformHeaderMagic, 0, h, 0, 4)  // 0xFD + "SMB"
    // Signature [4..19] left zero until AEAD tag is written
    Array.Copy(nonce16, 0, h, 20, 16)
    Array.Copy(le32 (uint32 plainLen), 0, h, 36, 4)
    // Reserved @ 40 = 0
    Array.Copy(le16 flagsOrAlg, 0, h, 42, 2)
    Array.Copy(le64 sessionId, 0, h, 44, 8)
    h

/// AAD for AES-CCM/GCM is TRANSFORM_HEADER bytes from offset 20 through 51
/// (Nonce || OriginalMessageSize || Reserved || Flags || SessionId) — 32 bytes.
/// MS-SMB2 / Windows use the portion starting after ProtocolId+Signature.
let private transformAad (header : byte array) : byte array =
    Array.sub header 20 32

/// Encrypt a full SMB2 message (header+body) into a TRANSFORM_HEADER packet.
let encryptSmbMessage (encryption : SmbEncryption) (sessionId : uint64) (plainSmb2 : byte array) : byte array =
    let nLen = nonceLength encryption.Cipher
    let nonce = RandomNumberGenerator.GetBytes(nLen)
    let nonce16 = Array.zeroCreate<byte> 16
    Array.Copy(nonce, 0, nonce16, 0, nLen)

    // SMB 3.0/3.0.2: field is EncryptionAlgorithm (AES128_CCM = 1).
    // SMB 3.1.1+: field is Flags (ENCRYPTED = 1). Same wire value for AES-128-CCM.
    let flagsOrAlg =
        match encryption.Cipher with
        | Aes128Ccm -> cipherAes128Ccm
        | _ -> transformFlagEncrypted

    let header = buildTransformHeaderSkeleton nonce16 plainSmb2.Length flagsOrAlg sessionId
    let aad = transformAad header
    let ciphertext = Array.zeroCreate<byte> plainSmb2.Length
    let tag = Array.zeroCreate<byte> 16

    match encryption.Cipher with
    | Aes128Ccm | Aes256Ccm ->
        use ccm = new AesCcm(encryption.EncryptionKey)
        ccm.Encrypt(nonce, plainSmb2, ciphertext, tag, aad)
    | Aes128Gcm | Aes256Gcm ->
        use gcm = new AesGcm(encryption.EncryptionKey, 16)
        gcm.Encrypt(nonce, plainSmb2, ciphertext, tag, aad)

    Array.Copy(tag, 0, header, 4, 16)
    let packet = Array.zeroCreate<byte> (52 + ciphertext.Length)
    Array.Copy(header, 0, packet, 0, 52)
    Array.Copy(ciphertext, 0, packet, 52, ciphertext.Length)
    packet

/// Decrypt a TRANSFORM_HEADER packet back to the plain SMB2 message.
let decryptSmbMessage (encryption : SmbEncryption) (transformPacket : byte array) : Result<byte array, AuthError> =
    try
        if transformPacket.Length < 52 then
            Error (UnexpectedError "SMB transform packet too short")
        elif transformPacket.[0] <> Fauli.Constants.smbTransformHeaderMagic.[0] then
            Error (UnexpectedError "Not an SMB2 TRANSFORM_HEADER")
        else
            let header = Array.sub transformPacket 0 52
            let tag = Array.sub header 4 16
            let nonce16 = Array.sub header 20 16
            let originalSize = int (BitConverter.ToUInt32(header, 36))
            let nLen = nonceLength encryption.Cipher
            let nonce = Array.sub nonce16 0 nLen
            let aad = transformAad header
            let ciphertext =
                if 52 + originalSize <= transformPacket.Length then
                    Array.sub transformPacket 52 originalSize
                else
                    Array.sub transformPacket 52 (transformPacket.Length - 52)
            let plain = Array.zeroCreate<byte> ciphertext.Length
            match encryption.Cipher with
            | Aes128Ccm | Aes256Ccm ->
                use ccm = new AesCcm(encryption.DecryptionKey)
                ccm.Decrypt(nonce, ciphertext, tag, plain, aad)
            | Aes128Gcm | Aes256Gcm ->
                use gcm = new AesGcm(encryption.DecryptionKey, 16)
                gcm.Decrypt(nonce, ciphertext, tag, plain, aad)
            Ok plain
    with
    | :? CryptographicException as ex ->
        Error (UnexpectedError $"SMB decrypt failed: {ex.Message}")
    | ex ->
        Error (UnexpectedError $"SMB decrypt error: {ex.Message}")

/// True when the NetBIOS payload is an encrypted transform (0xFD 'SMB').
let isTransformPacket (data : byte array) : bool =
    data.Length >= 4
    && data.[0] = Fauli.Constants.smbTransformHeaderMagic.[0]
    && data.[1] = 0x53uy
    && data.[2] = 0x4Duy
    && data.[3] = 0x42uy
