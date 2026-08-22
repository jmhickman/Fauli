module internal Fauli.Smb.Encryption


open System
open System.Security.Cryptography
open System.Text

open Fauli.Domain
open Fauli.Smb.Signing


///
/// Wire CipherId values from SMB2_ENCRYPTION_CAPABILITIES.
let cipherAes128Ccm = 0x0001us


let cipherAes128Gcm = 0x0002us


let cipherAes256Ccm = 0x0003us


let cipherAes256Gcm = 0x0004us


///
/// SMB2_SESSION_FLAG_ENCRYPT_DATA on SESSION_SETUP response SessionFlags.
let sessionFlagEncryptData = 0x0004us


///
/// SMB2_GLOBAL_CAP_ENCRYPTION on negotiate Capabilities.
let globalCapEncryption = 0x00000040u


///
/// TRANSFORM_HEADER Flags: encrypted (SMB 3.1.1+).
/// For SMB 3.0/3.0.2 the same 2-byte field carries EncryptionAlgorithm = AES128_CCM (0x0001).
/// 
let transformFlagEncrypted = 0x0001us


///
/// Parsed SMB2 TRANSFORM_HEADER + ciphertext ([MS-SMB2] §2.2.41).
type private TransformPacket =
    { header : byte array
      tag : byte array
      nonce : byte array
      ciphertext : byte array }


///
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


let private nonceLength (cipher : SmbCipher) : int =
    match cipher with
    | Aes128Ccm | Aes256Ccm -> 11
    | Aes128Gcm | Aes256Gcm -> 12


let private keyBits (cipher : SmbCipher) : int =
    match cipher with
    | Aes128Ccm | Aes128Gcm -> 128
    | Aes256Ccm | Aes256Gcm -> 256


let private asciiZ (s : string) : byte array =
    Array.append (Encoding.ASCII.GetBytes s) [| 0uy |]


let private sessionKeyMaterial (keyLen : int) (sessionKey : byte array) : byte array =
    match sessionKey.Length >= keyLen, sessionKey.Length >= 16 with
    | true, _ -> Array.sub sessionKey 0 keyLen
    | false, true -> Array.sub sessionKey 0 16
    | false, false -> sessionKey


let private keysOfExpectedLength (keyLen : int) (fail : string) (encKey : byte array) (decKey : byte array) : Result<byte array * byte array, AuthError> =
    match encKey.Length = keyLen && decKey.Length = keyLen with
    | true -> (encKey, decKey) |> Ok
    | false -> UnexpectedError fail |> Error


let private smb311Keys (ki : byte array) (bits : int) (keyLen : int) (preauthHash : byte array option) : Result<byte array * byte array, AuthError> =
    let context =
        match preauthHash with
        | Some h when h.Length = 64 -> h
        | _ -> Array.zeroCreate 64
    
    keysOfExpectedLength keyLen "SMB 3.1.1 encryption KDF produced unexpected key length"
        (kdfCounterMode ki (asciiZ "SMBC2SCipherKey") context bits)
        (kdfCounterMode ki (asciiZ "SMBS2CCipherKey") context bits)


let private smb30Keys (ki : byte array) (bits : int) (keyLen : int) : Result<byte array * byte array, AuthError> =
    let label = asciiZ "SMB2AESCCM"
    keysOfExpectedLength keyLen "SMB 3.0 encryption KDF produced unexpected key length"
        (kdfCounterMode ki label (asciiZ "ServerIn ") bits)
        (kdfCounterMode ki label (asciiZ "ServerOut") bits)


///
/// Derive C2S encryption key and S2C decryption key from the session key.
///
/// SMB 3.0 / 3.0.2:
///   EncryptionKey = KDF(SessionKey, "SMB2AESCCM\0", "ServerIn \0", L)
///   DecryptionKey = KDF(SessionKey, "SMB2AESCCM\0", "ServerOut\0", L)
/// SMB 3.1.1:
///   EncryptionKey = KDF(SessionKey, "SMBC2SCipherKey\0", PreauthHash, L)
///   DecryptionKey = KDF(SessionKey, "SMBS2CCipherKey\0", PreauthHash, L)
let deriveEncryptionKeys (dialect : Dialect) (sessionKey : byte array) (cipher : SmbCipher) (preauthHash : byte array option) : Result<byte array * byte array, AuthError> =
    let bits = keyBits cipher
    let keyLen = bits / 8
    let ki = sessionKeyMaterial keyLen sessionKey
    match dialect with
    | SMB202 | SMB21 -> UnexpectedError "SMB encryption requires SMB 3.x" |> Error
    | SMB311 -> smb311Keys ki bits keyLen preauthHash
    | SMB30 | SMB302 -> smb30Keys ki bits keyLen


let private encryptionState (cipher : SmbCipher) (encKey : byte array, decKey : byte array) : SmbEncryption =
    { Cipher = cipher
      EncryptionKey = encKey
      DecryptionKey = decKey }


let private requireCipher (cipherId : uint16) : Result<SmbCipher, AuthError> =
    match cipherFromId cipherId with
    | Some cipher -> cipher |> Ok
    | None -> UnexpectedError $"Unsupported SMB cipher id 0x{cipherId:X4}" |> Error


let private deriveEncryption (dialect : Dialect) (sessionKey : byte array) (preauthHash : byte array option) (cipher : SmbCipher) : Result<SmbEncryption, AuthError> =
    deriveEncryptionKeys dialect sessionKey cipher preauthHash
    |> Result.map (encryptionState cipher)


///
/// Build SmbEncryption state when the session requires (or enforces) encryption.
let tryBuildEncryption (dialect : Dialect) (sessionKey : byte array) (cipherId : uint16) (preauthHash : byte array option) (encryptData : bool) : Result<SmbEncryption option, AuthError> =
    match encryptData with
    | false -> None |> Ok
    | true ->
        cipherId
        |> requireCipher
        |> Result.bind (deriveEncryption dialect sessionKey preauthHash)
        |> Result.map Some


let private le16 (v : uint16) : byte array = BitConverter.GetBytes(v)


let private le32 (v : uint32) : byte array = BitConverter.GetBytes(v)


let private le64 (v : uint64) : byte array = BitConverter.GetBytes(v)


///
/// Build the 52-byte SMB2 TRANSFORM_HEADER with a zeroed Signature field.
/// Layout: ProtocolId(4) Signature(16) Nonce(16) OriginalMessageSize(4)
///         Reserved(2) FlagsOrAlg(2) SessionId(8) = 52 bytes.
/// 
let private buildTransformHeaderSkeleton (nonce16 : byte array) (plainLen : int) (flagsOrAlg : uint16) (sessionId : uint64) : byte array =
    let h = Array.zeroCreate<byte> 52
    Array.Copy(Fauli.Constants.smbTransformHeaderMagic, 0, h, 0, 4)  // 0xFD + "SMB"
    Array.Copy(nonce16, 0, h, 20, 16)
    Array.Copy(le32 (uint32 plainLen), 0, h, 36, 4)
    Array.Copy(le16 flagsOrAlg, 0, h, 42, 2)
    Array.Copy(le64 sessionId, 0, h, 44, 8)
    
    h


///
/// AAD for AES-CCM/GCM is TRANSFORM_HEADER bytes from offset 20 through 51
/// (Nonce || OriginalMessageSize || Reserved || Flags || SessionId) — 32 bytes.
/// MS-SMB2 / Windows use the portion starting after ProtocolId+Signature.
/// 
let private transformAad (header : byte array) : byte array =
    Array.sub header 20 32


///
/// Encrypt a full SMB2 message (header+body) into a TRANSFORM_HEADER packet.
let encryptSmbMessage (encryption : SmbEncryption) (sessionId : uint64) (plainSmb2 : byte array) : byte array =
    let nLen = nonceLength encryption.Cipher
    let nonce = RandomNumberGenerator.GetBytes(nLen)
    let nonce16 = Array.zeroCreate<byte> 16
    Array.Copy(nonce, 0, nonce16, 0, nLen)
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


///
/// True when the NetBIOS payload is an encrypted transform (0xFD 'SMB').
let isTransformPacket (data : byte array) : bool =
    match data.Length >= 4 with
    | false -> false
    | true -> Array.sub data 0 4 = Fauli.Constants.smbTransformHeaderMagic


let private ciphertextSlice (packet : byte array) (originalSize : int) : byte array =
    match 52 + originalSize <= packet.Length with
    | true -> Array.sub packet 52 originalSize
    | false -> Array.sub packet 52 (packet.Length - 52)


let private parsedTransform (cipher : SmbCipher) (packet : byte array) : TransformPacket =
    let header = Array.sub packet 0 52
    { header = header
      tag = Array.sub header 4 16
      nonce = Array.sub header 20 (nonceLength cipher)
      ciphertext = ciphertextSlice packet (int (BitConverter.ToUInt32(header, 36))) }


let private transformFromLongPacket (cipher : SmbCipher) (packet : byte array) : Result<TransformPacket, AuthError> =
    match isTransformPacket packet with
    | false -> UnexpectedError "Not an SMB2 TRANSFORM_HEADER" |> Error
    | true -> parsedTransform cipher packet |> Ok


let private parseTransform (cipher : SmbCipher) (packet : byte array) : Result<TransformPacket, AuthError> =
    match packet.Length < 52 with
    | true -> UnexpectedError "SMB transform packet too short" |> Error
    | false -> transformFromLongPacket cipher packet


let private decryptCiphertext (encryption : SmbEncryption) (parsed : TransformPacket) : byte array =
    let aad = transformAad parsed.header
    let plain = Array.zeroCreate parsed.ciphertext.Length
    match encryption.Cipher with
    | Aes128Ccm | Aes256Ccm ->
        use ccm = new AesCcm(encryption.DecryptionKey)
        ccm.Decrypt(parsed.nonce, parsed.ciphertext, parsed.tag, plain, aad)
    | Aes128Gcm | Aes256Gcm ->
        use gcm = new AesGcm(encryption.DecryptionKey, 16)
        gcm.Decrypt(parsed.nonce, parsed.ciphertext, parsed.tag, plain, aad)
    
    plain


///
/// Decrypt a TRANSFORM_HEADER packet back to the plain SMB2 message.
/// AesCcm/AesGcm raise CryptographicException on tag mismatch (wrong key or tamper).
let decryptSmbMessage (encryption : SmbEncryption) (transformPacket : byte array) : Result<byte array, AuthError> =
    match parseTransform encryption.Cipher transformPacket with
    | Error e -> e |> Error
    | Ok parsed ->
        try decryptCiphertext encryption parsed |> Ok
        with
        | :? CryptographicException as ex -> UnexpectedError $"SMB decrypt failed: {ex.Message}" |> Error
