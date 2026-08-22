module internal Fauli.Smb.Signing


open System
open System.Security.Cryptography
open System.Text

open Fauli.Domain


///
/// SMB2 dialect for signing algorithm selection.
type Dialect =
    | SMB202   // HMAC-SHA256 with session key directly (SMB 2.0.2)
    | SMB21    // HMAC-SHA256 with session key directly
    | SMB30    // AES-CMAC with derived signing key
    | SMB302   // AES-CMAC with derived signing key
    | SMB311   // AES-CMAC with derived signing key


///
/// How the last AES-CMAC block is finished ([RFC 4493] §2.4 / [MS-SMB2] §3.1.4.2).
type private LastBlockKind =
    | CompleteLastBlock
    | PaddedLastBlock


type private CmacLayout =
    { prefixCount : int
      lastKind : LastBlockKind }


///
/// Derive output bytes using NIST SP 800-108 KDF in Counter Mode.
/// Used by SMB3 to derive signing, encryption, and application keys from the session key.
///
/// Per [MS-SMB2] §3.1.1.4.1:
///   SMB3.1.1: label = "SMBSigningKey\0", context = preauthHash
///   SMB3.0/3.0.2: label = "SMB2AESCMAC\0", context = "SmbSign\0"
/// 
let internal kdfCounterMode (ki : byte array) (label : byte array) (context : byte array) (outputLength : int) : byte array =
    let h = 256  // HMAC-SHA256 output in bits
    let n = max 1 (outputLength / h)
    let rec loop i acc =
        match i > n with
        | true -> acc
        | false ->
            let counter = BitConverter.GetBytes(uint32 i) |> Array.rev  // big-endian
            let input = Array.concat [| counter; label; [| 0x00uy |]; context; BitConverter.GetBytes(uint32 outputLength) |> Array.rev |]
            use hmac = new HMACSHA256(ki)
            let k = hmac.ComputeHash(input)
            loop (i + 1) (Array.concat [| acc; k |])
    let raw = loop 1 [||]
    Array.sub raw 0 (outputLength / 8)


///
/// AES-CMAC block width (RFC 4493).
let private blockSize = 16


///
/// Rb for 128-bit CMAC: 0x87 in the last octet ([RFC 4493] §2.3).
let private xorConstRb (block : byte array) : byte array =
    Array.mapi (fun offset b ->
        match offset = blockSize - 1 with
        | true -> byte (int b ^^^ 0x87)
        | false -> b) block


///
/// Carry into `offset` is the former MSB of the next octet (0 at the last octet).
let private nextBitCarry (block : byte array) (offset : int) : int =
    match offset + 1 < blockSize with
    | true -> int block.[offset + 1] >>> 7
    | false -> 0


///
/// One-bit left shift of a 16-octet block, MSB discarded, zeros shifted in from the right.
let private leftShiftOneBit (block : byte array) : byte array =
    Array.init blockSize (fun offset ->
        byte (int block.[offset] <<< 1 &&& 0xFF ||| nextBitCarry block offset))


///
/// RFC 4493 dbl: L << 1, xor Rb when the original MSB was set.
let private doubleBlock (block : byte array) : byte array =
    match block.[0] &&& 0x80uy <> 0uy with
    | false -> leftShiftOneBit block
    | true -> block |> leftShiftOneBit |> xorConstRb


///
/// AES-128-ECB of one 16-octet block (no padding).
let private encryptBlock (key : byte array) (block : byte array) : byte array =
    use aes = Aes.Create()
    aes.Key <- key
    aes.Mode <- CipherMode.ECB
    aes.Padding <- PaddingMode.None
    aes.CreateEncryptor().TransformFinalBlock(block, 0, blockSize)


///
/// AES-128(K, 0^128) — the L value in [RFC 4493] §2.3.
let private encryptZeroBlock (key : byte array) : byte array =
    encryptBlock key (Array.zeroCreate blockSize)


///
/// Generate subkeys K1, K2 from the base key per RFC 4493 §2.3.
let internal generateSubkeys (key : byte array) : byte array * byte array =
    let k1 = doubleBlock (encryptZeroBlock key)
    k1, doubleBlock k1


///
/// Pad a partial last block for AES-CMAC: append 0x80 then zero-fill to 16 bytes.
/// Handles empty data (zero-length block) correctly per RFC 4493.
let private padBlock (data : byte array) : byte array =
    Array.init blockSize (fun i ->
        match i < data.Length, i = data.Length with
        | true, _ -> data.[i]
        | false, true -> 0x80uy
        | false, false -> 0uy)


///
/// XOR two 16-byte blocks.
let private xor128 (a : byte array) (b : byte array) : byte array =
    Array.init blockSize (fun i -> byte (int a.[i] ^^^ int b.[i]))


///
/// n = ceil(len/16) except empty → one padded block; full last block uses K1.
let private cmacLayout (message : byte array) : CmacLayout =
    match message.Length with
    | 0 -> { prefixCount = 0; lastKind = PaddedLastBlock }
    | n when n % blockSize = 0 -> { prefixCount = n / blockSize - 1; lastKind = CompleteLastBlock }
    | n -> { prefixCount = n / blockSize; lastKind = PaddedLastBlock }


let private sliceBlock (message : byte array) (index : int) : byte array =
    Array.sub message (index * blockSize) blockSize


let private lastRawBytes (message : byte array) (prefixCount : int) : byte array =
    match message.Length - prefixCount * blockSize with
    | rem when rem > 0 -> Array.sub message (prefixCount * blockSize) rem
    | _ -> [||]


let private finishLastBlock (k1 : byte array) (k2 : byte array) (message : byte array) (layout : CmacLayout) : byte array =
    match layout.lastKind with
    | CompleteLastBlock -> xor128 (sliceBlock message layout.prefixCount) k1
    | PaddedLastBlock -> xor128 (padBlock (lastRawBytes message layout.prefixCount)) k2


let private cbcEncrypt (key : byte array) (x : byte array) (block : byte array) : byte array =
    xor128 x block |> encryptBlock key


let private encryptPrefix (key : byte array) (message : byte array) (prefixCount : int) : byte array =
    Array.init prefixCount (sliceBlock message)
    |> Array.fold (cbcEncrypt key) (Array.zeroCreate blockSize)


///
/// AES-CMAC over the message ([RFC 4493] §2.4, [MS-SMB2] §3.1.4.2).
/// Empty or partial last block is padded and mixed with K2; a full last block uses K1.
let internal aesCmac (key : byte array) (message : byte array) : byte array =
    let k1, k2 = generateSubkeys key
    let layout = cmacLayout message
    finishLastBlock k1 k2 message layout
    |> xor128 (encryptPrefix key message layout.prefixCount)
    |> encryptBlock key


///
/// Derive the SMB signing key based on the negotiated dialect.
///
/// Per [MS-SMB2] §3.1.1.4.1:
///   SMB2.1 / SMB2.02: no derived key — use session key directly with HMAC-SHA256.
///   SMB3.0 / SMB3.0.2: KDF_CounterMode(sessionKey, "SMB2AESCMAC\0", "SmbSign\0", 128)
///   SMB3.1.1: KDF_CounterMode(sessionKey, "SMBSigningKey\0", preauthHash, 128)
///
/// Returns Some 16-byte signing key for SMB3.x, None for SMB2.1/SMB2.02.
/// 
let deriveSigningKey
        (dialect : Dialect)
        (sessionKey : byte array)
        (preauthHash : byte array option)
        : Result<byte array option, AuthError> =
    match dialect with
    | SMB202 | SMB21 ->
        None |> Ok
    | SMB30 | SMB302 | SMB311 ->
        let label =
            match dialect with
            | SMB311 -> Array.append (Encoding.ASCII.GetBytes "SMBSigningKey") [| 0uy |]
            | _ -> Array.append (Encoding.ASCII.GetBytes "SMB2AESCMAC") [| 0uy |]
        
        let context =
            match dialect with
            | SMB311 ->
                match preauthHash with
                | Some h -> h
                | None -> Array.zeroCreate<byte> 64
            | _ -> Array.append (Encoding.ASCII.GetBytes "SmbSign") [| 0uy |]
        
        let ki =
            if sessionKey.Length >= 16 then Array.sub sessionKey 0 16
            else sessionKey
        let signingKey = kdfCounterMode ki label context 128
        match signingKey.Length = 16 with
        | true -> Some signingKey |> Ok
        | false -> UnexpectedError $"Derived signing key has invalid length: {signingKey.Length}" |> Error


///
/// Compute the 16-byte SMB2 message signature.
///
/// SMB2.1 / SMB2.02: HMAC-SHA256(sessionKey, message)[0..15]
/// SMB3.x: AES-CMAC(signingKey, message)[0..15]
/// 
let computeSignature
        (dialect : Dialect)
        (sessionKey : byte array)
        (signingKey : byte array option)
        (message : byte array)
        : byte array =
    match dialect with
    | SMB202 | SMB21 ->
        use hmac = new HMACSHA256(sessionKey)
        hmac.ComputeHash(message) |> Array.take 16
    | SMB30 | SMB302 | SMB311 ->
        match signingKey with
        | Some sk -> aesCmac sk message
        | None -> Array.zeroCreate<byte> 16


///
/// Sign a complete SMB2 message (header + body).
///
/// Per [MS-SMB2] §3.2.4.1: the signature is computed over the message with
/// the signature field zeroed and the SMB2_FLAGS_SIGNED bit cleared, then
/// the signature is injected and the flag bit is set.
/// 
let signMessage (dialect : Dialect) (sessionKey : byte array) (signingKey : byte array option) (message : byte array) : byte array =
    let prepared = Array.copy message
    Array.Clear(prepared, 48, 16)
    prepared.[16] <- byte (int prepared.[16] ||| 0x08)  // SIGNED set during hash
    let signature = computeSignature dialect sessionKey signingKey prepared
    let signed = Array.copy prepared
    Array.Copy(signature, 0, signed, 48, 16)
    
    signed


///
/// Constant-time 16-byte compare (always visits every octet).
let private signaturesMatch (extracted : byte array) (expected : byte array) : bool =
    Array.fold2 (fun acc x y -> acc ||| int x ^^^ int y) 0 extracted expected = 0


///
/// Verify the signature on a received SMB2 message.
///
/// Extracts the signature from the header, clears both the signature field
/// and the SMB2_FLAGS_SIGNED bit, recomputes the signature over the message,
/// and performs a constant-time comparison.
let verifyMessageSignature (dialect : Dialect) (sessionKey : byte array) (signingKey : byte array option) (message : byte array) : bool =
    let extractedSignature = Array.sub message 48 16
    let verified = Array.copy message
    Array.Clear(verified, 48, 16)
    verified.[16] <- byte (int verified.[16] ||| 0x08)
    
    computeSignature dialect sessionKey signingKey verified
    |> signaturesMatch extractedSignature


///
/// Sign a message and verify it in one shot.
/// Useful for testing: proves sign + verify are consistent.
/// 
let signAndVerify (dialect : Dialect) (sessionKey : byte array) (signingKey : byte array option) (message : byte array) : bool =
    let signed = signMessage dialect sessionKey signingKey message
    verifyMessageSignature dialect sessionKey signingKey signed
