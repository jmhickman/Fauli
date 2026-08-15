/// SMB2/SMB3 message signing implementation.
/// Implements RFC 4493 (AES-CMAC), NIST SP 800-108 KDF, and [MS-SMB2] §3.2.4.1.
module internal Fauli.Smb.Signing

open System
open System.Security.Cryptography
open System.Text
open Fauli.Domain
open Fauli.Constants

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// SMB2 dialect for signing algorithm selection.
type Dialect =
    | SMB202   // HMAC-SHA256 with session key directly (SMB 2.0.2)
    | SMB21    // HMAC-SHA256 with session key directly
    | SMB30    // AES-CMAC with derived signing key
    | SMB302   // AES-CMAC with derived signing key
    | SMB311   // AES-CMAC with derived signing key

// ---------------------------------------------------------------------------
// NIST SP 800-108 KDF — Counter Mode with HMAC-SHA256 PRF
// ---------------------------------------------------------------------------

/// Derive output bytes using NIST SP 800-108 KDF in Counter Mode.
/// Used by SMB3 to derive signing, encryption, and application keys from the session key.
///
/// Per [MS-SMB2] §3.1.1.4.1:
///   SMB3.1.1: label = "SMBSigningKey\0", context = preauthHash
///   SMB3.0/3.0.2: label = "SMB2AESCMAC\0", context = "SmbSign\0"
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

// ---------------------------------------------------------------------------
// AES-CMAC (RFC 4493 / NIST SP 800-38B)
// ---------------------------------------------------------------------------

/// Generate subkeys K1, K2 from the base key per RFC 4493 §2.1.
let internal generateSubkeys (key : byte array) : byte array * byte array =
    use aes = Aes.Create()
    aes.Key <- key
    aes.Mode <- CipherMode.ECB
    aes.Padding <- PaddingMode.None

    let l = aes.CreateEncryptor().TransformFinalBlock(Array.zeroCreate<byte> 16, 0, 16)

        // BitConverter.ToUInt64 is little-endian on x86, so reverse each 8-byte half
    let lHigh = BitConverter.ToUInt64((l |> Array.take 8 |> Array.rev), 0)
    let lLow  = BitConverter.ToUInt64((l |> Array.skip 8 |> Array.rev), 0)

    let k1High = ((lHigh <<< 1) ||| (lLow >>> 63)) &&& 0xFFFFFFFFFFFFFFFFUL
    let k1Low  = (lLow  <<< 1) &&& 0xFFFFFFFFFFFFFFFFUL
    let k1 = Array.concat [BitConverter.GetBytes(k1High) |> Array.rev; BitConverter.GetBytes(k1Low) |> Array.rev]

    if (lHigh >>> 63) &&& 1UL <> 0UL then
        k1.[15] <- byte (int k1.[15] ^^^ 0x87)

    // Left-shift K1 to produce K2
    let k1High' = BitConverter.ToUInt64((k1 |> Array.take 8 |> Array.rev), 0)
    let k1Low'  = BitConverter.ToUInt64((k1 |> Array.skip 8 |> Array.rev), 0)

    let k2High = ((k1High' <<< 1) ||| (k1Low' >>> 63)) &&& 0xFFFFFFFFFFFFFFFFUL
    let k2Low  = (k1Low'  <<< 1) &&& 0xFFFFFFFFFFFFFFFFUL
    let k2 = Array.concat [BitConverter.GetBytes(k2High) |> Array.rev; BitConverter.GetBytes(k2Low) |> Array.rev]

    if (k1High' >>> 63) &&& 1UL <> 0UL then
        k2.[15] <- byte (int k2.[15] ^^^ 0x87)

    k1, k2

/// Pad a partial last block for AES-CMAC: append 0x80 then zero-fill to 16 bytes.
/// Handles empty data (zero-length block) correctly per RFC 4493.
let private padBlock (data : byte array) : byte array =
    let padded = Array.zeroCreate<byte> 16
    if data.Length > 0 then
        Array.Copy(data, 0, padded, 0, data.Length)
    if data.Length < 16 then
        padded.[data.Length] <- 0x80uy
    padded

/// XOR two 16-byte blocks.
let private xor128 (a : byte array) (b : byte array) : byte array =
    Array.init 16 (fun i -> byte (int a.[i] ^^^ int b.[i]))

/// Compute AES-CMAC over the message using the given 128-bit key.
/// Returns the full 16-byte MAC per RFC 4493 §3.
///
/// Compute AES-CMAC per [MS-SMB2] §3.1.4.2:
///   1. n = len(M) // 16  (integer division, NOT ceiling)
///   2. If n == 0: n = 1, flag = False (pad empty message with K2)
///   3. If len(M) % 16 == 0: flag = True (full last block, use K1)
///   4. Otherwise: n += 1, flag = False (partial last block, pad with K2)
let internal aesCmac (key : byte array) (message : byte array) : byte array =
    let blockSize = 16
    let zeros = Array.zeroCreate<byte> 16

    let k1, k2 = generateSubkeys key

    // Step 1: integer division for n (NOT ceiling)
    let n = message.Length / blockSize

    // Step 2-4: determine flag and adjust n
    let flag, n =
        if n = 0 then
            (false, 1)  // empty message: treat as 1 padded block
        elif message.Length % blockSize = 0 then
            (true, n)   // full last block
        else
            (false, n + 1)  // partial last block: increment n

    // Step 5: X = const_Zero
    let mutable x = zeros

    // Step 6: process blocks 1..n-1
    for i in 0 .. n - 2 do
        let blockStart = i * blockSize
        let block = Array.zeroCreate<byte> blockSize
        Array.Copy(message, blockStart, block, 0, blockSize)
        let y = xor128 x block
        use aes = Aes.Create()
        aes.Key <- key
        aes.Mode <- CipherMode.ECB
        aes.Padding <- PaddingMode.None
        x <- aes.CreateEncryptor().TransformFinalBlock(y, 0, blockSize)

    // Step 4 (continued): prepare last block M_last
    let lastBlockStart = (n - 1) * blockSize
    let lastBlock =
        if flag then
            // Full last block: M_n XOR K1
            let m_n = Array.zeroCreate<byte> blockSize
            Array.Copy(message, lastBlockStart, m_n, 0, blockSize)
            xor128 m_n k1
        else
            // Partial last block: pad(M_n) XOR K2
            // Pass only the actual data bytes to padBlock (0..blockSize-1 bytes)
            let remaining = message.Length - lastBlockStart
            let rawBlock = Array.zeroCreate<byte> remaining
            if remaining > 0 then
                Array.Copy(message, lastBlockStart, rawBlock, 0, remaining)
            xor128 (padBlock rawBlock) k2

    // Step 7: Y = M_last XOR X; T = AES-128(K, Y)
    let y = xor128 lastBlock x

    use aes = Aes.Create()
    aes.Key <- key
    aes.Mode <- CipherMode.ECB
    aes.Padding <- PaddingMode.None
    aes.CreateEncryptor().TransformFinalBlock(y, 0, blockSize)

// ---------------------------------------------------------------------------
// Signing key derivation
// ---------------------------------------------------------------------------

/// Derive the SMB signing key based on the negotiated dialect.
///
/// Per [MS-SMB2] §3.1.1.4.1:
///   SMB2.1 / SMB2.02: no derived key — use session key directly with HMAC-SHA256.
///   SMB3.0 / SMB3.0.2: KDF_CounterMode(sessionKey, "SMB2AESCMAC\0", "SmbSign\0", 128)
///   SMB3.1.1: KDF_CounterMode(sessionKey, "SMBSigningKey\0", preauthHash, 128)
///
/// Returns Some 16-byte signing key for SMB3.x, None for SMB2.1/SMB2.02.
let deriveSigningKey
        (dialect : Dialect)
        (sessionKey : byte array)
        (preauthHash : byte array option)
        : Result<byte array option, AuthError> =
    match dialect with
    | SMB202 | SMB21 ->
        // SMB 2.x: HMAC-SHA256 over session key directly — no derived key
        Ok None
    | SMB30 | SMB302 | SMB311 ->
        // SMB 3.x: AES-CMAC with KDF-derived signing key ([MS-SMB2] §3.1.4.2)
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

        // Session key material for KDF is the first 16 bytes (AES-128 CMAC key)
        let ki =
            if sessionKey.Length >= 16 then Array.sub sessionKey 0 16
            else sessionKey
        let signingKey = kdfCounterMode ki label context 128
        match signingKey.Length = 16 with
        | true -> Ok (Some signingKey)
        | false -> Error (UnexpectedError $"Derived signing key has invalid length: {signingKey.Length}")

// ---------------------------------------------------------------------------
// Signature computation
// ---------------------------------------------------------------------------

/// Compute the 16-byte SMB2 message signature.
///
/// SMB2.1 / SMB2.02: HMAC-SHA256(sessionKey, message)[0..15]
/// SMB3.x: AES-CMAC(signingKey, message)[0..15]
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

// ---------------------------------------------------------------------------
// Message signing
// ---------------------------------------------------------------------------

/// Sign a complete SMB2 message (header + body).
///
/// Per [MS-SMB2] §3.2.4.1: the signature is computed over the message with
/// the signature field zeroed and the SMB2_FLAGS_SIGNED bit cleared, then
/// the signature is injected and the flag bit is set.
let signMessage
        (dialect : Dialect)
        (sessionKey : byte array)
        (signingKey : byte array option)
        (message : byte array)
        : byte array =
    // HMAC-SHA256 signing for SMB 2.x — per [MS-SMB2] §3.1.4.1:
    //   1. Zero the Signature field
    //   2. Set SMB2_FLAGS_SIGNED in Flags BEFORE computing the hash
    //   3. HMAC-SHA256 (or AES-CMAC) over the full message
    //   4. Write first 16 bytes of the digest into Signature
    // Fauli previously cleared the SIGNED bit during hashing, which produced
    // signatures Windows rejects (STATUS_ACCESS_DENIED on TREE_CONNECT).
    let prepared = Array.copy message
    Array.Clear(prepared, 48, 16)
    prepared.[16] <- byte (int prepared.[16] ||| 0x08)  // SIGNED set during hash

    let signature = computeSignature dialect sessionKey signingKey prepared

    let signed = Array.copy prepared
    Array.Copy(signature, 0, signed, 48, 16)
    signed

/// Verify the signature on a received SMB2 message.
///
/// Extracts the signature from the header, clears both the signature field
/// and the SMB2_FLAGS_SIGNED bit, recomputes the signature over the message,
/// and performs a constant-time comparison.
let verifyMessageSignature
        (dialect : Dialect)
        (sessionKey : byte array)
        (signingKey : byte array option)
        (message : byte array)
        : bool =
    // Extract the signature stored in the header
    let extractedSignature = Array.sub message 48 16

    // Zero Signature; keep SMB2_FLAGS_SIGNED set (must match signMessage hashing input)
    let verified = Array.copy message
    Array.Clear(verified, 48, 16)
    verified.[16] <- byte (int verified.[16] ||| 0x08)

    let expectedSignature = computeSignature dialect sessionKey signingKey verified

    let mutable diff = 0
    for i in 0..15 do
        diff <- diff ||| (int extractedSignature.[i] ^^^ int expectedSignature.[i])
    diff = 0

// ---------------------------------------------------------------------------
// End-to-end signing verification
// ---------------------------------------------------------------------------

/// Sign a message and verify it in one shot.
/// Useful for testing: proves sign + verify are consistent.
let signAndVerify
        (dialect : Dialect)
        (sessionKey : byte array)
        (signingKey : byte array option)
        (message : byte array)
        : bool =
    let signed = signMessage dialect sessionKey signingKey message
    verifyMessageSignature dialect sessionKey signingKey signed
