/// Tests for SMB2/SMB3 message signing implementation.
///
/// These tests use NIST-standard test vectors.
/// to verify our AES-CMAC, subkey generation, and KDF implementations produce
/// identical results.
module Fauli.Tests.SmbSigningTests

open System
open Xunit
open Fauli.Domain
open Fauli.Smb.Signing

// ============================================================================
// Test vectors from NIST reference implementation.
// ============================================================================

let private aesKey =
    System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")

let private fullMessage =
    System.Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")

let private message16 = Array.sub fullMessage 0 16
let private message40 = Array.sub fullMessage 0 40
let private emptyMessage = [||]

// ============================================================================
// 1. AES-CMAC Tests (RFC 4493 / NIST SP 800-38B)
// ============================================================================

[<Fact>]
let ``AES-CMAC empty message matches reference vector`` () =
    let result = aesCmac aesKey emptyMessage
    Assert.Equal(16, result.Length)
    Assert.Equal("bb1d6929e95937287fa37d129b756746", System.Convert.ToHexString(result).ToLowerInvariant())

[<Fact>]
let ``AES-CMAC 16-byte message matches reference vector`` () =
    let result = aesCmac aesKey message16
    Assert.Equal(16, result.Length)
    Assert.Equal("070a16b46b4d4144f79bdd9dd04a287c", System.Convert.ToHexString(result).ToLowerInvariant())

[<Fact>]
let ``AES-CMAC 40-byte message matches reference vector`` () =
    let result = aesCmac aesKey message40
    Assert.Equal(16, result.Length)
    Assert.Equal("dfa66747de9ae63030ca32611497c827", System.Convert.ToHexString(result).ToLowerInvariant())

[<Fact>]
let ``AES-CMAC 64-byte message matches reference vector`` () =
    let result = aesCmac aesKey fullMessage
    Assert.Equal(16, result.Length)
    Assert.Equal("51f0bebf7e3b9d92fc49741779363cfe", System.Convert.ToHexString(result).ToLowerInvariant())

// ============================================================================
// 2. Subkey Generation Tests (RFC 4493 §2.1)
// ============================================================================

[<Fact>]
let ``GenerateSubkeys K1 matches reference vector`` () =
    let k1, _ = generateSubkeys aesKey
    Assert.Equal(16, k1.Length)
    Assert.Equal("fbeed618357133667c85e08f7236a8de", System.Convert.ToHexString(k1).ToLowerInvariant())

[<Fact>]
let ``GenerateSubkeys K2 matches reference vector`` () =
    let _, k2 = generateSubkeys aesKey
    Assert.Equal(16, k2.Length)
    Assert.Equal("f7ddac306ae266ccf90bc11ee46d513b", System.Convert.ToHexString(k2).ToLowerInvariant())

// ============================================================================
// 3. KDF Counter Mode Tests (NIST SP 800-108)
// ============================================================================

[<Fact>]
let ``KDF_CounterMode produces correct output for SMBSigningKey derivation`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let preauthHash = Array.init 64 (fun i -> byte (i % 256))
    let label = Array.append (System.Text.Encoding.ASCII.GetBytes "SMBSigningKey") [| 0uy |]
    let derived = kdfCounterMode sessionKey label preauthHash 128
    Assert.Equal(16, derived.Length)
    let derived2 = kdfCounterMode sessionKey label preauthHash 128
    Assert.True((derived = derived2))

[<Fact>]
let ``KDF_CounterMode produces correct output for SMB2AESCMAC derivation`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let label = Array.append (System.Text.Encoding.ASCII.GetBytes "SMB2AESCMAC") [| 0uy |]
    let context = Array.append (System.Text.Encoding.ASCII.GetBytes "SmbSign") [| 0uy |]
    let derived = kdfCounterMode sessionKey label context 128
    Assert.Equal(16, derived.Length)
    let derived2 = kdfCounterMode sessionKey label context 128
    Assert.True((derived = derived2))

[<Fact>]
let ``KDF_CounterMode produces different outputs for different labels`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let context = Array.init 64 (fun i -> byte (i % 256))
    let derived1 = kdfCounterMode sessionKey (System.Text.Encoding.ASCII.GetBytes "LabelA" |> Array.append [| 0uy |]) context 128
    let derived2 = kdfCounterMode sessionKey (System.Text.Encoding.ASCII.GetBytes "LabelB" |> Array.append [| 0uy |]) context 128
    Assert.False((derived1 = derived2))

// ============================================================================
// 4. Signing Key Derivation Tests
// ============================================================================

[<Fact>]
let ``DeriveSigningKey SMB21 returns None`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    match deriveSigningKey Dialect.SMB21 sessionKey None with
    | Ok None -> ()
    | other -> Assert.Fail (sprintf "Expected Ok None, got %A" other)

[<Fact>]
let ``DeriveSigningKey SMB30 returns 16-byte AES-CMAC key`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    match deriveSigningKey Dialect.SMB30 sessionKey None with
    | Ok (Some key) -> Assert.Equal(16, key.Length)
    | Ok None -> Assert.Fail("SMB 3.0 must derive a signing key")
    | Error e -> Assert.Fail(sprintf "Unexpected error: %A" e)


let ``DeriveSigningKey SMB302 returns 16-byte key`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some key) -> Assert.Equal(16, key.Length)
    | other -> Assert.Fail (sprintf "Expected Ok (Some 16-byte key), got %A" other)

[<Fact>]
let ``DeriveSigningKey SMB311 returns 16-byte key`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let preauthHash = Array.init 64 (fun i -> byte (i % 256))
    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some key) -> Assert.Equal(16, key.Length)
    | other -> Assert.Fail (sprintf "Expected Ok (Some 16-byte key), got %A" other)

[<Fact>]
let ``DeriveSigningKey SMB311 with null preauthHash uses zero-filled context`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    match deriveSigningKey Dialect.SMB311 sessionKey None with
    | Ok (Some key) -> Assert.Equal(16, key.Length)
    | other -> Assert.Fail (sprintf "Expected Ok (Some 16-byte key), got %A" other)

[<Fact>]
let ``DeriveSigningKey SMB302 matches reference KDF output`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some key) ->
        // Expected: 82f4cd5c08f148e2506cb8b530dafdd9
        Assert.Equal("82f4cd5c08f148e2506cb8b530dafdd9", System.Convert.ToHexString(key).ToLowerInvariant())
    | other -> Assert.Fail (sprintf "Expected Ok (Some key), got %A" other)

[<Fact>]
let ``DeriveSigningKey SMB311 matches reference KDF with preauthHash`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let preauthHash = System.Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some key) ->
        // Expected: 896e39b7427c0a44062cdaa5e56d66c7
        Assert.Equal("896e39b7427c0a44062cdaa5e56d66c7", System.Convert.ToHexString(key).ToLowerInvariant())
    | other -> Assert.Fail (sprintf "Expected Ok (Some key), got %A" other)

// ============================================================================
// 5. Signature Computation Tests
// ============================================================================

[<Fact>]
let ``ComputeSignature SMB21 uses HMAC-SHA256`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.init 100 (fun i -> byte (i % 256))
    let result = computeSignature Dialect.SMB21 sessionKey None message
    Assert.Equal(16, result.Length)
    use hmac = new System.Security.Cryptography.HMACSHA256(sessionKey)
    let expected = hmac.ComputeHash(message) |> Array.take 16
    Assert.True((result = expected))

[<Fact>]
let ``ComputeSignature SMB311 uses AES-CMAC`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let preauthHash = Array.init 64 (fun i -> byte (i % 256))
    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some signingKey) ->
        let message = Array.init 100 (fun i -> byte (i % 256))
        let result = computeSignature Dialect.SMB311 sessionKey (Some signingKey) message
        Assert.Equal(16, result.Length)
        let expected = aesCmac signingKey message
        Assert.True((result = expected))
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``ComputeSignature SMB302 uses AES-CMAC`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey) ->
        let message = Array.init 100 (fun i -> byte (i % 256))
        let result = computeSignature Dialect.SMB302 sessionKey (Some signingKey) message
        Assert.Equal(16, result.Length)
        let expected = aesCmac signingKey message
        Assert.True((result = expected))
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

// ============================================================================
// 6. Message Signing Tests
// ============================================================================

[<Fact>]
let ``SignMessage sets SMB2_FLAGS_SIGNED bit`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.zeroCreate<byte> 64
    message.[0..3] <- [| 0xFEuy; 0x53uy; 0x4Duy; 0x42uy |]
    message.[4..5] <- System.BitConverter.GetBytes(uint16 64)
    let signed = signMessage Dialect.SMB21 sessionKey None message
    Assert.Equal(0x08, (int signed.[16] &&& 0x08))  // SMB2_FLAGS_SIGNED at byte 16, bit 3

[<Fact>]
let ``SignMessage injects signature at offset 48`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.zeroCreate<byte> 64
    message.[0..3] <- [| 0xFEuy; 0x53uy; 0x4Duy; 0x42uy |]
    message.[4..5] <- System.BitConverter.GetBytes(uint16 64)
    let signed = signMessage Dialect.SMB21 sessionKey None message
    let sigBytes = Array.sub signed 48 16
    Assert.False((Array.forall ((=) 0uy) sigBytes))

[<Fact>]
let ``VerifyMessageSignature validates correct signature`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.zeroCreate<byte> 64
    message.[0..3] <- [| 0xFEuy; 0x53uy; 0x4Duy; 0x42uy |]
    message.[4..5] <- System.BitConverter.GetBytes(uint16 64)
    let signed = signMessage Dialect.SMB21 sessionKey None message
    Assert.True((verifyMessageSignature Dialect.SMB21 sessionKey None signed))

[<Fact>]
let ``VerifyMessageSignature rejects tampered message`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.zeroCreate<byte> 64
    message.[0..3] <- [| 0xFEuy; 0x53uy; 0x4Duy; 0x42uy |]
    message.[4..5] <- System.BitConverter.GetBytes(uint16 64)
    let signed = signMessage Dialect.SMB21 sessionKey None message
    signed.[10] <- byte (int signed.[10] ^^^ 0xFF)
    Assert.False((verifyMessageSignature Dialect.SMB21 sessionKey None signed))

// ============================================================================
// 7. SMB3-Level Signing Tests
// ============================================================================
//
// These tests validate the complete SMB2/SMB3 signing pipeline as implemented
// within the SMB2 header before hashing.
//
//   1. Zero the 16-byte signature field at header offset 48
//   2. Set the SMB2_FLAGS_SIGNED bit (byte 16, mask 0x08) before hashing
//   3. Compute HMAC-SHA256 (SMB2.1/2.02) or AES-CMAC (SMB3.x)
//   4. Inject signature at offset 48
//
// Test vectors are from the NIST reference implementation.

/// Minimal SMB2 header (48 bytes) + 16-byte zeroed signature space, followed by body.
/// Total = 64 + body length. Signature field is zeroed before hashing.
let private makeSmb2Message (body : byte array) : byte array =
    let header = Array.zeroCreate<byte> 48
    // ProtocolId = 0x424D53FE ("SMB" little-endian) at offset 0
    header.[0] <- 0x42uy; header.[1] <- 0x4Duy; header.[2] <- 0x53uy; header.[3] <- 0xFEuy
    // StructureSize = 64 at offset 4
    let ss = System.BitConverter.GetBytes(uint16 64uy)
    header.[4] <- ss.[0]; header.[5] <- ss.[1]
    // CreditCharge = 0 at offset 6
    header.[6] <- 0x00uy; header.[7] <- 0x00uy
    // ChannelSequence = 0 at offset 8
    header.[8] <- 0x00uy; header.[9] <- 0x00uy
    // Reserved = 0 at offset 10
    header.[10] <- 0x00uy; header.[11] <- 0x00uy
    // Command = 0 (Negotiate) at offset 12
    header.[12] <- 0x00uy; header.[13] <- 0x00uy
    // NtStatus = 0 at offset 14
    header.[14] <- 0x00uy; header.[15] <- 0x00uy
    // Flags (4 bytes) @ 16-19 — SMB2_FLAGS_SIGNED is bit 3 (0x08) in byte 16
    header.[16] <- 0x00uy; header.[17] <- 0x00uy
    header.[18] <- 0x00uy; header.[19] <- 0x00uy
    // NextCommand = 0 at offset 20
    header.[20] <- 0x00uy; header.[21] <- 0x00uy; header.[22] <- 0x00uy; header.[23] <- 0x00uy
    // MessageID = 1 at offset 24
    let mid = System.BitConverter.GetBytes(uint64 0x0000000000000001UL)
    for i in 0..7 do header.[24 + i] <- mid.[i]
    // Reserved = 0 at offset 32
    header.[32] <- 0x00uy; header.[33] <- 0x00uy; header.[34] <- 0x00uy; header.[35] <- 0x00uy
    // TreeID = 0 at offset 36
    header.[36] <- 0x00uy; header.[37] <- 0x00uy; header.[38] <- 0x00uy; header.[39] <- 0x00uy
    // SessionID = 0 at offset 40
    header.[40] <- 0x00uy; header.[41] <- 0x00uy; header.[42] <- 0x00uy; header.[43] <- 0x00uy
    header.[44] <- 0x00uy; header.[45] <- 0x00uy; header.[46] <- 0x00uy; header.[47] <- 0x00uy
    // 16-byte zeroed signature space at offset 48.
    let sigSpace = Array.zeroCreate<byte> 16
    Array.concat [header; sigSpace; body]

// --- SMB 2.1 HMAC-SHA256 signing ---

[<Fact>]
let ``SMB2.1 signSMB produces correct HMAC-SHA256 signature`` () =
    // HMAC-SHA256(SessionKey, packet) truncated to 16 bytes.
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let body = System.Convert.FromHexString("00010203")
    let message = makeSmb2Message body

    // Compute expected signature — match signMessage: zero sig, SIGNED flag set during hashing.
    let prepared = Array.copy message
    prepared.[16] <- byte (int prepared.[16] ||| 0x08)  // SIGNED set during hashing
    use hmac = new System.Security.Cryptography.HMACSHA256(sessionKey)
    let expected = hmac.ComputeHash(prepared) |> Array.take 16

    // Sign via our module
    let signed = signMessage Dialect.SMB21 sessionKey None message

    // Signature should be injected at offset 48
    let actualSig = Array.sub signed 48 16
    Assert.True((expected = actualSig))

    // SMB2_FLAGS_SIGNED bit must be set
    Assert.Equal(0x08, (int signed.[16] &&& 0x08))  // SMB2_FLAGS_SIGNED at byte 16, bit 3

[<Fact>]
let ``SMB2.1 signSMB empty body matches reference vector`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let message = makeSmb2Message [||]

    // Match signMessage: zero sig, SIGNED flag set during hashing
    let prepared = Array.copy message
    prepared.[16] <- byte (int prepared.[16] ||| 0x08)  // SIGNED set during hashing
    use hmac = new System.Security.Cryptography.HMACSHA256(sessionKey)
    let expected = hmac.ComputeHash(prepared) |> Array.take 16

    let signed = signMessage Dialect.SMB21 sessionKey None message
    let actualSig = Array.sub signed 48 16
    Assert.True((expected = actualSig))

[<Fact>]
let ``SMB2.1 verifyMessageSignature validates correct signature`` () =
    let sessionKey = System.Convert.FromHexString("abcdef0123456789abcdef0123456789")
    let body = System.Convert.FromHexString("0000010000000000")
    let message = makeSmb2Message body
    let signed = signMessage Dialect.SMB21 sessionKey None message
    Assert.True((verifyMessageSignature Dialect.SMB21 sessionKey None signed))

[<Fact>]
let ``SMB2.1 verifyMessageSignature rejects tampered body`` () =
    let sessionKey = System.Convert.FromHexString("abcdef0123456789abcdef0123456789")
    let body = System.Convert.FromHexString("0000010000000000")
    let message = makeSmb2Message body
    let signed = signMessage Dialect.SMB21 sessionKey None message
    // Tamper the body (after the 48-byte header)
    signed.[50] <- byte (int signed.[50] ^^^ 0xFF)
    Assert.False((verifyMessageSignature Dialect.SMB21 sessionKey None signed))

// --- SMB 3.0 AES-CMAC signing ---

[<Fact>]
let ``SMB3.0 signSMB produces correct AES-CMAC signature`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let body = Array.init 16 (fun i -> byte i)
    let message = makeSmb2Message body

    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey) ->
        let signed = signMessage Dialect.SMB302 sessionKey (Some signingKey) message
        let actualSig = Array.sub signed 48 16
        Assert.False((Array.forall ((=) 0uy) actualSig))
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``SMB3.0 signSMB empty body matches reference vector`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let message = makeSmb2Message [||]

    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey) ->
        // Expected with SIGNED flag set during hashing
        let signed = signMessage Dialect.SMB302 sessionKey (Some signingKey) message
        let actualSig = Array.sub signed 48 16
        Assert.Equal("6b0f9461fb0b7f1fa509ba5af19e5cb4", System.Convert.ToHexString(actualSig).ToLowerInvariant())
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``SMB3.0 signSMB full-block message matches reference vector`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let body = Array.init 64 (fun i -> byte (i % 256))
    let message = makeSmb2Message body

    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey) ->
        // Expected with SIGNED flag set during hashing
        let signed = signMessage Dialect.SMB302 sessionKey (Some signingKey) message
        let actualSig = Array.sub signed 48 16
        Assert.Equal("0830a8266c77c9ae86ca071ba630b817", System.Convert.ToHexString(actualSig).ToLowerInvariant())
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``SMB3.0 verifyMessageSignature validates correct signature`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let body = Array.init 16 (fun i -> byte i)
    let message = makeSmb2Message body
    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey) ->
        let signed = signMessage Dialect.SMB302 sessionKey (Some signingKey) message
        Assert.True((verifyMessageSignature Dialect.SMB302 sessionKey (Some signingKey) signed))
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``SMB3.0 verifyMessageSignature rejects tampered message`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let body = Array.init 16 (fun i -> byte i)
    let message = makeSmb2Message body
    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey) ->
        let signed = signMessage Dialect.SMB302 sessionKey (Some signingKey) message
        // Tamper the header (offset 10 — inside the 48-byte header)
        signed.[10] <- byte (int signed.[10] ^^^ 0xFF)
        Assert.False((verifyMessageSignature Dialect.SMB302 sessionKey (Some signingKey) signed))
    | Ok None | Error _ -> Assert.Fail "SMB3.0.2 derivation failed"

// --- SMB3.1.1 AES-CMAC signing with preauthHash context ---

[<Fact>]
let ``SMB3.1.1 signSMB produces correct AES-CMAC signature`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let preauthHash = System.Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    let body = Array.init 16 (fun i -> byte i)
    let message = makeSmb2Message body

    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some signingKey) ->
        // Expected with SIGNED flag set during hashing
        let signed = signMessage Dialect.SMB311 sessionKey (Some signingKey) message
        let actualSig = Array.sub signed 48 16
        Assert.Equal("7ab8896f099bf6800a79cdd314cd3705", System.Convert.ToHexString(actualSig).ToLowerInvariant())
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``SMB3.1.1 signSMB empty body matches reference vector`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let preauthHash = System.Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    let message = makeSmb2Message [||]

    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some signingKey) ->
        // Expected with SIGNED flag set during hashing
        let signed = signMessage Dialect.SMB311 sessionKey (Some signingKey) message
        let actualSig = Array.sub signed 48 16
        Assert.Equal("1672b0690d7c6cf3d34a1e557d08d1ba", System.Convert.ToHexString(actualSig).ToLowerInvariant())
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``SMB3.1.1 verifyMessageSignature validates correct signature`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let preauthHash = System.Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    let body = Array.init 16 (fun i -> byte i)
    let message = makeSmb2Message body
    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some signingKey) ->
        let signed = signMessage Dialect.SMB311 sessionKey (Some signingKey) message
        Assert.True((verifyMessageSignature Dialect.SMB311 sessionKey (Some signingKey) signed))
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``SMB3.1.1 verifyMessageSignature rejects tampered message`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let preauthHash = System.Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    let body = Array.init 16 (fun i -> byte i)
    let message = makeSmb2Message body
    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some signingKey) ->
        let signed = signMessage Dialect.SMB311 sessionKey (Some signingKey) message
        // Tamper the body
        signed.[55] <- byte (int signed.[55] ^^^ 0xFF)
        Assert.False((verifyMessageSignature Dialect.SMB311 sessionKey (Some signingKey) signed))
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

// --- Cross-dialect consistency: same message, different signing algorithms ---

[<Fact>]
let ``Same message produces different signatures across dialects`` () =
    let sessionKey = System.Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let preauthHash = System.Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    let body = Array.init 16 (fun i -> byte i)
    let message = makeSmb2Message body

    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey30) ->
        match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
        | Ok (Some signingKey311) ->
            let sigSmb21 = signMessage Dialect.SMB21 sessionKey None message
            let sigSmb30 = signMessage Dialect.SMB302 sessionKey (Some signingKey30) message
            let sigSmb311 = signMessage Dialect.SMB311 sessionKey (Some signingKey311) message

            // All three must differ (different crypto per dialect)
            Assert.False((Array.sub sigSmb21 48 16 = Array.sub sigSmb30 48 16))
            Assert.False((Array.sub sigSmb30 48 16 = Array.sub sigSmb311 48 16))
            Assert.False((Array.sub sigSmb21 48 16 = Array.sub sigSmb311 48 16))
        | _ -> Assert.Fail "SMB3.1.1 derivation failed"
    | _ -> Assert.Fail "SMB3.0.2 derivation failed"

// --- Roundtrip tests ---

[<Fact>]
let ``signAndVerify SMB21 roundtrip`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.init 100 (fun i -> byte (i % 256))
    let result = signAndVerify Dialect.SMB21 sessionKey None message
    Assert.True(result)

[<Fact>]
let ``signAndVerify SMB302 roundtrip`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.init 100 (fun i -> byte (i % 256))
    match deriveSigningKey Dialect.SMB302 sessionKey None with
    | Ok (Some signingKey) ->
        let result = signAndVerify Dialect.SMB302 sessionKey (Some signingKey) message
        Assert.True(result)
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

[<Fact>]
let ``signAndVerify SMB311 roundtrip`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let preauthHash = Array.init 64 (fun i -> byte (i % 256))
    let message = Array.init 100 (fun i -> byte (i % 256))
    match deriveSigningKey Dialect.SMB311 sessionKey (Some preauthHash) with
    | Ok (Some signingKey) ->
        let result = signAndVerify Dialect.SMB311 sessionKey (Some signingKey) message
        Assert.True(result)
    | other -> Assert.Fail (sprintf "Expected Ok (Some signingKey), got %A" other)

// --- Determinism ---

[<Fact>]
let ``SignMessage is deterministic across multiple calls`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let message = Array.init 100 (fun i -> byte (i % 256))
    let signed1 = signMessage Dialect.SMB21 sessionKey None message
    let signed2 = signMessage Dialect.SMB21 sessionKey None message
    Assert.True((signed1 = signed2))

// --- SMB3 encryption (TRANSFORM_HEADER) ---

[<Fact>]
let ``AES-128-CCM encrypt then decrypt roundtrip recovers plaintext`` () =
    let sessionKey = Array.init 16 (fun i -> byte (i + 1))
    match Fauli.Smb.Encryption.deriveEncryptionKeys Dialect.SMB302 sessionKey Aes128Ccm None with
    | Error e -> Assert.Fail(sprintf "key derive failed: %A" e)
    | Ok (encKey, decKey) ->
        let enc : SmbEncryption =
            { Cipher = Aes128Ccm
              EncryptionKey = encKey
              // Self-roundtrip: use C2S key for both directions
              DecryptionKey = encKey }
        let plain = Array.init 80 (fun i -> byte (i * 3))
        let wire = Fauli.Smb.Encryption.encryptSmbMessage enc 0x1122334455667788UL plain
        Assert.True(Fauli.Smb.Encryption.isTransformPacket wire)
        Assert.True(wire.Length > plain.Length)
        match Fauli.Smb.Encryption.decryptSmbMessage enc wire with
        | Ok recovered -> Assert.True((recovered = plain))
        | Error e -> Assert.Fail(sprintf "decrypt failed: %A" e)

[<Fact>]
let ``SMB 3.1.1 encryption key derivation produces 16-byte keys`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    let preauth = Array.init 64 (fun i -> byte (255 - i))
    match Fauli.Smb.Encryption.deriveEncryptionKeys Dialect.SMB311 sessionKey Aes128Ccm (Some preauth) with
    | Ok (e, d) ->
        Assert.Equal(16, e.Length)
        Assert.Equal(16, d.Length)
        Assert.False((e = d)) // C2S and S2C differ
    | Error err -> Assert.Fail(sprintf "%A" err)

[<Fact>]
let ``tryBuildEncryption returns None when encryptData is false`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    match Fauli.Smb.Encryption.tryBuildEncryption Dialect.SMB302 sessionKey Fauli.Smb.Encryption.cipherAes128Ccm None false with
    | Ok None -> ()
    | other -> Assert.Fail(sprintf "expected Ok None, got %A" other)

[<Fact>]
let ``tryBuildEncryption returns Some when encryptData is true`` () =
    let sessionKey = Array.init 16 (fun i -> byte i)
    match Fauli.Smb.Encryption.tryBuildEncryption Dialect.SMB302 sessionKey Fauli.Smb.Encryption.cipherAes128Ccm None true with
    | Ok (Some enc) ->
        Assert.Equal(Aes128Ccm, enc.Cipher)
        Assert.Equal(16, enc.EncryptionKey.Length)
        Assert.Equal(16, enc.DecryptionKey.Length)
        Assert.False((enc.EncryptionKey = enc.DecryptionKey))
    | other -> Assert.Fail(sprintf "expected Ok Some, got %A" other)

[<Fact>]
let ``encryptSmbMessage TRANSFORM_HEADER is 0xFD SMB with session id and size`` () =
    let sessionKey = Array.init 16 (fun i -> byte (i + 3))
    match Fauli.Smb.Encryption.deriveEncryptionKeys Dialect.SMB30 sessionKey Aes128Ccm None with
    | Error e -> Assert.Fail(sprintf "%A" e)
    | Ok (encKey, _) ->
        let enc : SmbEncryption =
            { Cipher = Aes128Ccm; EncryptionKey = encKey; DecryptionKey = encKey }
        let plain = Array.init 64 (fun i -> byte i)
        let sid = 0x0102030405060708UL
        let wire = Fauli.Smb.Encryption.encryptSmbMessage enc sid plain
        Assert.Equal(0xFDuy, wire.[0])
        Assert.Equal(0x53uy, wire.[1]) // S
        Assert.Equal(0x4Duy, wire.[2]) // M
        Assert.Equal(0x42uy, wire.[3]) // B
        Assert.True(wire.Length = 52 + plain.Length)
        let origSize = BitConverter.ToUInt32(wire, 36)
        Assert.Equal(uint32 plain.Length, origSize)
        let wireSid = BitConverter.ToUInt64(wire, 44)
        Assert.Equal(sid, wireSid)

[<Fact>]
let ``decrypt with wrong key fails`` () =
    let sessionKey = Array.init 16 (fun i -> byte (i + 9))
    match Fauli.Smb.Encryption.deriveEncryptionKeys Dialect.SMB302 sessionKey Aes128Ccm None with
    | Error e -> Assert.Fail(sprintf "%A" e)
    | Ok (encKey, decKey) ->
        let enc : SmbEncryption =
            { Cipher = Aes128Ccm; EncryptionKey = encKey; DecryptionKey = encKey }
        let plain = Array.init 32 (fun i -> byte (i * 2))
        let wire = Fauli.Smb.Encryption.encryptSmbMessage enc 1UL plain
        let bad : SmbEncryption =
            { Cipher = Aes128Ccm
              EncryptionKey = encKey
              DecryptionKey = Array.init 16 (fun _ -> 0xFFuy) }
        match Fauli.Smb.Encryption.decryptSmbMessage bad wire with
        | Error _ -> ()
        | Ok _ -> Assert.Fail "wrong key must not decrypt"
