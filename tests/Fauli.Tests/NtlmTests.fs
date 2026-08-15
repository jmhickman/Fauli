module Fauli.Tests.NtlmTests

open System
open Xunit
open Fauli.Ntlm.Encoding
open Fauli.Ntlm.Crypto
open Fauli.Ntlm.Auth

// ============================================================================
// 1. NT-Hash (MD4 of UTF-16LE password)
// ============================================================================

[<Fact>]
let ``computeNtHash is deterministic`` () =
    let h1 = computeNtHash "password"
    let h2 = computeNtHash "password"
    Assert.True((h1 = h2))
    Assert.Equal(16, h1.Length)

[<Fact>]
let ``computeNtHash differs for different passwords`` () =
    let h1 = computeNtHash "password"
    let h2 = computeNtHash "Password"
    Assert.False((h1 = h2))

[<Fact>]
let ``computeNtHash handles empty password`` () =
    let h = computeNtHash ""
    Assert.Equal(16, h.Length)

[<Fact>]
let ``computeNtHash handles Unicode passwords`` () =
    let h = computeNtHash "P@ssw0rd!日本語"
    Assert.Equal(16, h.Length)

// ============================================================================
// 2. NTLMv2 response key
// ============================================================================

[<Fact>]
let ``computeNtlmV2Hash is deterministic`` () =
    let ntHash = computeNtHash "password"
    let h1 = computeNtlmV2Hash ntHash "user" "DOMAIN"
    let h2 = computeNtlmV2Hash ntHash "user" "DOMAIN"
    Assert.True((h1 = h2))
    Assert.Equal(16, h1.Length)

[<Fact>]
let ``computeNtlmV2Hash differs for different usernames`` () =
    let ntHash = computeNtHash "password"
    let h1 = computeNtlmV2Hash ntHash "user" "DOMAIN"
    let h2 = computeNtlmV2Hash ntHash "other" "DOMAIN"
    Assert.False((h1 = h2))

// ============================================================================
// 3. NEGOTIATE_MESSAGE encoding
// ============================================================================

[<Fact>]
let ``encodeNegotiateMessage starts with NTLMSSP signature`` () =
    let msg = encodeNegotiateMessage None None
    Assert.Equal(0x4Euy, msg.[0])  // N
    Assert.Equal(0x54uy, msg.[1])  // T
    Assert.Equal(0x4Cuy, msg.[2])  // L
    Assert.Equal(0x4Duy, msg.[3])  // M
    Assert.Equal(0x53uy, msg.[4])  // S
    Assert.Equal(0x53uy, msg.[5])  // S
    Assert.Equal(0x50uy, msg.[6])  // P
    Assert.Equal(0x00uy, msg.[7])  // \0

[<Fact>]
let ``encodeNegotiateMessage has type 1`` () =
    let msg = encodeNegotiateMessage None None
    Assert.Equal(0x01uy, msg.[8])
    Assert.Equal(0x00uy, msg.[9])
    Assert.Equal(0x00uy, msg.[10])
    Assert.Equal(0x00uy, msg.[11])

[<Fact>]
let ``encodeNegotiateMessage includes domain when provided`` () =
    let msg = encodeNegotiateMessage (Some "CORP") None
    Assert.True(msg.Length > 48)

[<Fact>]
let ``encodeNegotiateMessage includes workstation when provided`` () =
    let msg = encodeNegotiateMessage None (Some "WORKSTATION1")
    Assert.True(msg.Length > 48)

[<Fact>]
let ``encodeNegotiateMessage roundtrips via decodeNegotiateMessage`` () =
    let msg = encodeNegotiateMessage (Some "CORP") (Some "WS01")
    let parsed = decodeNegotiateMessage msg
    Assert.Equal(Some "CORP", parsed.domainName)
    Assert.Equal(Some "WS01", parsed.workstation)

[<Fact>]
let ``encodeNegotiateMessage with no domain/workstation roundtrips`` () =
    let msg = encodeNegotiateMessage None None
    let parsed = decodeNegotiateMessage msg
    Assert.Equal(None, parsed.domainName)
    Assert.Equal(None, parsed.workstation)

// ============================================================================
// 4. CHALLENGE_MESSAGE encoding and decoding
// ============================================================================

[<Fact>]
let ``decodeChallengeMessage validates signature`` () =
    let bad = Array.zeroCreate<byte> 56
    let ex = Assert.Throws<ArgumentException>(fun () -> decodeChallengeMessage bad |> ignore)
    Assert.NotNull(ex)

[<Fact>]
let ``decodeChallengeMessage extracts server challenge`` () =
    // Build a minimal CHALLENGE_MESSAGE
    let buf = Array.zeroCreate<byte> 56
    buf.[0] <- 0x4Euy; buf.[1] <- 0x54uy; buf.[2] <- 0x4Cuy; buf.[3] <- 0x4Duy
    buf.[4] <- 0x53uy; buf.[5] <- 0x53uy; buf.[6] <- 0x50uy; buf.[7] <- 0x00uy
    // Type = 2
    buf.[8] <- 0x02uy
    // NegotiateFlags = UNICODE + TARGET_INFO
    buf.[20] <- byte (0x81uy &&& 0xFFuy)  // 0x00810000 (TARGET_INFO | UNICODE)
    buf.[21] <- 0x00uy
    buf.[22] <- 0x00uy
    buf.[23] <- 0x00uy
    // ServerChallenge at offset 24
    buf.[24] <- 0xABuy; buf.[25] <- 0xCDuy; buf.[26] <- 0xEFuy; buf.[27] <- 0x01uy
    buf.[28] <- 0x23uy; buf.[29] <- 0x45uy; buf.[30] <- 0x67uy; buf.[31] <- 0x89uy

    let parsed = decodeChallengeMessage buf
    Assert.Equal(8, parsed.serverChallenge.Length)
    Assert.Equal(0xABuy, parsed.serverChallenge.[0])

[<Fact>]
let ``decodeChallengeMessage with TargetInfo AV_PAIRs`` () =
    // Build CHALLENGE_MESSAGE with TargetInfo containing MsvAvNbDomainName + MsvAvEOL
    let targetInfo =
        [| // MsvAvNbDomainName: AvId=0x0002, AvLen=10, Value="DOMAIN" UTF-16LE
           0x02uy; 0x00uy;  // AvId
           0x0Auy; 0x00uy;  // AvLen = 10
           0x44uy; 0x00uy; 0x4Fuy; 0x00uy; 0x4Duy; 0x00uy; 0x41uy; 0x00uy; 0x4Euy; 0x00uy;
           // MsvAvEOL
           0x00uy; 0x00uy;  // AvId
           0x00uy; 0x00uy |]  // AvLen
    let buf = Array.zeroCreate<byte> (56 + targetInfo.Length)
    buf.[0] <- 0x4Euy; buf.[1] <- 0x54uy; buf.[2] <- 0x4Cuy; buf.[3] <- 0x4Duy
    buf.[4] <- 0x53uy; buf.[5] <- 0x53uy; buf.[6] <- 0x50uy; buf.[7] <- 0x00uy
    buf.[8] <- 0x02uy
    // NegotiateFlags: UNICODE + TARGET_INFO
    buf.[20] <- 0x81uy
    // TargetInfoFields at offset 40: Len=14, MaxLen=14, Offset=56
    buf.[40] <- byte (14 &&& 0xFF)
    buf.[41] <- byte (14 >>> 8 &&& 0xFF)
    buf.[42] <- byte (14 &&& 0xFF)
    buf.[43] <- byte (14 >>> 8 &&& 0xFF)
    buf.[44] <- byte (56 &&& 0xFF)
    buf.[45] <- byte (56 >>> 8 &&& 0xFF)
    // Copy TargetInfo into payload
    Array.Copy(targetInfo, 0, buf, 56, targetInfo.Length)

    let parsed = decodeChallengeMessage buf
    // Parser stops at MsvAvEOL — only the real pair is returned
    Assert.Equal(1, parsed.targetInfo.Length)
    Assert.Equal(AvId.MsvAvNbDomainName, parsed.targetInfo.Head.avId)

// ============================================================================
// 5. AUTHENTICATE_MESSAGE encoding
// ============================================================================

[<Fact>]
let ``encodeAuthenticateMessage starts with NTLMSSP signature and type 3`` () =
    let mic = Array.zeroCreate<byte> 16
    let msg =
        encodeAuthenticateMessage
            defaultNegotiateFlags
            [| 0x01uy; 0x02uy |]  // lmResponse
            [| 0x03uy; 0x04uy |]  // ntResponse
            "DOMAIN"
            "user"
            "WORKSTATION"
            [||]  // encryptedRandomSessionKey
            mic
    Assert.Equal(0x4Euy, msg.[0])
    Assert.Equal(0x03uy, msg.[8])

[<Fact>]
let ``encodeAuthenticateMessage includes MIC at offset 64`` () =
    let mic = Array.init 16 (fun i -> byte (i + 1))
    let msg =
        encodeAuthenticateMessage
            defaultNegotiateFlags
            [| 0x01uy |]
            [| 0x02uy |]
            "DOMAIN"
            "user"
            "WS"
            [||]
            mic
    let mic' = Array.init 16 (fun i -> msg.[72 + i])
    Assert.True((mic = mic'), "MIC bytes should match at offset 72")

// ============================================================================
// 6. MIC computation
// ============================================================================

[<Fact>]
let ``computeMic is deterministic`` () =
    let key = Array.init 16 (fun i -> byte i)
    let n1 = encodeNegotiateMessage None None
    let c1 = Array.zeroCreate<byte> 56
    c1.[0] <- 0x4Euy; c1.[1] <- 0x54uy; c1.[2] <- 0x4Cuy; c1.[3] <- 0x4Duy
    c1.[4] <- 0x53uy; c1.[5] <- 0x53uy; c1.[6] <- 0x50uy; c1.[7] <- 0x00uy
    c1.[8] <- 0x02uy
    let a1 = Array.zeroCreate<byte> 72
    let mic1 = computeMic key n1 c1 a1
    let mic2 = computeMic key n1 c1 a1
    Assert.True((mic1 = mic2))
    Assert.Equal(16, mic1.Length)

[<Fact>]
let ``computeMic differs for different session keys`` () =
    let key1 = Array.init 16 (fun i -> byte i)
    let key2 = Array.init 16 (fun i -> byte (255 - i))
    let n = encodeNegotiateMessage None None
    let c = Array.zeroCreate<byte> 56
    c.[0] <- 0x4Euy; c.[1] <- 0x54uy; c.[2] <- 0x4Cuy; c.[3] <- 0x4Duy
    c.[4] <- 0x53uy; c.[5] <- 0x53uy; c.[6] <- 0x50uy; c.[7] <- 0x00uy
    c.[8] <- 0x02uy
    let a = Array.zeroCreate<byte> 72
    let mic1 = computeMic key1 n c a
    let mic2 = computeMic key2 n c a
    Assert.False((mic1 = mic2))

// ============================================================================
// 7. Full NetNTLMv2 response computation
// ============================================================================

[<Fact>]
let ``computeNtlmV2Response produces valid LM and NT responses`` () =
    let challenge =
        { targetName = Some "AD-DC.CORP.LOCAL"
          negotiateFlags = defaultNegotiateFlags
          serverChallenge = [| 0x01uy; 0x02uy; 0x03uy; 0x04uy; 0x05uy; 0x06uy; 0x07uy; 0x08uy |]
          targetInfo = [] }

    let resp = computeNtlmV2Response "P@ssw0rd" "Administrator" "CORP" challenge

    // LMv2 response: 16-byte HMAC + 8-byte client challenge = 24 bytes
    Assert.Equal(24, resp.lmResponse.Length)

    // NTv2 response: 16-byte NTProofStr + client blob (>16 bytes)
    Assert.True(resp.ntResponse.Length > 16)

    // Session key
    Assert.Equal(16, resp.exportedSessionKey.Length)

[<Fact>]
let ``computeNtlmV2Response differs for different passwords`` () =
    let challenge =
        { targetName = None
          negotiateFlags = defaultNegotiateFlags
          serverChallenge = [| 0xAAuy; 0xBBuy; 0xCCuy; 0xDDuy; 0xEEuy; 0xFFuy; 0x00uy; 0x11uy |]
          targetInfo = [] }

    let r1 = computeNtlmV2Response "password1" "user" "DOMAIN" challenge
    let r2 = computeNtlmV2Response "password2" "user" "DOMAIN" challenge

    Assert.False((r1.ntResponse = r2.ntResponse))
    Assert.False((r1.lmResponse = r2.lmResponse))

[<Fact>]
let ``computeNtlmV2Response differs for different server challenges`` () =
    let c1 =
        { targetName = None
          negotiateFlags = defaultNegotiateFlags
          serverChallenge = [| 0x01uy; 0x02uy; 0x03uy; 0x04uy; 0x05uy; 0x06uy; 0x07uy; 0x08uy |]
          targetInfo = [] }
    let c2 =
        { targetName = None
          negotiateFlags = defaultNegotiateFlags
          serverChallenge = [| 0xAAuy; 0xBBuy; 0xCCuy; 0xDDuy; 0xEEuy; 0xFFuy; 0x00uy; 0x11uy |]
          targetInfo = [] }

    let r1 = computeNtlmV2Response "password" "user" "DOMAIN" c1
    let r2 = computeNtlmV2Response "password" "user" "DOMAIN" c2

    Assert.False((r1.ntResponse = r2.ntResponse))

// ============================================================================
// 8. buildAuthenticateMessage integration
// ============================================================================

[<Fact>]
let ``buildAuthenticateMessage produces valid message with MIC`` () =
    let challenge =
        { targetName = Some "DC.CORP.LOCAL"
          negotiateFlags = defaultNegotiateFlags
          serverChallenge = [| 0x12uy; 0x34uy; 0x56uy; 0x78uy; 0x9Auy; 0xBCuy; 0xDEuy; 0xF0uy |]
          targetInfo = [] }

    let resp = computeNtlmV2Response "P@ssw0rd" "Administrator" "CORP" challenge
    let negotiateMsg = encodeNegotiateMessage (Some "CORP") (Some "CLIENT01")
    let challengeData = Array.zeroCreate<byte> 56
    challengeData.[0] <- 0x4Euy; challengeData.[1] <- 0x54uy; challengeData.[2] <- 0x4Cuy; challengeData.[3] <- 0x4Duy
    challengeData.[4] <- 0x53uy; challengeData.[5] <- 0x53uy; challengeData.[6] <- 0x50uy; challengeData.[7] <- 0x00uy
    challengeData.[8] <- 0x02uy

    let authMsg =
        buildAuthenticateMessage
            challenge.negotiateFlags
            resp
            negotiateMsg
            challengeData
            "CORP"
            "Administrator"
            "CLIENT01"

    // Verify signature
    Assert.Equal(0x4Euy, authMsg.[0])
    Assert.Equal(0x03uy, authMsg.[8])

    // MIC should be non-zero (it was computed and patched in)
    let micBytes = Array.sub authMsg 72 16
    Assert.False((micBytes = Array.zeroCreate<byte> 16), "MIC should not be all zeros")

// ============================================================================
// 9. AV_PAIR helpers
// ============================================================================

[<Fact>]
let ``avPairToString decodes UTF-16LE strings`` () =
    let value = System.Text.Encoding.Unicode.GetBytes "CORP.LOCAL"
    let pair = { avId = AvId.MsvAvDnsDomainName; value = value }
    Assert.Equal("CORP.LOCAL", avPairToString pair)

[<Fact>]
let ``extractTargetName finds target in AV_PAIR list`` () =
    let tn = System.Text.Encoding.Unicode.GetBytes "dc.corp.local"
    let pairs =
        [ { avId = AvId.MsvAvNbDomainName; value = System.Text.Encoding.Unicode.GetBytes "CORP" }
          { avId = AvId.MsvAvTargetName; value = tn } ]
    Assert.Equal(Some "dc.corp.local", extractTargetName pairs)

[<Fact>]
let ``extractTargetName returns None when absent`` () =
    let pairs =
        [ { avId = AvId.MsvAvNbDomainName; value = System.Text.Encoding.Unicode.GetBytes "CORP" } ]
    Assert.Equal(None, extractTargetName pairs)

// ============================================================================
// 10. Flag constants
// ============================================================================

[<Fact>]
let ``defaultNegotiateFlags includes expected flags`` () =
    Assert.True((defaultNegotiateFlags &&& NtlmFlags.NegotiateUnicode) <> 0u)
    Assert.True((defaultNegotiateFlags &&& NtlmFlags.NegotiateSign) <> 0u)
    Assert.True((defaultNegotiateFlags &&& NtlmFlags.NegotiateSeal) <> 0u)
    Assert.True((defaultNegotiateFlags &&& NtlmFlags.NegotiateExtendedSessionSecurity) <> 0u)
    Assert.True((defaultNegotiateFlags &&& NtlmFlags.RequestTarget) <> 0u)

[<Fact>]
let ``buildNegotiateMessage delegates to encodeNegotiateMessage`` () =
    let msg = buildNegotiateMessage (Some "CORP") None
    Assert.Equal(0x4Euy, msg.[0])
    Assert.Equal(0x01uy, msg.[8])
