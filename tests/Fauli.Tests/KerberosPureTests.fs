/// Pure unit tests for Kerberos encoding, parsing, encryption, and token construction.
/// Synthetic data only — no KDC or network I/O.
///
/// Covers:
/// - extractServiceKey from EncTGSRepPart
/// - buildApReq / buildApReqMutual / GSS-API / SPNEGO / NTLM SPNEGO wrappers
module Fauli.Tests.KerberosPureTests

open System
open Xunit
open Fauli.Domain
open Fauli.Kerberos.Encoding
open Fauli.Kerberos.Parsing
open Fauli.Kerberos.Encryption
open Fauli.Kerberos.Auth
open Fauli.GssApi

// ===========================================================================
// Helpers
// ===========================================================================

let private makeTestKey () : Key =
    { enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
      contents = Array.init 32 (fun i -> byte (i + 42)) }

// APPLICATION 14 = 0x60 | 0x0E = 0x6E
let private application14Tag = 0x6Euy

// ===========================================================================
// 1. Service session key extraction (EncTGSRepPart parsing)
// ===========================================================================

[<Fact>]
let ``extractServiceKey extracts key from EncTGSRepPart-like structure`` () =
    let fakeKeyType = 18
    let fakeKeyBytes = Array.init 32 (fun i -> byte (i + 10))

    let encryptionKey =
        encodeSequence
            [| encodeContextConstructed 0 (encodeInteger fakeKeyType)
               encodeContextConstructed 1 (encodeOctetString fakeKeyBytes) |]

    let encTgsRepPart =
        encodeSequence [| encodeContextConstructed 0 encryptionKey |]
        |> parseBer

    let result = extractServiceKey encTgsRepPart

    match result with
    | Some key ->
        Assert.Equal(EncryptionType.AES256_CTS_HMAC_SHA1_96, key.enctype)
        Assert.Equal(32, key.contents.Length)
        Assert.True(key.contents = fakeKeyBytes)
    | None ->
        Assert.Fail("Should have extracted service session key")

[<Fact>]
let ``extractServiceKey returns None for malformed structure`` () =
    let bad = BerInteger 42
    let result = extractServiceKey bad
    Assert.Equal(None, result)

    let empty = encodeSequence [||] |> parseBer
    let result2 = extractServiceKey empty
    Assert.Equal(None, result2)

// ===========================================================================
// 2. buildApReq / buildApReqMutual
// ===========================================================================

[<Fact>]
let ``buildApReq produces APPLICATION 14 (0x6E) structure`` () =
    let key = makeTestKey ()
    let ticketBytes = Array.init 300 (fun i -> byte (i % 200))
    let cname = encodePrincipalName 1 [| "Administrator" |] |> parseBer

    let apReq = buildApReq ticketBytes key "AD-LAB.LOCAL" cname

    Assert.True(apReq.Length > 100)
    Assert.Equal(application14Tag, apReq.[0])

    let parsed = parseBer apReq
    match parsed with
    | BerSequence _ -> ()
    | _ -> Assert.Fail("AP-REQ should parse to a SEQUENCE")

[<Fact>]
let ``buildApReq produces APPLICATION 14 with encrypted authenticator`` () =
    let key = makeTestKey ()
    let ticketBytes = Array.init 300 (fun i -> byte (i % 200))
    let cname = encodePrincipalName 1 [| "Administrator" |] |> parseBer

    let apReq = buildApReq ticketBytes key "AD-LAB.LOCAL" cname

    Assert.Equal(application14Tag, apReq.[0])
    let parsed = parseBer apReq
    match parsed with
    | BerSequence fields ->
        match contextAt fields 4 with
        | Some (BerSequence encFields) ->
            let cipherBytes = contextAt encFields 2 |> Option.bind asOctetString
            Assert.True(cipherBytes.IsSome, "AP-REQ should have encrypted authenticator cipher")
            Assert.True(cipherBytes.Value.Length > 16, "cipher should include confounder+payload+MAC")
        | Some _ -> Assert.Fail "Authenticator should be EncryptedData SEQUENCE"
        | None -> Assert.Fail "AP-REQ missing authenticator [4]"
    | _ -> Assert.Fail "AP-REQ should parse to SEQUENCE"

[<Fact>]
let ``buildApReqMutual is distinct from buildApReq`` () =
    let key = makeTestKey ()
    let ticketBytes = Array.init 300 (fun i -> byte (i % 200))
    let cname = encodePrincipalName 1 [| "Administrator" |] |> parseBer
    let plain = buildApReq ticketBytes key "AD-LAB.LOCAL" cname
    let mutual = buildApReqMutual ticketBytes key "AD-LAB.LOCAL" cname
    Assert.Equal(application14Tag, mutual.[0])
    // Mutual path encrypts a different authenticator (GSS checksum + options)
    Assert.False((plain = mutual))
    Assert.True(mutual.Length > 100)

// ===========================================================================
// 3. GSS-API InitContextToken structure
// ===========================================================================

[<Fact>]
let ``buildGssInitContextToken wraps AP-REQ in GSS-API structure`` () =
    let apReq = Array.init 500 (fun i -> byte (i % 250))

    let gssToken = buildGssInitContextToken apReq

    Assert.True(gssToken.Length > 20)
    Assert.Equal(0x30uy, gssToken.[0])
    Assert.True(gssToken.Length > apReq.Length)

// ===========================================================================
// 4. SPNEGO wrapping structure
// ===========================================================================

[<Fact>]
let ``wrapSpnego wraps GSS token in SPNEGO negTokenInit`` () =
    let gssToken = Array.init 600 (fun i -> byte (i % 250))

    let spnego = wrapSpnego gssToken

    Assert.True(spnego.Length > 20)
    Assert.Equal(0x30uy, spnego.[0])
    Assert.True(spnego.Length > gssToken.Length)

// ===========================================================================
// 5. Full pure chain: AP-REQ inside SPNEGO
// ===========================================================================

[<Fact>]
let ``buildSpnegoToken of buildApReq produces valid SPNEGO token`` () =
    let key = makeTestKey ()
    let ticketBytes = Array.init 300 (fun i -> byte (i % 200))
    let cname = encodePrincipalName 1 [| "Administrator" |] |> parseBer

    let spnego = buildSpnegoToken (buildApReq ticketBytes key "AD-LAB.LOCAL" cname)

    Assert.True(spnego.Length > 100)
    Assert.Equal(0x60uy, spnego.[0])  // AID tag (application [0] constructed)

// ===========================================================================
// 6. NTLM SPNEGO wrapping (LDAP/SMB leg-1 / leg-2)
// ===========================================================================

[<Fact>]
let ``wrapNtlmSpnego starts with GSS Application 0 and embeds NTLMSSP`` () =
    let type1 =
        Array.concat
            [| [| 0x4Euy; 0x54uy; 0x4Cuy; 0x4Duy; 0x53uy; 0x53uy; 0x50uy; 0x00uy |]
               Array.zeroCreate 24 |]
    let wrapped = wrapNtlmSpnego type1
    Assert.Equal(0x60uy, wrapped.[0])
    let ntlmSig = [| 0x4Euy; 0x54uy; 0x4Cuy; 0x4Duy; 0x53uy; 0x53uy; 0x50uy; 0x00uy |]
    let rec find i =
        if i + 8 > wrapped.Length then false
        elif Array.sub wrapped i 8 = ntlmSig then true
        else find (i + 1)
    Assert.True(find 0)

[<Fact>]
let ``wrapNtlmNegTokenResp is context 1 constructed`` () =
    let type3 = Array.init 64 (fun i -> byte i)
    let resp = wrapNtlmNegTokenResp type3
    Assert.Equal(0xA1uy, resp.[0])
    Assert.True(resp.Length > type3.Length)
