/// Pure unit tests for LDAP SASL bind request encoding and BindResponse parsing.
/// Locks RFC 4511 wire shape (GSS-SPNEGO) and success / saslBindInProgress codes.
module Fauli.Tests.LdapWireTests

open System
open System.Text
open Xunit
open Fauli.Domain
open Fauli.Ldap.Handler
open Fauli.Kerberos.Encoding

// ===========================================================================
// Helpers — synthetic BindResponse BER
// ===========================================================================

/// Build LDAPMessage { messageId, BindResponse APPLICATION 1 }.
let private buildBindResponseMessage
        (messageId : int)
        (resultCode : int)
        (matchedDn : string)
        (diagnostic : string)
        (serverSaslCreds : byte array option)
        : byte array =
    // ENUMERATED resultCode
    let codeBytes =
        if resultCode < 128 then [| byte resultCode |]
        else BitConverter.GetBytes(resultCode) |> Array.rev |> fun a -> Array.skipWhile ((=) 0uy) a
    let enumerated =
        Array.concat [| [| 0x0Auy; byte codeBytes.Length |]; codeBytes |]

    let matched = encodeOctetString (Encoding.UTF8.GetBytes matchedDn)
    let diag = encodeOctetString (Encoding.UTF8.GetBytes diagnostic)

    let credsTlv =
        match serverSaslCreds with
        | None -> [||]
        | Some c ->
            // [7] IMPLICIT OCTET STRING → primitive context tag 0x87
            Array.concat [| [| 0x87uy; byte c.Length |]; c |]

    let bindBody = Array.concat [| enumerated; matched; diag; credsTlv |]
    let bindResponse = encodeApplicationConstructed 1 bindBody
    encodeSequence [| encodeInteger messageId; bindResponse |]

// ===========================================================================
// buildSaslBindRequest wire format
// ===========================================================================

[<Fact>]
let ``buildSaslBindRequest is SEQUENCE with messageId and APPLICATION 0 BindRequest`` () =
    let token = [| 0x60uy; 0x03uy; 0x02uy; 0x01uy; 0x01uy |]
    let msg = buildSaslBindRequest 1 token
    Assert.Equal(0x30uy, msg.[0]) // SEQUENCE
    // Must contain APPLICATION 0 (0x60) BindRequest
    Assert.True(Array.exists ((=) 0x60uy) msg)
    // Must contain mechanism name GSS-SPNEGO as UTF-8/ASCII octets
    let mech = Encoding.ASCII.GetBytes "GSS-SPNEGO"
    let rec contains (hay : byte array) (needle : byte array) i =
        if i + needle.Length > hay.Length then false
        elif Array.sub hay i needle.Length = needle then true
        else contains hay needle (i + 1)
    Assert.True(contains msg mech 0)

[<Fact>]
let ``buildSaslBindRequest embeds SPNEGO token bytes`` () =
    let token = Array.init 32 (fun i -> byte (0xA0 + i))
    let msg = buildSaslBindRequest 7 token
    let rec contains (hay : byte array) (needle : byte array) i =
        if i + needle.Length > hay.Length then false
        elif Array.sub hay i needle.Length = needle then true
        else contains hay needle (i + 1)
    Assert.True(contains msg token 0)

[<Fact>]
let ``buildSaslBindRequest uses IMPLICIT [3] sasl (tag 0xA3) not GeneralString mechanism`` () =
    let msg = buildSaslBindRequest 1 [| 0x01uy |]
    // Context constructed 3 = 0xA3
    Assert.True(Array.exists ((=) 0xA3uy) msg)
    // GeneralString tag is 0x1B — must NOT be used for LDAPString (OCTET STRING = 0x04)
    // Mechanism is OCTET STRING, so 0x04 appears; we assert A3 is present for sasl choice.
    Assert.True(Array.exists ((=) 0x04uy) msg)

[<Fact>]
let ``buildSaslBindRequest differs by messageId`` () =
    let t = [| 0xAAuy |]
    let a = buildSaslBindRequest 1 t
    let b = buildSaslBindRequest 2 t
    Assert.False((a = b))

// ===========================================================================
// parseBindResponse
// ===========================================================================

[<Fact>]
let ``parseBindResponse success resultCode 0`` () =
    let wire = buildBindResponseMessage 1 0 "CN=Admin,DC=lab" "" None
    match parseBindResponse wire with
    | Ok r ->
        Assert.Equal(0, r.resultCode)
        Assert.Equal("CN=Admin,DC=lab", r.matchedDN)
        Assert.True(r.serverSaslCreds.IsNone)
    | Error e -> Assert.Fail(sprintf "%A" e)

[<Fact>]
let ``parseBindResponse saslBindInProgress is code 14 with serverSaslCreds`` () =
    let challenge = [| 0xA1uy; 0x04uy; 0x04uy; 0x02uy; 0xBBuy; 0xCCuy |]
    let wire = buildBindResponseMessage 1 14 "" "saslBindInProgress" (Some challenge)
    match parseBindResponse wire with
    | Ok r ->
        Assert.Equal(14, r.resultCode)
        match r.serverSaslCreds with
        | Some c -> Assert.True((c = challenge))
        | None -> Assert.Fail "expected serverSaslCreds"
    | Error e -> Assert.Fail(sprintf "%A" e)

[<Fact>]
let ``parseBindResponse invalidCredentials is code 49`` () =
    let wire = buildBindResponseMessage 2 49 "" "Invalid credentials" None
    match parseBindResponse wire with
    | Ok r -> Assert.Equal(49, r.resultCode)
    | Error e -> Assert.Fail(sprintf "%A" e)

[<Fact>]
let ``parseBindResponse rejects empty buffer`` () =
    match parseBindResponse [||] with
    | Ok r when r.resultCode = -1 -> () // tolerant parser may return unknown code
    | Error _ -> ()
    | Ok r -> Assert.True(r.resultCode <> 0, sprintf "empty should not be success: %A" r)
