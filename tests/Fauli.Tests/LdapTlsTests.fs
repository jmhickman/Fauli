/// Integration tests for the LDAPS (implicit TLS) transport path.
/// A local SslStream listener with a self-signed cert stands in for an AD DC;
/// Fauli must complete the client handshake and carry the SASL bind over it.
module Fauli.Tests.LdapTlsTests

open System
open System.IO
open System.Net.Security
open System.Net.Sockets
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Threading
open Xunit
open Fauli.Domain
open Fauli.Ldap.Handler
open Fauli.Kerberos.Encoding


/// Generate a throwaway self-signed cert for the local TLS listener.
let private makeSelfSignedCert () : X509Certificate2 =
    let rsa = RSA.Create(2048)
    let req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
    req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1))


/// Minimal LDAPMessage { messageId, BindResponse APPLICATION 1 } wire bytes.
let private buildBindResponseMessage (messageId : int) (resultCode : int) (serverSaslCreds : byte array option) : byte array =
    let codeBytes =
        match resultCode < 128 with
        | true -> [| byte resultCode |]
        | false -> BitConverter.GetBytes(resultCode) |> Array.rev |> Array.skipWhile ((=) 0uy)
    let enumerated =
        Array.concat [| [| 0x0Auy; byte codeBytes.Length |]; codeBytes |]
    let matched = encodeOctetString [||]
    let diag = encodeOctetString (System.Text.Encoding.UTF8.GetBytes "saslBindInProgress")
    let credsTlv =
        match serverSaslCreds with
        | None -> [||]
        | Some c -> Array.concat [| [| 0x87uy; byte c.Length |]; c |]
    let bindBody = Array.concat [| enumerated; matched; diag; credsTlv |]
    let bindResponse = encodeApplicationConstructed 1 bindBody
    encodeSequence [| encodeInteger messageId; bindResponse |]


/// Minimal NTLM CHALLENGE_MESSAGE (Type 2): 56 bytes, zeroed optional fields.
let private buildNtlmType2 () : byte array =
    let buf = Array.zeroCreate<byte> 56
    // NTLMSSP signature: "NTLMSSP" + null terminator (8 bytes).
    Array.blit [| 0x4Euy; 0x54uy; 0x4Cuy; 0x4Duy; 0x53uy; 0x53uy; 0x50uy; 0x00uy |] 0 buf 0 8
    Array.blit (BitConverter.GetBytes 2u) 0 buf 8 4
    Array.blit (BitConverter.GetBytes 0x82898C97u) 0 buf 20 4
    Array.blit [| 1uy; 2uy; 3uy; 4uy; 5uy; 6uy; 7uy; 8uy |] 0 buf 24 8
    buf


/// Wrap a raw NTLM Type 2 in a SPNEGO NegTokenResp, as an LDAP server delivers
/// it in serverSaslCreds: [1] SEQUENCE { [0] ENUMERATED 3; [2] OCTET STRING }.
let private wrapType2InSpnego (type2 : byte array) : byte array =
    let negToken =
        Array.concat
            [| [| 0xA0uy; 0x03uy; 0x02uy; 0x01uy; 0x03uy |]
               [| 0xA2uy; byte (2 + type2.Length) |]
               [| 0x04uy; byte type2.Length |]
               type2 |]
    Array.concat [| [| 0xA1uy; byte negToken.Length |]; negToken |]


/// Read one byte from the stream, failing on EOF.
let private readByte (stream : Stream) : int =
    match stream.ReadByte() with
    | b when b < 0 -> invalidOp "EOF while reading BER message"
    | b -> b


/// Read a definite BER length (short or long form) after the tag byte.
let private readBerLength (stream : Stream) : int =
    let first = readByte stream
    match (first &&& 0x7F) = 0 with
    | true -> first
    | false ->
        let count = first &&& 0x7F
        let rec foldLen acc remaining =
            match remaining = 0 with
            | true -> acc
            | false -> foldLen ((acc <<< 8) ||| readByte stream) (remaining - 1)
        foldLen 0 count


/// Read one complete BER message (tag + length + content) from the stream,
/// looping until the full declared content length has arrived (TCP/TLS may
/// deliver in chunks). Returns the content bytes.
let private readFullMessage (stream : Stream) : byte array =
    let _tag = readByte stream
    let contentLen = readBerLength stream
    let content = Array.zeroCreate<byte> contentLen
    let rec fill off remaining =
        match remaining = 0 with
        | true -> ()
        | false ->
            let r = stream.Read(content, off, remaining)
            match r <= 0 with
            | true -> invalidOp "EOF while reading BER content"
            | false -> fill (off + r) (remaining - r)
    fill 0 contentLen
    content


/// Run a listener body on a background thread, swallowing all expected errors
/// that occur when the client disposes early (broken pipes, EOF mid-message,
/// TLS close_notify, etc.). Without this, an unhandled exception on a bare
/// thread aborts the whole test host. The real assertions run on the main thread.
let private runListenerThread (body : unit -> unit) : Thread =
    let thread =
        new Thread(ThreadStart(fun () ->
            try body ()
            with ex ->
                match ex with
                | :? OperationCanceledException -> ()
                | _ -> ()))
    thread.Start()
    thread


/// Start a local TLS listener that performs the server handshake, answers the
/// NTLM leg-1 bind with saslBindInProgress + a Type 2 challenge, then answers
/// leg 2 with a success BindResponse. Pass port 0 for an ephemeral port.
let private startNtlmTlsListener (cert : X509Certificate2) (port : int) : int * TcpListener =
    let listener = new TcpListener(System.Net.IPAddress.Loopback, port)
    listener.Start()
    let boundPort = int ((listener.LocalEndpoint :?> System.Net.IPEndPoint).Port)
    let _ =
        runListenerThread (fun () ->
            let client = listener.AcceptTcpClient()
            use client = client
            let inner = client.GetStream()
            let serverSsl = new SslStream(inner, false)
            serverSsl.AuthenticateAsServer cert
            // Leg 1: read the client's Type 1 bind, reply with the challenge.
            ignore (readFullMessage serverSsl)
            let leg1 =
                buildBindResponseMessage 1 14 (Some (wrapType2InSpnego (buildNtlmType2 ())))
            serverSsl.Write(leg1, 0, leg1.Length)
            serverSsl.Flush()
            // Leg 2: read the client's Type 3 bind, reply with success.
            ignore (readFullMessage serverSsl)
            let leg2 = buildBindResponseMessage 2 0 None
            serverSsl.Write(leg2, 0, leg2.Length)
            serverSsl.Flush())
    boundPort, listener


/// Start a plain TCP listener that accepts one connection, sends garbage (no TLS),
/// then holds the connection open so the client can read the bytes before EOF.
let private startPlainListener (garbage : byte array) : int * TcpListener =
    let listener = new TcpListener(System.Net.IPAddress.Loopback, 0)
    listener.Start()
    let port = int ((listener.LocalEndpoint :?> System.Net.IPEndPoint).Port)
    let _ =
        runListenerThread (fun () ->
            let client = listener.AcceptTcpClient()
            use client = client
            let stream = client.GetStream()
            stream.Write(garbage, 0, garbage.Length)
            stream.Flush()
            // Hold the connection open: the client reads the garbage before we close.
            stream.Read(Array.zeroCreate<byte> 1, 0, 1) |> ignore)
    port, listener


/// Open a connected loopback socket to the given port.
let private connectTo (port : int) : System.Net.Sockets.Socket =
    let socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp)
    socket.ReceiveTimeout <- 10000
    socket.SendTimeout <- 10000
    socket.Connect("127.0.0.1", port)
    socket


/// Unwrap a successful smart-constructor Result for test setup.
let private mustOk (label : string) (result : Result<'a, AuthError>) : 'a =
    match result with
    | Ok v -> v
    | Error e ->
        Assert.Fail(sprintf "%s: %A" label e)
        failwith "unreachable"


[<Fact>]
let ``establishTransportStream performs an implicit-TLS handshake for LdapTls`` () =
    let cert = makeSelfSignedCert ()
    let port, listener = startNtlmTlsListener cert 0
    try
        let host = mustOk "Host.create" (Host.create "127.0.0.1")
        let config = { LdapConnectionConfig.defaults with transport = LdapTls }
        match establishTransportStream host config (connectTo port |> Ok) with
        | Ok stream ->
            Assert.True(stream :? SslStream)
            stream.Dispose()
        | Error e -> Assert.Fail(sprintf "establishTransportStream failed: %A" e)
    finally
        listener.Stop()


[<Fact>]
let ``establishTransportStream returns a plain stream for LdapPlain`` () =
    let port, listener = startPlainListener [| 0x01uy; 0x02uy |]
    try
        let host = mustOk "Host.create" (Host.create "127.0.0.1")
        let config = { LdapConnectionConfig.defaults with transport = LdapPlain }
        match establishTransportStream host config (connectTo port |> Ok) with
        | Ok stream ->
            Assert.True(stream :? NetworkStream)
            Assert.False(stream :? SslStream)
            stream.Dispose()
        | Error e -> Assert.Fail(sprintf "establishTransportStream failed: %A" e)
    finally
        listener.Stop()


[<Fact>]
let ``establishTransportStream maps a non-TLS server onto a connection error`` () =
    let port, listener = startPlainListener [| 0x00uy; 0x01uy; 0x02uy; 0x03uy |]
    try
        let host = mustOk "Host.create" (Host.create "127.0.0.1")
        let config = { LdapConnectionConfig.defaults with transport = LdapTls }
        match establishTransportStream host config (connectTo port |> Ok) with
        | Ok _ -> Assert.Fail "expected handshake failure against a non-TLS server"
        // Garbage bytes during the handshake surface as an IO error, not a
        // certificate error (trust-any means the cert callback never fails).
        | Error e -> Assert.Equal(ProtocolConnectionFailed, e)
    finally
        listener.Stop()


[<Fact>]
let ``establishTransportStream propagates a socket error`` () =
    let host = mustOk "Host.create" (Host.create "127.0.0.1")
    let config = { LdapConnectionConfig.defaults with transport = LdapTls }
    match establishTransportStream host config (ProtocolConnectionFailed |> Error) with
    | Ok _ -> Assert.Fail "expected the socket error to propagate"
    | Error e -> Assert.Equal(ProtocolConnectionFailed, e)


[<Fact>]
let ``handleLdap completes a NetNTLMv2 bind over implicit TLS`` () =
    let cert = makeSelfSignedCert ()
    // handleLdap derives the port from the transport (636), so the fake DC must bind 636.
    let port, listener = startNtlmTlsListener cert 636
    try
        let host = mustOk "Host.create" (Host.create "127.0.0.1")
        let config = { LdapConnectionConfig.defaults with transport = LdapTls }
        let authParams =
            NtlmResponse
                { authResponse = NtlmAuthResponse [||]
                  userName = UserName "administrator"
                  domain = DomainName "ADLAB"
                  password = Password "correct-horse-battery-staple" }
        match handleLdap host config authParams with
        | Ok response ->
            Assert.Equal(NetNTLMv2, response.authenticationMethod)
            match response.connection with
            | AuthLdap session ->
                Assert.True(session.Stream :? SslStream)
                Assert.Equal(3, session.NextMessageId)
            | _ -> Assert.Fail "expected AuthLdap connection handle"
        | Error e -> Assert.Fail(sprintf "handleLdap over TLS failed: %A" e)
    finally
        listener.Stop()
