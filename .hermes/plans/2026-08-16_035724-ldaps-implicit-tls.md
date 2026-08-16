# LDAPS (Implicit TLS) Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make `LdapTransport.LdapTls` actually perform an implicit-TLS handshake on port 636 so the SASL bind runs over an encrypted channel, instead of the current cleartext-on-636 behavior.

**Architecture:** TLS is introduced as one new named pipeline step between "open TCP socket" and "run SASL bind." The socket is wrapped in a `NetworkStream`; for `LdapTls` that stream is further wrapped in an `SslStream` and authenticated as a client with a trust-any certificate callback (Fauli is a pentesting library and deliberately does **not** validate server identity). The bind pipeline's stream type is widened from `NetworkStream` to `Stream` so it is agnostic to whether the channel is plain TCP or TLS.

**Tech Stack:** F# / .NET 9, `System.Net.Security.SslStream`, `System.Net.Sockets`. No new packages.

---

## Verified BCL facts (confirmed against the installed .NET 9 SDK via reflection — do not re-derive)

- `System.Net.Security.RemoteCertificateValidationCallback` is **4-arg** in .NET 9:
  `(Object, X509Certificate, X509Chain, SslPolicyErrors) -> bool`.
  → the trust-any callback is `(fun _ _ _ _ -> true)`. (Pre-.NET-9 this was 3-arg; the 4th `SslPolicyErrors` param was added. If this ever compiles against an older TFM, drop one `_`.)
- `SslStream` constructor overload we use: `new SslStream(Stream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback)`.
- Synchronous handshake: `SslStream.AuthenticateAsClient(string targetHost)` (exists alongside the async overloads). We use the **sync** form because the entire Fauli handler is synchronous blocking I/O (`socket.Connect`, `stream.Write`, …); introducing `Task`/`.Wait()` would be inconsistent and risks deadlocks.
- All stream operations the bind pipeline uses — `Write`, `Flush`, `ReadByte`, `Read` — are on the base `Stream`, not `NetworkStream`. Widening the parameter type is behavior-preserving.

## Scope decisions (confirmed with user)

- **Implicit TLS only** (port 636). No STARTTLS / `ExtendedOperation` in this feature.
- **No server-certificate validation.** Trust-any callback. The existing `AuthError.Certificate*` cases are for *client* certs (PKINIT) and are untouched.

## Files likely to change

- Modify: `src/Domain.fs` — widen `LdapSession.Stream` from `NetworkStream` to `Stream` (public, widening change).
- Modify: `src/Ldap/Handler.fs` — the bulk: widen bind-pipeline stream params to `Stream`, add `authenticateTls`, `transportStreamFor` + `establishTransportStream`, split `bindAndWrap` into `performSaslBind` + `wrapLdapResponse`, rewire `handleLdap`.
- Test: `tests/Fauli.Tests/LdapWireTests.fs` — keep green (no changes expected).
- Create: `tests/Fauli.Tests/LdapTlsTests.fs` — local TLS integration test.
- Modify: `tests/Fauli.Tests/Fauli.Tests.fsproj` (only if a new file needs explicit `<Compile>` — verify; SDK-style projects auto-glob, so likely no change).
- Modify: `src/Solver.fs` doc comment (`:386`) and `README.md` — update "TLS not fully implemented" wording.
- Modify: `CHANGELOG.md` + `Fauli.fsproj` version bump (final task).

## Assumptions

- `handleLdap` is the only public entry that produces an `LdapSession`; nothing else constructs one. (Confirmed: only `Ldap/Handler.fs` builds `LdapSession`.)
- No other code pattern-matches on `LdapSession.Stream` as a `NetworkStream`. (Confirmed: only the handler reads `.Stream`.)
- The existing pure wire tests do not reference `NetworkStream`/`LdapSession` (confirmed — they only use `buildSaslBindRequest` and `parseBindResponse`).

---

### Task 1: Widen `LdapSession.Stream` to `Stream`

**Objective:** Make the public session record transport-agnostic so it can hold an `SslStream`.

**Files:**
- Modify: `src/Domain.fs:265-281` (the `LdapSession` record)

**Step 1: Change the field type**

In `type LdapSession`, change:
```fsharp
      Stream : NetworkStream
```
to:
```fsharp
      Stream : Stream
```
Update the doc comment above the field from "underlying bidirectional TCP stream" to "underlying bidirectional stream (plain TCP or TLS)."

**Step 2: Verify it compiles (expect failures in the handler)**

Run: `dotnet build`
Expected: FAIL — the LDAP handler still constructs/assigns `NetworkStream` values into `LdapSession.Stream` and its bind functions still declare `NetworkStream`. This is expected; Task 2 fixes the handler. Do NOT stop here to "fix" the handler piecemeal — go to Task 2.

**Step 3: Commit (after Task 2, see below)** — this task is committed together with Task 2 because the tree does not compile between them.

---

### Task 2: Widen the LDAP bind pipeline to `Stream` and add the TLS step

**Objective:** Make the whole bind path transport-agnostic and insert the implicit-TLS handshake as a named step.

**Files:**
- Modify: `src/Ldap/Handler.fs`

**Step 1: Add the `System.Net.Security` open**

At the top of `src/Ldap/Handler.fs`, after `open System.Net.Sockets`, add:
```fsharp
open System.Net.Security
```

**Step 2: Widen every bind-pipeline stream parameter from `NetworkStream` to `Stream`**

In `src/Ldap/Handler.fs`, change the parameter type `stream : NetworkStream` to `stream : Stream` in **all** of these functions (mechanical, one per signature):
- `sendLdapRequest`
- `tryReadByte`
- `tryFillBuffer`
- `decodeBerLengthPrefix`
- `readByteOrFail`
- `readBerLength`
- `readContentOrFail`
- `receiveLdapMessage`
- `receiveAndParseBind`
- `exchangeSaslBind`
- `sessionFromSuccess`
- `sessionFromKerberosBind`
- `performKerberosSaslBind`
- `completeNtlmLeg2`
- `continueNtlmAfterType2`
- `continueNtlmAfterLeg1Creds`
- `performNtlmSaslBind`
- `dispatchSaslBind`
- `retainStreamOnSuccess`

No body changes are required — every body call (`Write`, `Flush`, `ReadByte`, `Read`) resolves on `Stream`.

**Step 3: Add the trust-any callback and the TLS functions**

Add near the other private helpers (before `performLdapSaslBind`):
```fsharp
///
/// Fauli is a pentesting library and does not validate server identity:
/// the LDAPS server certificate is always accepted.
let private trustAnyServerCertificate : RemoteCertificateValidationCallback =
    (fun _ _ _ _ -> true)


///
/// Map a TLS handshake exception onto an AuthError.
let private mapTlsException (ex : exn) : AuthError =
    match ex with
    | :? AuthenticationException -> ProtocolHandshakeFailed
    | :? SocketException -> ProtocolConnectionFailed
    | :? IOException -> ProtocolConnectionFailed
    | _ -> UnexpectedError $"LDAPS handshake failed: {ex.Message}"


///
/// Perform the implicit-TLS client handshake on a plain stream.
/// Returns the authenticated SslStream (as Stream) on success.
let internal authenticateTls (host : Host) (stream : Stream) : Result<Stream, AuthError> =
    let (Host hostStr) = host
    try
        let sslStream = new SslStream(stream, leaveInnerStreamOpen = false, trustAnyServerCertificate)
        sslStream.AuthenticateAsClient hostStr
        sslStream |> Ok
    with ex ->
        mapTlsException ex |> Error


///
/// Named step: given an open socket, produce the transport stream for the configured
/// transport. LdapPlain → plain NetworkStream. LdapTls → SslStream after the client handshake.
/// Extracted so the transport dispatch is a single flat match (no nested conditionals).
let private transportStreamFor (host : Host) (config : LdapConnectionConfig) (socket : Socket) : Result<Stream, AuthError> =
    let networkStream = new NetworkStream(socket, ownsSocket = true)
    match config.transport with
    | LdapPlain -> networkStream |> Ok
    | LdapTls -> authenticateTls host networkStream


///
/// Named step: wrap the open socket in a transport stream. All Result handling lives here;
/// the transport-specific work is delegated to transportStreamFor.
let internal establishTransportStream (host : Host) (config : LdapConnectionConfig) (socketResult : Result<Socket, AuthError>) : Result<Stream, AuthError> =
    match socketResult with
    | Error e -> e |> Error
    | Ok socket -> transportStreamFor host config socket
```

**Step 4: Replace `performLdapSaslBind` with a stream-taking `performSaslBind`**

The old function builds the `NetworkStream` itself; that now lives in `establishTransportStream`. Replace:
```fsharp
let private performLdapSaslBind (socket : Socket) (authParams : ProtocolHandlerParams) : Result<LdapSession, AuthError> =
    let stream = new NetworkStream(socket, ownsSocket = true)
    dispatchSaslBind stream authParams
    |> retainStreamOnSuccess stream
```
with:
```fsharp
///
/// Named step: run the SASL bind over an established transport stream.
/// Owns the stream on success; disposes it on failure so sockets do not leak.
let private performSaslBind (authParams : ProtocolHandlerParams) (streamResult : Result<Stream, AuthError>) : Result<LdapSession, AuthError> =
    match streamResult with
    | Error e -> e |> Error
    | Ok stream ->
        dispatchSaslBind stream authParams
        |> retainStreamOnSuccess stream
```

**Step 5: Split `bindAndWrap` into `wrapLdapResponse` and rewire `handleLdap`**

Replace the existing `bindAndWrap` + `handleLdap`:
```fsharp
let private bindAndWrap (authParams : ProtocolHandlerParams) (socketResult : Result<Socket, AuthError>) : Result<AuthenticatedResponse, AuthError> =
    match socketResult with
    | Error e -> e |> Error
    | Ok socket ->
        match performLdapSaslBind socket authParams with
        | Error e -> e |> Error
        | Ok session -> wrapLdapAuthenticatedResponse session authParams |> Ok


let internal handleLdap (host : Host) (config : LdapConnectionConfig) (authParams : ProtocolHandlerParams) : Result<AuthenticatedResponse, AuthError> =
    openLdapConnection host config
    |> bindAndWrap authParams
```
with:
```fsharp
///
/// Named step: wrap a bound session into the authenticated response.
let private wrapLdapResponse (authParams : ProtocolHandlerParams) (sessionResult : Result<LdapSession, AuthError>) : Result<AuthenticatedResponse, AuthError> =
    match sessionResult with
    | Error e -> e |> Error
    | Ok session -> wrapLdapAuthenticatedResponse session authParams |> Ok


let internal handleLdap (host : Host) (config : LdapConnectionConfig) (authParams : ProtocolHandlerParams) : Result<AuthenticatedResponse, AuthError> =
    openLdapConnection host config
    |> establishTransportStream host config
    |> performSaslBind authParams
    |> wrapLdapResponse authParams
```

The pipeline now reads as pure named domain steps with zero monadic operators between the pipes; all `Result` handling is inside the named functions.

**Step 6: Build**

Run: `dotnet build`
Expected: PASS, 0 warnings (the project treats warnings as errors). If a stray `NetworkStream` reference remains, fix it to `Stream`.

**Step 7: Commit (combines Task 1 + Task 2)**

```bash
git add src/Domain.fs src/Ldap/Handler.fs
git commit -m "feat(ldap): implicit TLS (LDAPS) on port 636 with trust-any server cert"
```

---

### Task 3: Add a local TLS integration test

**Objective:** Prove the `LdapTls` path performs a real handshake and can carry a SASL bind, using a local `SslStream` listener with a self-signed cert (no external AD needed).

**Files:**
- Create: `tests/Fauli.Tests/LdapTlsTests.fs`

**Step 1: Write the test**

```fsharp
/// Integration test for the LDAPS (implicit TLS) transport path.
/// A local SslStream listener with a self-signed cert stands in for an AD DC;
/// Fauli must complete the client handshake and carry a SASL bind over it.
module Fauli.Tests.LdapTlsTests

open System
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Threading
open Xunit
open Fauli.Domain
open Fauli.Ldap.Handler


/// Generate a throwaway self-signed cert for the local TLS listener.
let private makeSelfSignedCert () : X509Certificate2 =
    let rsa = RSA.Create(2048)
    let req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
    let cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1))
    // Re-import so the private key is retained for the server SslStream.
    use _ = rsa
    cert


/// Start a local TLS listener that accepts one connection, completes the server
/// handshake, then echoes a fixed BindResponse back so the client bind can proceed.
let private startTlsListener (cert : X509Certificate2) (bindResponseBytes : byte array) : int * Thread =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()
    let port = int (listener.Server.IPEndPoint.Port)
    let thread =
        Thread (fun _ ->
            let client = listener.AcceptTcpClient()
            use client = client
            let inner = client.GetStream()
            let serverSsl = new SslStream(inner, false)
            serverSsl.AuthenticateAsServer(cert)
            // Read the client's bind request (drain), then send our canned response.
            let buf = Array.zeroCreate<byte> 4096
            ignore (serverSsl.Read(buf, 0, buf.Length))
            serverSsl.Write(bindResponseBytes, 0, bindResponseBytes.Length)
            serverSsl.Flush())
    thread.Start()
    port, thread


[<Fact>]
let ``establishTransportStream performs an implicit-TLS handshake (LdapTls)`` () =
    let cert = makeSelfSignedCert ()
    let canned = Array.zeroCreate<byte> 0 // handshake only; response content irrelevant here
    let port, _ = startTlsListener cert canned
    let host = Host.create "127.0.0.1" |> Option.get
    let config = LdapConnectionConfig.defaults
    let socket =
        new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        |> fun s -> s.Connect("127.0.0.1", port)
    match establishTransportStream host config (socket |> Ok) with
    | Ok stream ->
        // A successful handshake yields an authenticated SslStream.
        Assert.True(stream :? SslStream)
        stream.Dispose()
    | Error e -> Assert.Fail(sprintf "establishTransportStream failed: %A" e)


[<Fact>]
let ``establishTransportStream returns a plain stream for LdapPlain`` () =
    let host = Host.create "127.0.0.1" |> Option.get
    let config = { LdapConnectionConfig.defaults with transport = LdapPlain }
    let socket =
        new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        |> fun s -> s.Connect("127.0.0.1", 1) // connect will fail; we only test the branch on a live socket below
    // Use a connected socket so NetworkStream construction succeeds:
    let listener = new TcpListener(IPAddress.Loopback, 0)
    listener.Start()
    let port = int (listener.Server.IPEndPoint.Port)
    let live = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
    live.Connect("127.0.0.1", port)
    let _ = socket
    match establishTransportStream host config (live |> Ok) with
    | Ok stream ->
        Assert.True(stream :? NetworkStream)
        Assert.False(stream :? SslStream)
        stream.Dispose()
    | Error e -> Assert.Fail(sprintf "establishTransportStream failed: %A" e)
```

> Note for the implementer: the `LdapPlain` test above is a little awkward (it opens a throwaway listener just to get a connected socket). If it proves fiddly, simplify it to only assert the `LdapTls` handshake fact and drop the `LdapPlain` case — the `LdapPlain` branch is already exercised by the existing behavior. Do not let test scaffolding bloat; YAGNI.

**Step 2: Run the new tests**

Run: `dotnet test --filter "FullyQualifiedName~LdapTlsTests"`
Expected: PASS (both facts). If `Host.create` returns a `Result`, adjust the `Option.get` to match on `Ok` — verify the actual shape of `Host.create` (`src/Domain.fs:307`) before finalizing.

**Step 3: Commit**

```bash
git add tests/Fauli.Tests/LdapTlsTests.fs
git commit -m "test(ldap): local TLS integration test for LDAPS transport"
```

---

### Task 4: Full test suite + docs

**Objective:** Confirm nothing regressed and that user-facing docs reflect real LDAPS support.

**Files:**
- Modify: `src/Solver.fs:386` (doc comment)
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `Fauli.fsproj` (version bump)

**Step 1: Run the whole suite**

Run: `dotnet test`
Expected: PASS, all tests (existing `LdapWireTests` + new `LdapTlsTests` + everything else).

**Step 2: Fix the stale "TLS not fully implemented" wording**

In `src/Solver.fs` doc comment (`:386`), change:
```
///       TCP to <c>connectHost</c> port 389 (<c>LdapPlain</c>) or 636 (<c>LdapTls</c>; TLS not fully
///       implemented beyond port selection). SASL bind ...
```
to accurately describe that `LdapTls` performs an implicit-TLS handshake (trust-any server cert) before the SASL bind.

In `README.md`, update line 5 from:
```
Supports Kerberos and NetNTLMv2 for SMB, LDAP
```
to note LDAPS (implicit TLS) support, e.g.:
```
Supports Kerberos and NetNTLMv2 for SMB and LDAP, including LDAPS (implicit TLS on port 636).
```

**Step 3: Bump version + changelog**

In `Fauli.fsproj`, bump `<Version>` to the next date-based value (match the existing `YYYY.M.D` scheme; use today's date).
Add a `CHANGELOG.md` entry:
```
### <new-version>
- LDAPS (implicit TLS) support for LDAP connections on port 636. Server certificate is not validated (pentesting use).
```

**Step 4: Final build + test**

Run: `dotnet build && dotnet test`
Expected: PASS, 0 warnings.

**Step 5: Commit**

```bash
git add src/Solver.fs README.md CHANGELOG.md Fauli.fsproj
git commit -m "docs: document LDAPS support; bump version"
```

---

## Risks, tradeoffs, and open questions

- **Public API widening (`LdapSession.Stream : NetworkStream` → `Stream`).** Source-compatible for anyone calling `.Read/.Write/.Flush`; only breaks hypothetical code that downcasts to `NetworkStream`. Acceptable and more correct (the domain shouldn't leak a specific transport type). Flag it in the changelog.
- **Sync `AuthenticateAsClient`.** Consistent with Fauli's fully-synchronous handlers. If a future caller invokes `authenticate` from a UI sync context, the blocking handshake could surface a deadlock — but that is already true of the existing blocking `socket.Connect`, so it's not a new class of risk.
- **Trust-any is intentional and documented.** This is a security-relevant choice; it is scoped to the LDAPS transport only and does not affect any other protocol or the client-cert (PKINIT) path.
- **Self-signed cert in tests.** `CertificateRequest.CreateSelfSigned` + `RSA.Create` is standard on .NET 9 and needs no external tooling. The test binds to `127.0.0.1:0` (ephemeral port) so it won't collide with real services.
- **`Host.create` shape.** Verify whether it returns `Result<Host, AuthError>` or `Host` (`src/Domain.fs:307`) and adjust the test's unwrap accordingly before finalizing Task 3.

## Verification summary

- `dotnet build` → 0 warnings, 0 errors (project has `WarningsAsErrors`).
- `dotnet test` → all green, including the new `LdapTlsTests`.
- Manual smoke (optional, if an AD/LDAPS endpoint is available): call `Solver.authenticate` with `ConnectionType.Ldap { transport = LdapTls; ... }` and confirm a successful bind over 636.
