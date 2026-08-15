module internal Fauli.Ldap.Handler

open System
open System.Net.Sockets
open System.Text

open Fauli.Domain
open Fauli.Kerberos.Auth
open Fauli.Kerberos.Encoding
open Fauli.GssApi
open Fauli.Ntlm.Auth
open Fauli.Ntlm.Crypto
open Fauli.Ntlm.Encoding


/// Result of parsing an LDAP BindResponse. Internal (testable) wire parse product.
type internal LdapBindResult =
    { resultCode : int
      matchedDN : string
      diagnosticMessage : string
      serverSaslCreds : byte array option }

/// LDAP resultCode values we care about (RFC 4511 §4.1.9).
let private ldapSuccess = 0
let private ldapSaslBindInProgress = 14

/// SASL mechanism name for SPNEGO over LDAP (RFC 4178 / MS-ADTS).
let private saslMechanismGssSpnego = "GSS-SPNEGO"

// ---------------------------------------------------------------------------
// BER helpers specific to LDAP (RFC 4511 uses OCTET STRING for LDAPString)
// ---------------------------------------------------------------------------


let private encodeLdapString (value : string) : byte array =
    encodeOctetString (Encoding.UTF8.GetBytes value)

let internal buildSaslBindRequest (messageId : int) (spnegoToken : byte array) : byte array =
    // SaslCredentials content under IMPLICIT [3] — no inner SEQUENCE tag.
    let saslContent =
        Array.concat
            [| encodeLdapString saslMechanismGssSpnego
               encodeOctetString spnegoToken |]

    let bindRequestBody =
        Array.concat
            [| encodeInteger 3
               encodeLdapString ""
               encodeContextConstructed 3 saslContent |]

    let bindRequest = encodeApplicationConstructed 0 bindRequestBody

    encodeSequence
        [| encodeInteger messageId
           bindRequest |]

// ---------------------------------------------------------------------------
// Send / receive a single LDAP BER message over a stream
// ---------------------------------------------------------------------------

let private mapLdapIoException (action : string) (ex : exn) : AuthError =
    match ex with
    | :? SocketException -> ProtocolConnectionFailed
    | _ -> UnexpectedError $"LDAP {action} failed: {ex.Message}"


let private sendLdapRequest (stream : NetworkStream) (message : byte array) : Result<unit, AuthError> =
    try
        stream.Write(message, 0, message.Length)
        stream.Flush()
        Ok ()
    with ex ->
        Error (mapLdapIoException "send" ex)


/// Read one stream byte as Option (None = EOF).
let private tryReadByte (stream : NetworkStream) : int option =
    match stream.ReadByte() with
    | b when b < 0 -> None
    | b -> Some b


/// Fold big-endian length octets into an integer.
let private foldBigEndianLength (bytes : byte array) : int =
    bytes
    |> Array.fold (fun acc b -> (acc <<< 8) ||| int b) 0


/// Fill a buffer from the stream; false on EOF before complete.
let private tryFillBuffer (stream : NetworkStream) (buffer : byte array) : bool =
    let rec loop off rem =
        match rem <= 0 with
        | true -> true
        | false ->
            match stream.Read(buffer, off, rem) with
            | r when r <= 0 -> false
            | r -> loop (off + r) (rem - r)
    loop 0 buffer.Length


/// Decode definite BER length after the first length octet has been read.
/// Returns (length-prefix-bytes including first octet, content length) or None.
let private decodeBerLengthPrefix (stream : NetworkStream) (lenFirst : int) : (byte array * int) option =
    match (lenFirst &&& 0x80) = 0 with
    | true -> Some ([| byte lenFirst |], lenFirst)
    | false ->
        let num = lenFirst &&& 0x7F
        match num <= 0 || num > 4 with
        | true -> None
        | false ->
            let lenBytes = Array.zeroCreate<byte> num
            match tryFillBuffer stream lenBytes with
            | false -> None
            | true ->
                Some (Array.concat [| [| byte lenFirst |]; lenBytes |], foldBigEndianLength lenBytes)


/// Assemble tag + length prefix + content into one BER TLV buffer.
let private assembleBerMessage (tag : int) (lengthPrefix : byte array) (content : byte array) : byte array =
    Array.concat [| [| byte tag |]; lengthPrefix; content |]


/// Read one complete BER TLV from the stream (tag + length octets + content).
let private receiveLdapMessage (stream : NetworkStream) : Result<byte array, AuthError> =
    try
        match tryReadByte stream with
        | None -> Error ProtocolConnectionFailed
        | Some tag ->
            match tryReadByte stream with
            | None -> Error ProtocolConnectionFailed
            | Some lenFirst ->
                match decodeBerLengthPrefix stream lenFirst with
                | None -> Error (UnexpectedError "LDAP receive: invalid BER length")
                | Some (lengthPrefix, contentLen) when contentLen < 0 ->
                    Error (UnexpectedError "LDAP receive: invalid BER length")
                | Some (lengthPrefix, contentLen) ->
                    let content = Array.zeroCreate<byte> contentLen
                    match tryFillBuffer stream content with
                    | false -> Error ProtocolConnectionFailed
                    | true -> Ok (assembleBerMessage tag lengthPrefix content)
    with ex ->
        Error (mapLdapIoException "receive" ex)

// ---------------------------------------------------------------------------
// BindResponse parsing
// ---------------------------------------------------------------------------

let private decodeUtf8 (bytes : byte array) : string =
    try Encoding.UTF8.GetString(bytes).Trim('\u0000').Trim()
    with _ -> ""


/// ENUMERATED / INTEGER value from a small BER content buffer.
let private decodeSmallInt (bytes : byte array) : int option =
    match bytes.Length with
    | 0 -> None
    | n when n > 4 -> None
    | _ -> Some (foldBigEndianLength bytes)


/// Decode BER length at a buffer offset. Returns (contentStart, contentLen, nextPos) or None.
let private decodeLengthAt (buf : byte array) (pos : int) : (int * int * int) option =
    match pos + 1 >= buf.Length with
    | true -> None
    | false ->
        let lb = buf.[pos + 1]
        match (lb &&& 0x80uy) = 0uy with
        | true ->
            let len = int lb
            Some (pos + 2, len, pos + 2 + len)
        | false ->
            let num = int (lb &&& 0x7Fuy)
            match num <= 0 || num > 4 || pos + 2 + num > buf.Length with
            | true -> None
            | false ->
                let lenBytes = Array.sub buf (pos + 2) num
                let len = foldBigEndianLength lenBytes
                let cs = pos + 2 + num
                Some (cs, len, cs + len)


/// Walk raw TLVs so ENUMERATED (0x0A) is not lost as BerRaw without a code path.
let private readTlv (buf : byte array) (pos : int) : (byte * byte array * int) option =
    match pos >= buf.Length with
    | true -> None
    | false ->
        let tag = buf.[pos]
        match decodeLengthAt buf pos with
        | None -> None
        | Some (contentStart, contentLen, next) when contentLen < 0 || next > buf.Length -> None
        | Some (contentStart, contentLen, next) ->
            Some (tag, Array.sub buf contentStart contentLen, next)


let private collectTlvs (buf : byte array) (pos : int) : (byte * byte array) list =
    let rec loop p acc =
        match readTlv buf p with
        | None -> List.rev acc
        | Some (tag, content, next) -> loop next ((tag, content) :: acc)
    loop pos []


/// Prefer APPLICATION 1 (BindResponse = 0x61) content; fall back to top SEQUENCE body.
let private extractBindBody (top : (byte * byte array) list) (data : byte array) : byte array =
    let fromNestedSequence content =
        collectTlvs content 0
        |> List.tryPick (fun (t2, c2) ->
            match t2 with
            | 0x61uy -> Some c2
            | _ -> None)

    let fromTop =
        top
        |> List.tryPick (fun (tag, content) ->
            match tag with
            | 0x61uy -> Some content
            | 0x30uy -> fromNestedSequence content
            | _ -> None)

    match fromTop with
    | Some body -> body
    | None ->
        match top with
        | (0x30uy, body) :: _ -> body
        | _ -> data


let private pickResultCode (fields : (byte * byte array) list) : int =
    fields
    |> List.tryPick (fun (tag, content) ->
        // ENUMERATED (0x0A) preferred; INTEGER (0x02) accepted for robustness
        match tag with
        | 0x0Auy | 0x02uy -> decodeSmallInt content
        | _ -> None)
    |> Option.defaultValue -1


let private pickOctetStrings (fields : (byte * byte array) list) : string list =
    fields
    |> List.choose (fun (tag, content) ->
        match tag with
        | 0x04uy -> Some (decodeUtf8 content)
        | _ -> None)


let private nthStringOrEmpty (strings : string list) (index : int) : string =
    match List.tryItem index strings with
    | Some s -> s
    | None -> ""


/// Unwrap serverSaslCreds [7] IMPLICIT OCTET STRING — primitive (0x87) or constructed (0xA7).
let private pickServerSaslCreds (fields : (byte * byte array) list) : byte array option =
    fields
    |> List.tryPick (fun (tag, content) ->
        match tag with
        | 0x87uy -> Some content
        | 0xA7uy ->
            match collectTlvs content 0 with
            | (0x04uy, inner) :: _ -> Some inner
            | _ -> Some content
        | _ -> None)


let internal parseBindResponse (data : byte array) : Result<LdapBindResult, AuthError> =
    try
        let top = collectTlvs data 0
        let fields = collectTlvs (extractBindBody top data) 0
        let strings = pickOctetStrings fields
        Ok
            { resultCode = pickResultCode fields
              matchedDN = nthStringOrEmpty strings 0
              diagnosticMessage = nthStringOrEmpty strings 1
              serverSaslCreds = pickServerSaslCreds fields }
    with ex ->
        Error (UnexpectedError $"Failed to parse LDAP BindResponse: {ex.Message}")

// ---------------------------------------------------------------------------
// Single bind round-trip: send SASL bind, parse BindResponse
// ---------------------------------------------------------------------------

/// Continue after a successful send into receive + parse.
let private receiveAndParseBind (stream : NetworkStream) (sendResult : Result<unit, AuthError>) : Result<LdapBindResult, AuthError> =
    match sendResult with
    | Error e -> Error e
    | Ok () ->
        match receiveLdapMessage stream with
        | Error e -> Error e
        | Ok response -> parseBindResponse response


let private exchangeSaslBind (stream : NetworkStream) (messageId : int) (spnegoToken : byte array) : Result<LdapBindResult, AuthError> =
    buildSaslBindRequest messageId spnegoToken
    |> sendLdapRequest stream
    |> receiveAndParseBind stream


let private boundAsFromMatchedDn (matchedDN : string) : string option =
    match String.IsNullOrWhiteSpace matchedDN with
    | true -> None
    | false -> Some matchedDN


let private sessionFromSuccess (stream : NetworkStream) (nextMessageId : int) (bindResult : LdapBindResult) : LdapSession =
    { Stream = stream
      NextMessageId = nextMessageId
      BoundAs = boundAsFromMatchedDn bindResult.matchedDN }

// ---------------------------------------------------------------------------
// Kerberos SASL bind (single-shot GSS-SPNEGO + AP-REQ)
// ---------------------------------------------------------------------------

let private buildKerberosSpnegoToken (authParams : KerberosTicketParams) : byte array =
    let (ServiceTicket ticketBytes) = authParams.serviceTicket
    buildSpnegoToken (buildApReqFromDomain ticketBytes authParams.sessionKey authParams.clientRealm authParams.clientName)


/// Map a Kerberos bind response onto session success or rejection.
let private sessionFromKerberosBind (stream : NetworkStream) (bindResult : Result<LdapBindResult, AuthError>) : Result<LdapSession, AuthError> =
    match bindResult with
    | Error e -> Error e
    | Ok br when br.resultCode = ldapSuccess ->
        sessionFromSuccess stream 2 br |> Ok
    | Ok _ ->
        Error ProtocolAuthenticationRejected


let private performKerberosSaslBind (stream : NetworkStream) (authParams : KerberosTicketParams) : Result<LdapSession, AuthError> =
    buildKerberosSpnegoToken authParams
    |> exchangeSaslBind stream 1
    |> sessionFromKerberosBind stream

// ---------------------------------------------------------------------------
// NTLM SASL bind (two-leg GSS-SPNEGO: Type1 → challenge → Type3)
// ---------------------------------------------------------------------------

/// Clamp a machine name into a 15-char NetBIOS-style workstation label.
let private clampWorkstationName (name : string) : string =
    match String.IsNullOrWhiteSpace name with
    | true -> "DESKTOP-FAULI"
    | false when name.Length <= 15 -> name.ToUpperInvariant()
    | false -> name.Substring(0, 15).ToUpperInvariant()


/// Workstation name for NTLM — host-derived, not a hardcoded tool banner.
let private ntlmWorkstationName () : string =
    try clampWorkstationName Environment.MachineName
    with _ -> "DESKTOP-FAULI"


/// LDAP SASL NTLM Type1 flags.
/// IMPORTANT: Do NOT set NegotiateSign / NegotiateSeal / NegotiateKeyExch until a security-layer is implemented.
let private ldapNtlmType1Flags : uint32 =
    NtlmFlags.NegotiateUnicode
    ||| NtlmFlags.RequestTarget
    ||| NtlmFlags.NegotiateNtlm
    ||| NtlmFlags.NegotiateExtendedSessionSecurity
    ||| NtlmFlags.NegotiateTargetInfo
    ||| NtlmFlags.NegotiateVersion
    ||| NtlmFlags.Negotiate128
    ||| NtlmFlags.Negotiate56


/// Overwrite the flags DWORD at offset 12 of a Type1 message.
let private overwriteNtlmFlags (buf : byte array) (flags : uint32) : byte array =
    match buf.Length >= 16 with
    | false -> buf
    | true ->
        buf.[12] <- byte (flags &&& 0xFFu)
        buf.[13] <- byte ((flags >>> 8) &&& 0xFFu)
        buf.[14] <- byte ((flags >>> 16) &&& 0xFFu)
        buf.[15] <- byte ((flags >>> 24) &&& 0xFFu)
        buf


let private buildNtlmType1 (domain : string) (workstation : string) : byte array =
    let msg = encodeNegotiateMessage (Some domain) (Some workstation) |> Array.copy
    overwriteNtlmFlags msg ldapNtlmType1Flags


/// NTLMSSP signature bytes for scanning serverSaslCreds.
let private ntlmSignature = Fauli.Constants.ntlmsspSignature


/// True when bytes start with the NTLMSSP signature and are long enough for Type2.
let private looksLikeNtlmType2 (t : byte array) : bool =
    t.Length >= 32
    && t.[0..6] = [| 0x4Euy; 0x54uy; 0x4Cuy; 0x4Duy; 0x53uy; 0x53uy; 0x50uy |]


/// Scan buffer for NTLMSSP signature and return the tail from that offset.
let private findNtlmPayload (serverSaslCreds : byte array) : byte array option =
    let rec loop i =
        match i + 8 > serverSaslCreds.Length with
        | true -> None
        | false when Array.sub serverSaslCreds i 8 = ntlmSignature ->
            Some (Array.sub serverSaslCreds i (serverSaslCreds.Length - i))
        | false -> loop (i + 1)
    loop 0


/// Extract NTLMSSP Type2 bytes from serverSaslCreds (SPNEGO NegTokenResp or raw NTLM).
let private extractNtlmType2 (serverSaslCreds : byte array) : byte array =
    let _, mechOpt = parseSnegoNegTokenResp serverSaslCreds
    match mechOpt with
    | Some t when looksLikeNtlmType2 t -> t
    | _ -> defaultArg (findNtlmPayload serverSaslCreds) [||]


/// Require saslBindInProgress + serverSaslCreds on leg 1.
let private requireSaslInProgress (leg1 : Result<LdapBindResult, AuthError>) : Result<byte array, AuthError> =
    match leg1 with
    | Error e -> Error e
    | Ok br when br.resultCode <> ldapSaslBindInProgress -> Error ProtocolAuthenticationRejected
    | Ok br ->
        match br.serverSaslCreds with
        | None -> Error ProtocolAuthenticationRejected
        | Some creds -> Ok creds


/// Require a usable Type2 blob length.
let private requireValidType2 (type2Bytes : byte array) : Result<byte array, AuthError> =
    match type2Bytes.Length < 32 with
    | true -> Error ProtocolAuthenticationRejected
    | false -> Ok type2Bytes


/// Build Type3 SPNEGO token from challenge + password material.
let private buildNtlmType3Token (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (type2Bytes : byte array) (challenge : ChallengeMessage) : byte array =
    // Intersect server challenge flags with the LDAP Type1 set so we
    // never accept Sign/Seal/KeyExch that Type1 did not offer.
    let type3Flags = challenge.negotiateFlags &&& ldapNtlmType1Flags
    let ntlmV2 = computeNtlmV2Response password user domain challenge
    let type3 =
        buildAuthenticateMessage
            type3Flags ntlmV2 type1 type2Bytes domain user workstation
    wrapNtlmNegTokenResp type3


/// Continue NTLM leg 2 after challenge parse.
let private completeNtlmLeg2 (stream : NetworkStream) (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (type2Bytes : byte array) (challengeResult : Result<ChallengeMessage, AuthError>) : Result<LdapSession, AuthError> =
    match challengeResult with
    | Error e -> Error e
    | Ok challenge ->
        let token3 = buildNtlmType3Token password user domain workstation type1 type2Bytes challenge
        match exchangeSaslBind stream 2 token3 with
        | Error e -> Error e
        | Ok leg2 when leg2.resultCode = ldapSuccess ->
            sessionFromSuccess stream 3 leg2 |> Ok
        | Ok _ ->
            Error ProtocolAuthenticationRejected


/// After Type2 bytes are validated, parse challenge and finish leg 2.
let private continueNtlmAfterType2 (stream : NetworkStream) (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (type2Result : Result<byte array, AuthError>) : Result<LdapSession, AuthError> =
    match type2Result with
    | Error e -> Error e
    | Ok type2Bytes ->
        parseChallenge type2Bytes
        |> completeNtlmLeg2 stream password user domain workstation type1 type2Bytes


/// After leg-1 creds are accepted, extract Type2 and finish the NTLM bind.
let private continueNtlmAfterLeg1Creds (stream : NetworkStream) (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (credsResult : Result<byte array, AuthError>) : Result<LdapSession, AuthError> =
    match credsResult with
    | Error e -> Error e
    | Ok creds ->
        extractNtlmType2 creds
        |> requireValidType2
        |> continueNtlmAfterType2 stream password user domain workstation type1


let private performNtlmSaslBind (stream : NetworkStream) (authParams : NtlmResponseParams) : Result<LdapSession, AuthError> =
    let (UserName user) = authParams.userName
    let (DomainName domain) = authParams.domain
    let (Password password) = authParams.password
    let workstation = ntlmWorkstationName ()
    let type1 = buildNtlmType1 domain workstation
    let token1 = wrapNtlmSpnego type1

    // Leg 1: NegTokenInit + NTLM Type1 → expect saslBindInProgress + serverSaslCreds
    exchangeSaslBind stream 1 token1
    |> requireSaslInProgress
    |> continueNtlmAfterLeg1Creds stream password user domain workstation type1

// ---------------------------------------------------------------------------
// Dispatch bind by auth params
// ---------------------------------------------------------------------------

let private dispatchSaslBind (stream : NetworkStream) (authParams : ProtocolHandlerParams) : Result<LdapSession, AuthError> =
    match authParams with
    | KerberosTicket krb -> performKerberosSaslBind stream krb
    | NtlmResponse ntlm -> performNtlmSaslBind stream ntlm
    | _ -> Error NoSuitableAuthMethod


/// Own the stream on success; dispose on failure so sockets do not leak.
let private retainStreamOnSuccess (stream : NetworkStream) (bindResult : Result<LdapSession, AuthError>) : Result<LdapSession, AuthError> =
    match bindResult with
    | Ok session -> Ok session
    | Error e ->
        stream.Dispose()
        Error e


let private performLdapSaslBind (socket : Socket) (authParams : ProtocolHandlerParams) : Result<LdapSession, AuthError> =
    let stream = new NetworkStream(socket, ownsSocket = true)
    dispatchSaslBind stream authParams
    |> retainStreamOnSuccess stream

// ---------------------------------------------------------------------------
// Supporting named steps
// ---------------------------------------------------------------------------

let private authMethodFromParams (authParams : ProtocolHandlerParams) : AuthenticationMethod =
    match authParams with
    | KerberosTicket _ -> Kerberos
    | NtlmResponse _ -> NetNTLMv2
    | _ -> Anonymous


let private emptySessionInfo : SessionInfo =
    { authenticatedAs = None
      expiresAt = None
      sessionId = None
      domain = None }


let private wrapLdapAuthenticatedResponse (session : LdapSession) (authParams : ProtocolHandlerParams) : AuthenticatedResponse =
    { connection = AuthLdap session
      authenticationMethod = authMethodFromParams authParams
      sessionInfo = emptySessionInfo }

// ---------------------------------------------------------------------------
// Connection setup
// ---------------------------------------------------------------------------

let private ldapPortForTransport (transport : LdapTransport) : int =
    match transport with
    | LdapPlain -> 389
    | LdapTls -> 636


let private openLdapConnection (host : Host) (config : LdapConnectionConfig) : Result<Socket, AuthError> =
    let (Host hostStr) = host
    let port = ldapPortForTransport config.transport
    try
        let socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        socket.ReceiveTimeout <- config.connectTimeout
        socket.SendTimeout <- config.connectTimeout
        socket.Connect(hostStr, port)
        Ok socket
    with
    | :? SocketException -> Error ProtocolConnectionFailed
    | ex -> Error (UnexpectedError $"LDAP connection failed: {ex.Message}")

// ---------------------------------------------------------------------------
// Public handler entry — composition of named steps
// ---------------------------------------------------------------------------

/// After a live socket is open, bind and wrap the authenticated response.
let private bindAndWrap (authParams : ProtocolHandlerParams) (socketResult : Result<Socket, AuthError>) : Result<AuthenticatedResponse, AuthError> =
    match socketResult with
    | Error e -> Error e
    | Ok socket ->
        match performLdapSaslBind socket authParams with
        | Error e -> Error e
        | Ok session -> wrapLdapAuthenticatedResponse session authParams |> Ok


let internal handleLdap (host : Host) (config : LdapConnectionConfig) (authParams : ProtocolHandlerParams) : Result<AuthenticatedResponse, AuthError> =
    openLdapConnection host config
    |> bindAndWrap authParams
