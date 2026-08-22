module internal Fauli.Ldap.Handler

open System
open System.IO
open System.Net.Security
open System.Net.Sockets
open System.Security.Authentication
open System.Text

open Fauli.Domain
open Fauli.Kerberos.Auth
open Fauli.Kerberos.Encoding
open Fauli.GssApi
open Fauli.Ntlm.Auth
open Fauli.Ntlm.Crypto
open Fauli.Ntlm.Encoding


///
/// Result of parsing an LDAP BindResponse. Internal (testable) wire parse product.
type internal LdapBindResult =
    { resultCode : int
      matchedDN : string
      diagnosticMessage : string
      serverSaslCreds : byte array option }


///
/// LDAP resultCode values we care about (RFC 4511 §4.1.9).
let private ldapSuccess = 0


let private ldapSaslBindInProgress = 14


///
/// SASL mechanism name for SPNEGO over LDAP (RFC 4178 / MS-ADTS).
let private saslMechanismGssSpnego = "GSS-SPNEGO"


let private encodeLdapString (value : string) : byte array =
    encodeOctetString (Encoding.UTF8.GetBytes value)


let internal buildSaslBindRequest (messageId : int) (spnegoToken : byte array) : byte array =
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


let private mapLdapIoException (action : string) (ex : exn) : AuthError =
    match ex with
    | :? SocketException -> ProtocolConnectionFailed
    | _ -> UnexpectedError $"LDAP {action} failed: {ex.Message}"


let private sendLdapRequest (stream : Stream) (message : byte array) : Result<unit, AuthError> =
    try
        stream.Write(message, 0, message.Length)
        stream.Flush()
        () |> Ok
    with ex ->
        mapLdapIoException "send" ex |> Error


///
/// Read one stream byte as Option (None = EOF).
let private tryReadByte (stream : Stream) : int option =
    match stream.ReadByte() with
    | b when b < 0 -> None
    | b -> Some b


///
/// Fold big-endian length octets into an integer.
let private foldBigEndianLength (bytes : byte array) : int =
    bytes
    |> Array.fold (fun acc b -> (acc <<< 8) ||| int b) 0


///
/// Fill a buffer from the stream; false on EOF before complete.
let private tryFillBuffer (stream : Stream) (buffer : byte array) : bool =
    let rec loop off rem =
        match rem <= 0 with
        | true -> true
        | false ->
            match stream.Read(buffer, off, rem) with
            | r when r <= 0 -> false
            | r -> loop (off + r) (rem - r)
    loop 0 buffer.Length


///
/// Decode definite BER length after the first length octet has been read.
/// Returns (length-prefix-bytes including first octet, content length) or None.
/// 
let private decodeBerLengthPrefix (stream : Stream) (lenFirst : int) : (byte array * int) option =
    match lenFirst &&& 0x80 = 0 with
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


///
/// Assemble tag + length prefix + content into one BER TLV buffer.
let private assembleBerMessage (tag : int) (lengthPrefix : byte array) (content : byte array) : byte array =
    Array.concat [| [| byte tag |]; lengthPrefix; content |]


///
/// Read one stream byte as Result (EOF = ProtocolConnectionFailed).
let private readByteOrFail (stream : Stream) : Result<int, AuthError> =
    match tryReadByte stream with
    | None -> ProtocolConnectionFailed |> Error
    | Some b -> b |> Ok


///
/// Decode a definite BER length prefix from the stream as a Result.
let private readBerLength (stream : Stream) : Result<byte array * int, AuthError> =
    match readByteOrFail stream with
    | Error e -> e |> Error
    | Ok lenFirst ->
        match decodeBerLengthPrefix stream lenFirst with
        | None -> UnexpectedError "LDAP receive: invalid BER length" |> Error
        | Some (prefix, len) when len < 0 -> UnexpectedError "LDAP receive: invalid BER length" |> Error
        | Some (prefix, len) -> (prefix, len) |> Ok


///
/// Read exactly len content bytes from the stream as a Result.
let private readContentOrFail (stream : Stream) (len : int) : Result<byte array, AuthError> =
    let content = Array.zeroCreate<byte> len
    match tryFillBuffer stream content with
    | false -> ProtocolConnectionFailed |> Error
    | true -> content |> Ok


///
/// Read one complete BER TLV from the stream (tag + length octets + content).
let private receiveLdapMessage (stream : Stream) : Result<byte array, AuthError> =
    try
        match readByteOrFail stream with
        | Error e -> e |> Error
        | Ok tag ->
            match readBerLength stream with
            | Error e -> e |> Error
            | Ok (lengthPrefix, contentLen) ->
                readContentOrFail stream contentLen
                |> Result.map (fun content -> assembleBerMessage tag lengthPrefix content)
    with ex ->
        mapLdapIoException "receive" ex |> Error


let private decodeUtf8 (bytes : byte array) : string =
    try Encoding.UTF8.GetString(bytes).Trim('\u0000').Trim()
    with _ -> ""


///
/// ENUMERATED / INTEGER value from a small BER content buffer.
let private decodeSmallInt (bytes : byte array) : int option =
    match bytes.Length with
    | 0 -> None
    | n when n > 4 -> None
    | _ -> Some (foldBigEndianLength bytes)


///
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


///
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


///
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


///
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
        { resultCode = pickResultCode fields
          matchedDN = nthStringOrEmpty strings 0
          diagnosticMessage = nthStringOrEmpty strings 1
          serverSaslCreds = pickServerSaslCreds fields } |> Ok
    with ex ->
        UnexpectedError $"Failed to parse LDAP BindResponse: {ex.Message}" |> Error


///
/// Continue after a successful send into receive + parse.
let private receiveAndParseBind (stream : Stream) (sendResult : Result<unit, AuthError>) : Result<LdapBindResult, AuthError> =
    match sendResult with
    | Error e -> e |> Error
    | Ok () ->
        match receiveLdapMessage stream with
        | Error e -> e |> Error
        | Ok response -> parseBindResponse response


let private exchangeSaslBind (stream : Stream) (messageId : int) (spnegoToken : byte array) : Result<LdapBindResult, AuthError> =
    buildSaslBindRequest messageId spnegoToken
    |> sendLdapRequest stream
    |> receiveAndParseBind stream


let private boundAsFromMatchedDn (matchedDN : string) : string option =
    match String.IsNullOrWhiteSpace matchedDN with
    | true -> None
    | false -> Some matchedDN


let private sessionFromSuccess (stream : Stream) (nextMessageId : int) (bindResult : LdapBindResult) : LdapSession =
    { Stream = stream
      NextMessageId = nextMessageId
      BoundAs = boundAsFromMatchedDn bindResult.matchedDN }


let private buildKerberosSpnegoToken (authParams : KerberosTicketParams) : byte array =
    let (ServiceTicket ticketBytes) = authParams.serviceTicket
    buildSpnegoToken (buildApReqFromDomain ticketBytes authParams.sessionKey authParams.clientRealm authParams.clientName)


///
/// Map a Kerberos bind response onto session success or rejection.
let private sessionFromKerberosBind (stream : Stream) (bindResult : Result<LdapBindResult, AuthError>) : Result<LdapSession, AuthError> =
    match bindResult with
    | Error e -> e |> Error
    | Ok br when br.resultCode = ldapSuccess ->
        sessionFromSuccess stream 2 br |> Ok
    | Ok _ ->
        ProtocolAuthenticationRejected |> Error


let private performKerberosSaslBind (stream : Stream) (authParams : KerberosTicketParams) : Result<LdapSession, AuthError> =
    buildKerberosSpnegoToken authParams
    |> exchangeSaslBind stream 1
    |> sessionFromKerberosBind stream


///
/// Clamp a machine name into a 15-char NetBIOS-style workstation label.
let private clampWorkstationName (name : string) : string =
    match String.IsNullOrWhiteSpace name with
    | true -> "DESKTOP-FAULI"
    | false when name.Length <= 15 -> name.ToUpperInvariant()
    | false -> name.Substring(0, 15).ToUpperInvariant()


///
/// Workstation name for NTLM — host-derived, not a hardcoded tool banner.
let private ntlmWorkstationName () : string =
    try clampWorkstationName Environment.MachineName
    with _ -> "DESKTOP-FAULI"


///
/// LDAP SASL NTLM Type1 flags.
/// IMPORTANT: Do NOT set NegotiateSign / NegotiateSeal / NegotiateKeyExch until a security-layer is implemented.
/// 
let private ldapNtlmType1Flags : uint32 =
    NtlmFlags.NegotiateUnicode
    ||| NtlmFlags.RequestTarget
    ||| NtlmFlags.NegotiateNtlm
    ||| NtlmFlags.NegotiateExtendedSessionSecurity
    ||| NtlmFlags.NegotiateTargetInfo
    ||| NtlmFlags.NegotiateVersion
    ||| NtlmFlags.Negotiate128
    ||| NtlmFlags.Negotiate56


///
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


///
/// NTLMSSP signature bytes for scanning serverSaslCreds.
let private ntlmSignature = Fauli.Constants.ntlmsspSignature


///
/// True when bytes start with the NTLMSSP signature and are long enough for Type2.
let private looksLikeNtlmType2 (t : byte array) : bool =
    t.Length >= 32
    && t.[0..6] = [| 0x4Euy; 0x54uy; 0x4Cuy; 0x4Duy; 0x53uy; 0x53uy; 0x50uy |]


///
/// Scan buffer for NTLMSSP signature and return the tail from that offset.
let private findNtlmPayload (serverSaslCreds : byte array) : byte array option =
    let rec loop i =
        match i + 8 > serverSaslCreds.Length with
        | true -> None
        | false when Array.sub serverSaslCreds i 8 = ntlmSignature ->
            Some (Array.sub serverSaslCreds i (serverSaslCreds.Length - i))
        | false -> loop (i + 1)
    loop 0


///
/// Extract NTLMSSP Type2 bytes from serverSaslCreds (SPNEGO NegTokenResp or raw NTLM).
let private extractNtlmType2 (serverSaslCreds : byte array) : byte array =
    let _, mechOpt = parseSnegoNegTokenResp serverSaslCreds
    match mechOpt with
    | Some t when looksLikeNtlmType2 t -> t
    | _ -> defaultArg (findNtlmPayload serverSaslCreds) [||]


///
/// Require saslBindInProgress + serverSaslCreds on leg 1.
let private requireSaslInProgress (leg1 : Result<LdapBindResult, AuthError>) : Result<byte array, AuthError> =
    match leg1 with
    | Error e -> e |> Error
    | Ok br when br.resultCode <> ldapSaslBindInProgress -> 
        ProtocolAuthenticationRejected |> Error
    | Ok br ->
        match br.serverSaslCreds with
        | None -> ProtocolAuthenticationRejected |> Error
        | Some creds -> creds |> Ok


///
/// Require a usable Type2 blob length.
let private requireValidType2 (type2Bytes : byte array) : Result<byte array, AuthError> =
    match type2Bytes.Length < 32 with
    | true -> ProtocolAuthenticationRejected |> Error
    | false -> type2Bytes |> Ok


///
/// Build Type3 SPNEGO token from challenge + password material.
let private buildNtlmType3Token (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (type2Bytes : byte array) (challenge : ChallengeMessage) : byte array =
    let type3Flags = challenge.negotiateFlags &&& ldapNtlmType1Flags
    let ntlmV2 = computeNtlmV2Response password user domain challenge
    let type3 =
        buildAuthenticateMessage
            type3Flags ntlmV2 type1 type2Bytes domain user workstation
    wrapNtlmNegTokenResp type3


///
/// Continue NTLM leg 2 after challenge parse.
let private completeNtlmLeg2 (stream : Stream) (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (type2Bytes : byte array) (challengeResult : Result<ChallengeMessage, AuthError>) : Result<LdapSession, AuthError> =
    match challengeResult with
    | Error e -> e |> Error
    | Ok challenge ->
        let token3 = buildNtlmType3Token password user domain workstation type1 type2Bytes challenge
        match exchangeSaslBind stream 2 token3 with
        | Error e -> e |> Error
        | Ok leg2 when leg2.resultCode = ldapSuccess ->
            sessionFromSuccess stream 3 leg2 |> Ok
        | Ok _ ->
            ProtocolAuthenticationRejected |> Error


///
/// After Type2 bytes are validated, parse challenge and finish leg 2.
let private continueNtlmAfterType2 (stream : Stream) (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (type2Result : Result<byte array, AuthError>) : Result<LdapSession, AuthError> =
    match type2Result with
    | Error e -> e |> Error
    | Ok type2Bytes ->
        decodeChallengeMessage type2Bytes
        |> completeNtlmLeg2 stream password user domain workstation type1 type2Bytes


///
/// After leg-1 creds are accepted, extract Type2 and finish the NTLM bind.
let private continueNtlmAfterLeg1Creds (stream : Stream) (password : string) (user : string) (domain : string) (workstation : string) (type1 : byte array) (credsResult : Result<byte array, AuthError>) : Result<LdapSession, AuthError> =
    match credsResult with
    | Error e -> e |> Error
    | Ok creds ->
        extractNtlmType2 creds
        |> requireValidType2
        |> continueNtlmAfterType2 stream password user domain workstation type1


let private performNtlmSaslBind (stream : Stream) (authParams : NtlmResponseParams) : Result<LdapSession, AuthError> =
    let (UserName user) = authParams.userName
    let (DomainName domain) = authParams.domain
    let (Password password) = authParams.password
    let workstation = ntlmWorkstationName ()
    let type1 = buildNtlmType1 domain workstation
    let token1 = wrapNtlmSpnego type1
    exchangeSaslBind stream 1 token1
    |> requireSaslInProgress
    |> continueNtlmAfterLeg1Creds stream password user domain workstation type1


let private dispatchSaslBind (stream : Stream) (authParams : ProtocolHandlerParams) : Result<LdapSession, AuthError> =
    match authParams with
    | KerberosTicket krb -> performKerberosSaslBind stream krb
    | NtlmResponse ntlm -> performNtlmSaslBind stream ntlm
    | _ -> NoSuitableAuthMethod |> Error


///
/// Own the stream on success; dispose on failure so sockets do not leak.
let private retainStreamOnSuccess (stream : Stream) (bindResult : Result<LdapSession, AuthError>) : Result<LdapSession, AuthError> =
    match bindResult with
    | Ok session -> session |> Ok
    | Error e ->
        stream.Dispose()
        e |> Error


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
/// Fauli is a pentesting library and does not validate server identity:
/// the LDAPS server certificate is always accepted.
let internal authenticateTls (host : Host) (stream : Stream) : Result<Stream, AuthError> =
    let (Host hostStr) = host
    try
        let sslStream = new SslStream(stream, false, (fun _ _ _ _ -> true))
        sslStream.AuthenticateAsClient hostStr
        (sslStream : Stream) |> Ok
    with ex ->
        mapTlsException ex |> Error


///
/// Named step: given an open socket, produce the transport stream for the configured
/// transport. LdapPlain → plain NetworkStream. LdapTls → SslStream after the client handshake.
let private transportStreamFor (host : Host) (config : LdapConnectionConfig) (socket : Socket) : Result<Stream, AuthError> =
    let networkStream = new NetworkStream(socket, ownsSocket = true)
    match config.transport with
    | LdapPlain -> (networkStream : Stream) |> Ok
    | LdapTls -> authenticateTls host networkStream


///
/// Named step: wrap the open socket in a transport stream. All Result handling lives here;
/// the transport-specific work is delegated to transportStreamFor.
let internal establishTransportStream (host : Host) (config : LdapConnectionConfig) (socketResult : Result<Socket, AuthError>) : Result<Stream, AuthError> =
    match socketResult with
    | Error e -> e |> Error
    | Ok socket -> transportStreamFor host config socket


///
/// Named step: run the SASL bind over an established transport stream.
/// Owns the stream on success; disposes it on failure so sockets do not leak.
let private performSaslBind (authParams : ProtocolHandlerParams) (streamResult : Result<Stream, AuthError>) : Result<LdapSession, AuthError> =
    match streamResult with
    | Error e -> e |> Error
    | Ok stream ->
        dispatchSaslBind stream authParams
        |> retainStreamOnSuccess stream


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
        socket |> Ok
    with
    | :? SocketException -> ProtocolConnectionFailed |> Error
    | ex -> UnexpectedError $"LDAP connection failed: {ex.Message}" |> Error


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
