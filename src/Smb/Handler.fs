module internal Fauli.Smb.Handler


open System
open System.Net.Sockets
open System.Text

open Fauli.Domain
open Fauli.Kerberos.Auth
open Fauli.GssApi
open Fauli.Ntlm.Auth
open Fauli.Ntlm.Encoding
open Fauli.Ntlm.Crypto
open Fauli.Smb.Signing
open Fauli.Smb.Encryption


///
/// State after SMB2 dialect negotiation.
type SmbNegotiateState =
    { client : TcpClient
      stream : NetworkStream
      dialect : uint16
      serverGuid : byte array
      capabilities : uint32
      ///
      /// SecurityMode from the negotiate response (bit 0 = enabled, bit 1 = required).
      securityMode : uint16
      ///
      /// Negotiated CipherId (SMB 3.x). Defaults to AES-128-CCM when encryption is supported.
      cipherId : uint16
      ///
      /// Running SMB 3.1.1 preauth integrity hash (SHA-512 chain). Empty for other dialects.
      preauthHash : byte array
      ///
      /// Raw negotiate request bytes.
      negotiateRequestRaw : byte array
      ///
      /// Raw negotiate response bytes.
      negotiateResponseRaw : byte array }


///
/// State after SMB2 session setup.
type SmbSessionState =
    { stream : NetworkStream
      sessionId : uint64
      dialect : uint16
      ///
      /// The Kerberos/NTLM session key (SMB2.x signing material / SMB3.x KDF input).
      sessionKey : byte array
      ///
      /// Derived signing key (Some for SMB3.x, None for SMB2.x).
      signingKey : byte array option
      ///
      /// SMB3 transform encryption (Some when SessionFlags.ENCRYPT_DATA or SMB3+cap).
      encryption : SmbEncryption option }


///
/// Concatenate two byte arrays.
let internal concat2 (a : byte array) (b : byte array) : byte array =
    let result = Array.zeroCreate<byte> (a.Length + b.Length)
    Array.Copy(a, 0, result, 0, a.Length)
    Array.Copy(b, 0, result, a.Length, b.Length)
    result


///
/// Concatenate multiple byte arrays.
let private concatMany (arrays : byte array array) : byte array =
    let total = arrays |> Array.sumBy Array.length
    let result = Array.zeroCreate<byte> total
    let rec copyLoop idx offset =
        match idx < arrays.Length with
        | false -> ()
        | true ->
            Array.Copy(arrays.[idx], 0, result, offset, arrays.[idx].Length)
            copyLoop (idx + 1) (offset + arrays.[idx].Length)
    copyLoop 0 0
    result


///
/// Write a little-endian uint16.
let private le16 (v : uint16) : byte array =
    BitConverter.GetBytes(v)


///
/// Write a little-endian uint32.
let private le32 (v : uint32) : byte array =
    BitConverter.GetBytes(v)


///
/// Write a little-endian uint64.
let private le64 (v : uint64) : byte array =
    BitConverter.GetBytes(v)


///
/// SMB2 protocol identifier: "SMB" + 0xFE.
let private smb2ProtocolId : byte array = Fauli.Constants.smb2ProtocolId  // 0xFE + "SMB"


///
/// SMB2 negotiate request command.
let private smb2Negotiate = 0x0000us


///
/// NT_STATUS_SUCCESS.
let private ntStatusSuccess = 0x00000000u


///
/// NT_STATUS_MORE_PROCESSING_REQUIRED (NTLM second message expected).
let private ntStatusMoreProcessing = 0xC0000016u



///
/// SMB 3.1.1 preauth integrity chain ([MS-SMB2]):
///   H0 = 64 zero bytes
///   H' = SHA-512(H || message) for each negotiate/session-setup message in order.
/// 
let private preauthUpdate (current : byte array) (message : byte array) : byte array =
    use sha512 = Security.Cryptography.SHA512.Create()
    sha512.ComputeHash(Array.append current message)


let private preauthZero : byte array = Array.zeroCreate<byte> 64


///
/// Fold one message into the preauth chain.
let private foldPreauth (hash : byte array) (message : byte array) : byte array =
    preauthUpdate hash message


///
/// SMB 3.1.1 negotiate preauth: SHA512(0^64 || negoReq || negoResp).
let private negotiatePreauthHash (requestRaw : byte array) (response : byte array) : byte array =
    preauthZero
    |> foldPreauth requestRaw
    |> foldPreauth response


///
/// Credit request: keep the window healthy (Windows clients routinely request credits).
let private creditRequestFor (creditCharge : uint16) : uint16 =
    match creditCharge with
    | 0us -> 0us
    | c -> max c 1us


///
/// Populate a zeroed 64-byte buffer as an SMB2 header.
let private fillSmb2Header (command : uint16) (messageId : uint64) (sessionId : uint64) (treeId : uint32) (creditCharge : uint16) (h : byte array) : byte array =
    Array.Copy(smb2ProtocolId, 0, h, 0, 4)
    Array.Copy(le16 0x40us, 0, h, 4, 2)
    Array.Copy(le16 creditCharge, 0, h, 6, 2)
    Array.Copy(le16 command, 0, h, 12, 2)
    Array.Copy(le16 (creditRequestFor creditCharge), 0, h, 14, 2)
    Array.Copy(le64 messageId, 0, h, 24, 8)
    Array.Copy(le32 0xFEFFu, 0, h, 32, 4)
    Array.Copy(le32 treeId, 0, h, 36, 4)
    Array.Copy(le64 sessionId, 0, h, 40, 8)
    h


///
/// Build an SMB2 header with Windows-like defaults (not minimal third-party profile).
/// ProcessId 0xFEFF and non-zero CreditRequest match common Windows SMB2 clients.
/// 
let internal buildSmb2Header (command : uint16) (messageId : uint64) (sessionId : uint64) (treeId : uint32) (creditCharge : uint16) : byte array =
    Array.zeroCreate<byte> 64
    |> fillSmb2Header command messageId sessionId treeId creditCharge


///
/// Parse NTSTATUS from an SMB2 response header.
let private parseSmb2Status (header : byte array) : uint32 =
    BitConverter.ToUInt32(header, 8)


///
/// Wrap data in a NetBIOS Session Message header (type=0x00, 3-byte big-endian length).
let internal wrapNetbiosMessage (data : byte array) : byte array =
    let len = data.Length
    let header = Array.zeroCreate<byte> 4
    header.[0] <- 0x00uy                          // NetBIOS Session Message type
    header.[1] <- byte (len >>> 16)               // Length high byte (BE)
    header.[2] <- byte ((len >>> 8) &&& 0xFF)     // Length mid byte (BE)
    header.[3] <- byte (len &&& 0xFF)             // Length low byte (BE)
    Array.concat [| header; data |]


///
/// Read a NetBIOS Session Message from the stream: read the 4-byte header to get the length,
/// then read the payload. Strips the NetBIOS framing.
/// 
let internal readNetbiosMessage (stream : NetworkStream) : byte array =
    let rec readLoop () : byte array =
        let nbHeader = Array.zeroCreate<byte> 4
        let rec readNB off remaining =
            match remaining = 0 with
            | true -> nbHeader
            | false ->
                let r = stream.Read(nbHeader, off, remaining)
                match r = 0 with
                | true -> nbHeader
                | false -> readNB (off + r) (remaining - r)
        readNB 0 4 |> ignore
        let nbType = nbHeader.[0]
        match nbType with
        | 0x85uy -> readLoop ()
        | t when t <> 0x00uy ->
            readLoop ()
        | _ ->
            let length = int nbHeader.[1] <<< 16 ||| int nbHeader.[2] <<< 8 ||| int nbHeader.[3]
            let payload = Array.zeroCreate<byte> length
            let rec readPayload off remaining =
                match remaining = 0 with
                | true -> payload
                | false ->
                    let r = stream.Read(payload, off, remaining)
                    match r = 0 with
                    | true -> payload
                    | false -> readPayload (off + r) (remaining - r)
            readPayload 0 length
    readLoop ()


///
/// Read a raw SMB response: read the NetBIOS header, then read the SMB body.
let private readRawResponse (stream : NetworkStream) : byte array =
    readNetbiosMessage stream


///
/// Send raw SMB data (NetBIOS-wrapped) on the session NetworkStream and read one response.
/// One NetworkStream per connection — never create a second stream on the same socket.
/// 
let private sendRaw (stream : NetworkStream) (data : byte array) : byte array =
    let wrapped = wrapNetbiosMessage data
    stream.Write(wrapped, 0, wrapped.Length)
    stream.Flush()
    readNetbiosMessage stream

///
/// Build SMB2_PREAUTH_INTEGRITY_CAPABILITIES context (type 1) for SMB 3.1.1.
let private buildPreauthContext () : byte array =
    let salt = Array.zeroCreate<byte> 32
    Security.Cryptography.RandomNumberGenerator.Fill(salt)
    let data =
        concatMany
            [| le16 1us          // HashAlgorithmCount
               le16 32us         // SaltLength
               le16 0x0001us     // SHA-512
               salt |]
    concatMany [| le16 0x0001us; le16 (uint16 data.Length); le32 0u; data |]


///
/// Build SMB2_ENCRYPTION_CAPABILITIES context (type 2).
/// Offer AES-128-GCM then AES-128-CCM (common Windows 10+ order), not CCM-only.
/// 
let private buildEncryptionContext () : byte array =
    let data =
        concatMany
            [| le16 2us           // CipherCount
               le16 0x0002us      // AES-128-GCM
               le16 0x0001us |]   // AES-128-CCM
    concatMany [| le16 0x0002us; le16 (uint16 data.Length); le32 0u; data |]


///
/// Pad to 8-byte alignment with zeros.
let private pad8 (offset : int) : byte array =
    match offset % 8 with
    | 0 -> [||]
    | r -> Array.zeroCreate<byte> (8 - r)


///
/// SMB2 client capability bits ([MS-SMB2] §2.2.3).
let private windowsClientCapabilities : uint32 =
    0x00000001u   // DFS
    ||| 0x00000002u   // LEASING
    ||| 0x00000004u   // LARGE_MTU
    ||| 0x00000008u   // MULTI_CHANNEL
    ||| 0x00000010u   // PERSISTENT_HANDLES
    ||| 0x00000020u   // DIRECTORY_LEASING
    ||| 0x00000040u   // ENCRYPTION


///
/// Build negotiate context block for SMB 3.1.1 (preauth + encryption).
let private buildNegotiateContexts () : byte array =
    let c1 = buildPreauthContext ()
    let padC = pad8 c1.Length
    let c2 = buildEncryptionContext ()
    Array.concat [| c1; padC; c2 |]


///
/// Build an SMB2 NEGOTIATE body for a preferred dialect.
/// Still offers a single dialect when the caller pins one (needed for dialect matrix tests),
/// but capabilities/contexts follow a Windows-like client profile.
/// 
let private buildSmbNegotiateBody (preferred : SmbDialect) : byte array =
    let clientGuid = Guid.NewGuid().ToByteArray()
    let dialectCode = smbDialectCode preferred
    let needsContexts = preferred = Smb311
    let dialects = le16 dialectCode
    let dialectsEnd = 36 + dialects.Length
    let pad =
        match needsContexts with
        | true -> pad8 dialectsEnd
        | false -> [||]
    let contextOffsetInBody = dialectsEnd + pad.Length
    let contextOffsetInPacket = 64 + contextOffsetInBody
    let contexts =
        match needsContexts with
        | true -> buildNegotiateContexts ()
        | false -> [||]
    let contextOffsetField =
        match needsContexts with
        | true -> uint32 contextOffsetInPacket
        | false -> 0u
    let contextCountField =
        match needsContexts with
        | true -> 2us
        | false -> 0us
    concatMany
        [| le16 0x0024us
           le16 1us
           le16 0x0001us                      // SIGNING_ENABLED
           le16 0x0000us
           le32 windowsClientCapabilities
           clientGuid
           le32 contextOffsetField
           le16 contextCountField
           le16 0us
           dialects
           pad
           contexts |]


///
/// Back-compat name used by older call sites.
let private buildSmb2xNegotiateBody = buildSmbNegotiateBody


///
/// Cipher fallback when encryption is advertised but no context selected a cipher.
let private cipherFallback (hasEncryption : bool) : uint16 =
    match hasEncryption with
    | true -> cipherAes128Ccm
    | false -> 0us


///
/// Align a context length up to the next 8-byte boundary.
let private alignContextLength (dataLen : int) : int =
    let raw = 8 + dataLen
    match raw % 8 with
    | 0 -> raw
    | r -> raw + (8 - r)


///
/// Read the first encryption cipher from a type-2 negotiate context, if present.
let private cipherFromEncryptionContext (response : byte array) (off : int) (dataLen : int) : uint16 option =
    let dataStart = off + 8
    match dataStart + 4 <= response.Length && dataLen >= 4 with
    | false -> None
    | true ->
        let count = int (BitConverter.ToUInt16(response, dataStart))
        match count >= 1 && dataStart + 4 <= response.Length with
        | true -> Some (BitConverter.ToUInt16(response, dataStart + 2))
        | false -> None


///
/// Walk negotiate contexts looking for ENCRYPTION_CAPABILITIES (type 2).
let private findEncryptionCipherInContexts (response : byte array) (contextCount : int) (contextOffsetPkt : int) : uint16 option =
    let rec loop i off =
        match i < contextCount && off + 8 <= response.Length with
        | false -> None
        | true ->
            let ctxType = BitConverter.ToUInt16(response, off)
            let dataLen = int (BitConverter.ToUInt16(response, off + 2))
            match ctxType with
            | 0x0002us ->
                match cipherFromEncryptionContext response off dataLen with
                | Some c -> Some c
                | None -> loop (i + 1) (off + alignContextLength dataLen)
            | _ -> loop (i + 1) (off + alignContextLength dataLen)
    loop 0 contextOffsetPkt


///
/// Parse CipherId from an SMB 3.1.1 negotiate response body.
let private parseCipherFrom311Body (response : byte array) (hasEncryption : bool) : uint16 =
    try
        let body = Array.sub response 64 (response.Length - 64)
        match body.Length < 64 with
        | true -> cipherFallback hasEncryption
        | false ->
            let contextCount = int (BitConverter.ToUInt16(body, 6))
            let contextOffsetPkt = int (BitConverter.ToUInt32(body, 60))
            match findEncryptionCipherInContexts response contextCount contextOffsetPkt with
            | Some found -> found
            | None -> cipherFallback hasEncryption
    with _ ->
        cipherFallback hasEncryption


///
/// Parse CipherId from SMB 3.1.1 negotiate response contexts (type 2 = ENCRYPTION_CAPABILITIES).
/// Falls back to AES-128-CCM when the server advertises GLOBAL_CAP_ENCRYPTION but no context.
/// 
let private parseNegotiatedCipherId (response : byte array) (dialect : uint16) (capabilities : uint32) : uint16 =
    let hasEncryption = (capabilities &&& globalCapEncryption) <> 0u
    match dialect with
    | d when d = Fauli.Constants.smbDialect311 && response.Length >= 64 + 64 ->
        parseCipherFrom311Body response hasEncryption
    | d when d = Fauli.Constants.smbDialect30 || d = Fauli.Constants.smbDialect302 ->
        cipherFallback hasEncryption
    | _ -> 0us


///
/// Preauth hash for negotiate when dialect is 3.1.1; empty otherwise.
let private preauthForNegotiate (dialect : uint16) (requestRaw : byte array) (response : byte array) : byte array =
    match dialect = Fauli.Constants.smbDialect311 with
    | true -> negotiatePreauthHash requestRaw response
    | false -> [||]


///
/// Build negotiate state after a successful status parse.
let private buildNegotiateState (client : TcpClient) (stream : NetworkStream) (requestRaw : byte array) (response : byte array) : SmbNegotiateState =
    let body = Array.sub response 64 (response.Length - 64)
    let dialect = BitConverter.ToUInt16(body, 4)
    let serverGuid = Array.sub body 8 16
    let capabilities = BitConverter.ToUInt32(body, 24)
    let securityMode = BitConverter.ToUInt16(body, 2)
    { client = client
      stream = stream
      dialect = dialect
      serverGuid = serverGuid
      capabilities = capabilities
      securityMode = securityMode
      cipherId = parseNegotiatedCipherId response dialect capabilities
      preauthHash = preauthForNegotiate dialect requestRaw response
      negotiateRequestRaw = requestRaw
      negotiateResponseRaw = response }


///
/// Parse the selected dialect from an SMB2 Negotiate response.
let private parseNegotiateResponse (client : TcpClient) (stream : NetworkStream) (requestRaw : byte array) (response : byte array) : Result<SmbNegotiateState, AuthError> =
    let header = Array.sub response 0 64
    let status = parseSmb2Status header
    match status = ntStatusSuccess with
    | false -> ProtocolHandshakeFailed |> Error
    | true -> buildNegotiateState client stream requestRaw response |> Ok


///
/// Build an SMB2 SessionSetup request body with the given security blob.
/// Structure per MS-SMB2 §2.2.5:
///   StructureSize(2) + Flags(1) + SecurityMode(1) + Capabilities(4) + Channel(4) +
///   SecurityBufferOffset(2) + SecurityBufferLength(2) + PreviousSessionId(8) = 24 bytes before Buffer
/// Then Buffer (variable), aligned to the offset specified by SecurityBufferOffset.
/// 
let private buildSessionSetupRequest (securityBlob : byte array) (sessionId : uint64) : byte array =
    let structureSize = le16 0x19us  // 25 per MS-SMB2
    let securityBufferLength = le16 (uint16 securityBlob.Length)
    let securityBufferOffset = le16 0x58us
    concatMany [|
        structureSize
        [| 0x00uy |]                    // Flags
        [| 0x01uy |]                    // SecurityMode = SIGNING_ENABLED
        le32 0x00000000u                // Capabilities = 0 (no special)
        le32 0x00000000u                // Channel (reserved)
        securityBufferOffset            // SecurityBufferOffset (2 bytes)
        securityBufferLength            // SecurityBufferLength (2 bytes)
        le64 0x0000000000000000uL       // PreviousSessionId (8 bytes, 0 for first request)
        securityBlob
    |]


///
/// Parse the session ID, status, security blob, and SessionFlags from SESSION_SETUP response.
let private parseSessionSetupResponse (response : byte array) : uint64 * uint32 * byte array option * uint16 =
    let header = Array.sub response 0 64
    let sessionId = BitConverter.ToUInt64(header, 40)
    let body = Array.sub response 64 (response.Length - 64)
    let status = parseSmb2Status header
    let sessionFlags =
        match body.Length >= 4 with
        | true -> BitConverter.ToUInt16(body, 2)
        | false -> 0us
    let securityBufferOffset = int (BitConverter.ToUInt16(body, 4))
    let securityBufferLength = int (BitConverter.ToUInt16(body, 6))
    let securityBlob =
        match securityBufferLength > 0 && securityBufferOffset + securityBufferLength <= response.Length with
        | true -> Some (Array.sub response securityBufferOffset securityBufferLength)
        | false -> None
    sessionId, status, securityBlob, sessionFlags


///
/// Map wire dialect code to Signing.Dialect.
let private toSigningDialect (dialectCode : uint16) : Dialect =
    match dialectCode with
    | d when d = Fauli.Constants.smbDialect202 -> SMB202
    | d when d = Fauli.Constants.smbDialect21 -> SMB21
    | d when d = Fauli.Constants.smbDialect30 -> SMB30
    | d when d = Fauli.Constants.smbDialect302 -> SMB302
    | d when d = Fauli.Constants.smbDialect311 -> SMB311
    | _ -> SMB21


///
/// Decide whether this session must encrypt post-setup traffic.
/// True when the server set ENCRYPT_DATA, or when an SMB3 cipher was negotiated
/// (RejectUnencryptedAccess-class servers require encrypted SMB3 sessions).
/// Note: some Windows builds advertise the cipher only via NEGOTIATE_CONTEXT and
/// leave GLOBAL_CAP_ENCRYPTION clear on the response Capabilities field.
/// 
let private sessionRequiresEncryption (dialect : uint16) (_capabilities : uint32) (cipherId : uint16) (sessionFlags : uint16) : bool =
    let flagSet = sessionFlags &&& sessionFlagEncryptData <> 0us
    let smb3 =
        dialect = Fauli.Constants.smbDialect30
        || dialect = Fauli.Constants.smbDialect302
        || dialect = Fauli.Constants.smbDialect311
    let cipherNegotiated = smb3 && cipherId <> 0us
    flagSet || cipherNegotiated


///
/// Per-call values that vary between the Kerberos and NTLM finalize paths.
/// The remaining finalize inputs (stream, dialect, capabilities, cipherId)
/// come from the SmbNegotiateState already in scope at each call site.
type private SessionFinalizeParams =
    { sessionId : uint64
      sessionKey : byte array
      preauthOpt : byte array option
      sessionFlags : uint16 }


///
/// Finalize session state: signing key + optional encryption keys.
let private finalizeSessionState (state : SmbNegotiateState) (values : SessionFinalizeParams) : Result<SmbSessionState, AuthError> =
    let dialect = toSigningDialect state.dialect
    match deriveSigningKey dialect values.sessionKey values.preauthOpt with
    | Error e -> e |> Error
    | Ok derivedKey ->
        let encryptData = sessionRequiresEncryption state.dialect state.capabilities state.cipherId values.sessionFlags
        match tryBuildEncryption dialect values.sessionKey state.cipherId values.preauthOpt encryptData with
        | Error e -> e |> Error
        | Ok encOpt ->
            { stream = state.stream
              sessionId = values.sessionId
              dialect = state.dialect
              sessionKey = values.sessionKey
              signingKey = derivedKey
              encryption = encOpt }
            |> Ok


///
/// Open a TCP connection to the SMB server on port 445.
/// Returns a connected TcpClient whose GetStream() is the sole I/O channel for the session.
/// 
let private openSmbConnection (host : Host) : Result<TcpClient, AuthError> =
    let (Host hostStr) = host
    try
        let client = new TcpClient()
        client.NoDelay <- true
        client.ReceiveTimeout <- 10000
        client.SendTimeout <- 10000
        client.Connect(hostStr, 445)
        client |> Ok
    with
    | :? SocketException -> ProtocolConnectionFailed |> Error
    | ex -> UnexpectedError $"SMB connection failed: {ex.Message}" |> Error


///
/// Perform SMB 2.x dialect negotiation for a preferred dialect.
/// Direct SMB2 NEGOTIATE on 445; SESSION_SETUP uses MessageId=1.
/// 
let private negotiateDialects (client : System.Net.Sockets.TcpClient) (preferred : SmbDialect) : Result<SmbNegotiateState, AuthError> =
    let preferredCode = smbDialectCode preferred
    let stream = client.GetStream()
    let negotiateBody = buildSmbNegotiateBody preferred
    let smb2Header = buildSmb2Header smb2Negotiate 0UL 0UL 0u 0us
    let smb2Request = concat2 smb2Header negotiateBody
    let smb2Response = sendRaw stream smb2Request
    match parseNegotiateResponse client stream smb2Request smb2Response with
    | Error e -> e |> Error
    | Ok state ->
        match state.dialect = preferredCode with
        | true -> state |> Ok
        | false -> ProtocolHandshakeFailed |> Error


///
/// Build a SPNEGO-wrapped Kerberos token for SMB session setup.
let private buildSmbKerberosToken (authParams : KerberosTicketParams) : byte array =
    let (ServiceTicket ticketBytes) = authParams.serviceTicket
    buildSpnegoToken (buildApReqFromDomain ticketBytes authParams.sessionKey authParams.clientRealm authParams.clientName)


///
/// Perform SMB2 session setup using Kerberos (SPNEGO/GSSAPI).
let private buildKerberosSessionSetupRequest (authParams : KerberosTicketParams) : byte array =
    let token = buildSmbKerberosToken authParams
    let sessionRequest = buildSessionSetupRequest token 0UL
    let smb2Header = buildSmb2Header 0x0001us 1UL 0UL 0u 1us
    concat2 smb2Header sessionRequest


///
/// Preauth hash after folding a SESSION_SETUP request (3.1.1 only).
let private preauthAfterSessionSetupRequest (state : SmbNegotiateState) (smb2Request : byte array) : byte array =
    match state.dialect = Fauli.Constants.smbDialect311 with
    | true -> preauthUpdate state.preauthHash smb2Request
    | false -> state.preauthHash


///
/// Optional preauth material for signing/encryption KDF after Kerberos SS.
let private kerberosPreauthOpt (state : SmbNegotiateState) (preauthAfterReq : byte array) : byte array option =
    match state.dialect = Fauli.Constants.smbDialect311 && preauthAfterReq.Length = 64 with
    | true -> Some preauthAfterReq
    | false -> None


///
/// Resolve effective session key from AP-REP processing outcome.
let private effectiveKeyFromEstablishment (establishment : SmbGssKeyEstablishment) (fallback : byte array) : byte array =
    match establishment with
    | SessionKeyReady k -> k
    | ContextIncomplete -> fallback
    | KerberosRejected _ -> fallback


///
/// Process optional AP-REP blob into a GSS establishment outcome.
let private establishmentFromBlob (blobOpt : byte array option) (fullKeyBytes : byte array) : SmbGssKeyEstablishment =
    match blobOpt with
    | Some blob when blob.Length > 16 -> processApRepForSmbKey blob fullKeyBytes
    | _ -> ContextIncomplete


///
/// Continue Kerberos session setup after a successful or more-processing status.
let private finalizeKerberosSession (state : SmbNegotiateState) (sessionId : uint64) (status : uint32) (blobOpt : byte array option) (sessionFlags : uint16) (fullKeyBytes : byte array) (fallbackSessionKey : byte array) (preauthAfterReq : byte array) : Result<SmbSessionState, AuthError> =
    let establishment = establishmentFromBlob blobOpt fullKeyBytes
    match establishment with
    | KerberosRejected _ ->
        ProtocolAuthenticationRejected |> Error
    | ContextIncomplete when status = ntStatusMoreProcessing && blobOpt.IsNone ->
        ProtocolAuthenticationRejected |> Error
    | ContextIncomplete
    | SessionKeyReady _ ->
        finalizeSessionState state
            { sessionId = sessionId
              sessionKey = effectiveKeyFromEstablishment establishment fallbackSessionKey
              preauthOpt = kerberosPreauthOpt state preauthAfterReq
              sessionFlags = sessionFlags }


let private smbKerberosSessionSetup (state : SmbNegotiateState) (authParams : KerberosTicketParams) (smb2Request : byte array) : Result<SmbSessionState, AuthError> =
    let (ServiceSessionKey (keyBytes, _)) = authParams.sessionKey
    let sessionKey = Array.sub keyBytes 0 16
    let preauthAfterReq = preauthAfterSessionSetupRequest state smb2Request
    let response = sendRaw state.stream smb2Request
    let sessionId, status, blobOpt, sessionFlags = parseSessionSetupResponse response
    match status with
    | s when s = ntStatusSuccess || s = ntStatusMoreProcessing ->
        finalizeKerberosSession state sessionId s blobOpt sessionFlags keyBytes sessionKey preauthAfterReq
    | _ ->
        ProtocolAuthenticationRejected |> Error


///
/// Windows-like NTLMSSP Type1 flags.
/// UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY |
/// TARGET_INFO | VERSION | 128 | 56 | KEY_EXCH | SIGN | SEAL
/// 
let private smbNtlmType1Flags : uint32 =
    NtlmFlags.NegotiateUnicode
    ||| NtlmFlags.RequestTarget
    ||| NtlmFlags.NegotiateSign
    ||| NtlmFlags.NegotiateSeal
    ||| NtlmFlags.NegotiateNtlm
    ||| NtlmFlags.NegotiateAlwaysSign
    ||| NtlmFlags.NegotiateExtendedSessionSecurity
    ||| NtlmFlags.NegotiateTargetInfo
    ||| NtlmFlags.NegotiateVersion
    ||| NtlmFlags.Negotiate128
    ||| NtlmFlags.Negotiate56
    ||| NtlmFlags.NegotiateKeyExch


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
/// Overwrite the flags DWORD at offset 12 of a Type1 message.
let private overwriteNtlmFlags (buf : byte array) (flags : uint32) : byte array =
    match buf.Length >= 16 with
    | false -> buf
    | true ->
        buf.[12] <- byte (flags &&& 0xFFu)
        buf.[13] <- byte (flags >>> 8 &&& 0xFFu)
        buf.[14] <- byte (flags >>> 16 &&& 0xFFu)
        buf.[15] <- byte (flags >>> 24 &&& 0xFFu)
        buf


let private buildSmbNtlmType1 (domain : string) (workstation : string) : byte array =
    let msg = encodeNegotiateMessage (Some domain) (Some workstation) |> Array.copy
    overwriteNtlmFlags msg smbNtlmType1Flags


///
/// True when bytes start with the NTLMSSP signature and are long enough for Type2.
let private looksLikeNtlmType2 (t : byte array) : bool =
    t.Length >= 32
    && t.[0..6] = [| 0x4Euy; 0x54uy; 0x4Cuy; 0x4Duy; 0x53uy; 0x53uy; 0x50uy |]


///
/// Scan buffer for NTLMSSP signature and return the tail from that offset.
let private findNtlmPayload (blob : byte array) : byte array option =
    let ntlmSig = Fauli.Constants.ntlmsspSignature
    let rec loop i =
        match i + 8 > blob.Length with
        | true -> None
        | false when Array.sub blob i 8 = ntlmSig ->
            Some (Array.sub blob i (blob.Length - i))
        | false -> loop (i + 1)
    loop 0


///
/// Extract NTLMSSP Type2 bytes from a SPNEGO security blob (or raw NTLM).
let private extractNtlmType2FromBlob (blob1 : byte array) : byte array =
    let _, mechOpt = parseSnegoNegTokenResp blob1
    match mechOpt with
    | Some t when looksLikeNtlmType2 t -> t
    | _ -> defaultArg (findNtlmPayload blob1) [||]


///
/// Truncate exported session key to 16 bytes when longer.
let private truncateSessionKey (k : byte array) : byte array =
    match k.Length >= 16 with
    | true -> Array.sub k 0 16
    | false -> k


///
/// Prefer the second session id when the server assigned a non-zero value.
let private preferSessionId (sessionId3 : uint64) (sessionId1 : uint64) : uint64 =
    match sessionId3 <> 0UL with
    | true -> sessionId3
    | false -> sessionId1


///
/// SMB 3.1.1 NTLM preauth: nego + Type1 req + Type1 resp + Type3 req.
let private ntlmPreauthOpt (state : SmbNegotiateState) (req1 : byte array) (resp1 : byte array) (req3 : byte array) : byte array option =
    match state.dialect = Fauli.Constants.smbDialect311 with
    | true ->
        state.preauthHash
        |> foldPreauth req1
        |> foldPreauth resp1
        |> foldPreauth req3
        |> Some
    | false -> None


///
/// After Type2 challenge is parsed, complete Type3 SESSION_SETUP and finalize.
let private completeNtlmSessionAfterChallenge (state : SmbNegotiateState) (user : string) (domain : string) (password : string) (workstation : string) (type1 : byte array) (type2Bytes : byte array) (sessionId1 : uint64) (req1 : byte array) (resp1 : byte array) (challenge : ChallengeMessage) : Result<SmbSessionState, AuthError> =
    let ntlmV2 = computeNtlmV2Response password user domain challenge
    let type3 =
        buildAuthenticateMessage
            challenge.negotiateFlags ntlmV2 type1 type2Bytes domain user workstation
    let token3 = wrapNtlmNegTokenResp type3
    let req3 =
        concat2
            (buildSmb2Header 0x0001us 2UL sessionId1 0u 1us)
            (buildSessionSetupRequest token3 0UL)
    let resp3 = sendRaw state.stream req3
    let sessionId3, status3, _, sessionFlags = parseSessionSetupResponse resp3
    match status3 = ntStatusSuccess || status3 = ntStatusMoreProcessing with
    | false -> ProtocolAuthenticationRejected |> Error
    | true ->
        finalizeSessionState state
            { sessionId = preferSessionId sessionId3 sessionId1
              sessionKey = truncateSessionKey ntlmV2.exportedSessionKey
              preauthOpt = ntlmPreauthOpt state req1 resp1 req3
              sessionFlags = sessionFlags }


///
/// Continue NTLM after Type2 bytes are extracted.
let private continueNtlmAfterType2 (state : SmbNegotiateState) (user : string) (domain : string) (password : string) (workstation : string) (type1 : byte array) (sessionId1 : uint64) (req1 : byte array) (resp1 : byte array) (type2Bytes : byte array) : Result<SmbSessionState, AuthError> =
    match type2Bytes.Length < 32 with
    | true -> ProtocolAuthenticationRejected |> Error
    | false ->
        match parseChallenge type2Bytes with
        | Error e -> e |> Error
        | Ok challenge ->
            completeNtlmSessionAfterChallenge state user domain password workstation type1 type2Bytes sessionId1 req1 resp1 challenge


///
/// Full NetNTLMv2 over SMB2: Type1 SESSION_SETUP → Type2 challenge → Type3 SESSION_SETUP.
/// MessageIds 1 and 2; caller NextMessageId = 3.
/// 
let private smbNtlmSessionSetup (state : SmbNegotiateState) (authParams : NtlmResponseParams) : Result<SmbSessionState, AuthError> =
    let (UserName user) = authParams.userName
    let (DomainName domain) = authParams.domain
    let (Password password) = authParams.password
    let workstation = ntlmWorkstationName ()
    let type1 = buildSmbNtlmType1 domain workstation
    let token1 = wrapNtlmSpnego type1
    let req1 = concat2 (buildSmb2Header 0x0001us 1UL 0UL 0u 1us) (buildSessionSetupRequest token1 0UL)
    let resp1 = sendRaw state.stream req1
    let sessionId1, status1, blob1Opt, _ = parseSessionSetupResponse resp1
    match status1 = ntStatusMoreProcessing, blob1Opt with
    | false, _ | true, None -> ProtocolAuthenticationRejected |> Error
    | true, Some blob1 ->
        extractNtlmType2FromBlob blob1
        |> continueNtlmAfterType2 state user domain password workstation type1 sessionId1 req1 resp1


///
/// Dispatch on ProtocolHandlerParams and perform the appropriate SMB session setup.
let private smbSessionSetup (state : SmbNegotiateState) (authParams : ProtocolHandlerParams) : Result<SmbSessionState, AuthError> =
    match authParams with
    | KerberosTicket krb ->
        smbKerberosSessionSetup state krb (buildKerberosSessionSetupRequest krb)
    | NtlmResponse ntlm -> smbNtlmSessionSetup state ntlm
    | _ -> NoSuitableAuthMethod |> Error


///
/// Derive the authentication method from ProtocolHandlerParams.
let private authMethodFromParams (authParams : ProtocolHandlerParams) : AuthenticationMethod =
    match authParams with
    | KerberosTicket _ -> Kerberos
    | NtlmResponse _ -> NetNTLMv2
    | _ -> Anonymous


///
/// Wrap the authenticated SMB session into an AuthenticatedResponse.
/// At this point no tree has been connected; the caller will perform
/// TREE_CONNECT and all further operations using the SessionId.
/// 
let private wrapSmbResponse (session : SmbSession) (authParams : ProtocolHandlerParams) : AuthenticatedResponse =
    let sid = SessionId (string session.SessionId)
    { connection = AuthSmb session
      authenticationMethod = authMethodFromParams authParams
      sessionInfo =
        { authenticatedAs = None
          expiresAt = None
          sessionId = Some sid
          domain = None } }


///
/// Pre-build Kerberos SESSION_SETUP so NEGOTIATE → SESSION_SETUP is immediate on the wire.
let private prebuiltKerberosSessionSetup (authParams : ProtocolHandlerParams) : (KerberosTicketParams * byte array) option =
    match authParams with
    | KerberosTicket krb -> Some (krb, buildKerberosSessionSetupRequest krb)
    | _ -> None


///
/// MessageId the caller should use after session setup (NTLM consumed 1+2).
let private nextMessageIdAfterSetup (authParams : ProtocolHandlerParams) : uint64 =
    match authParams with
    | NtlmResponse _ -> 3UL
    | _ -> 2UL


///
/// Build the public SmbSession handle from negotiate + session state.
let private buildSmbSession (negotiateState : SmbNegotiateState) (sessionState : SmbSessionState) (authParams : ProtocolHandlerParams) : SmbSession =
    { Stream = sessionState.stream
      SessionId = sessionState.sessionId
      Dialect = negotiateState.dialect
      SessionKey = sessionState.sessionKey
      SigningKey = sessionState.signingKey
      Encryption = sessionState.encryption
      NextMessageId = nextMessageIdAfterSetup authParams }


///
/// Run session setup using a prebuilt Kerberos request when available.
let private runSessionSetup (negotiateState : SmbNegotiateState) (authParams : ProtocolHandlerParams) (prebuilt : (KerberosTicketParams * byte array) option) : Result<SmbSessionState, AuthError> =
    match prebuilt with
    | Some (krb, req) -> smbKerberosSessionSetup negotiateState krb req
    | None -> smbSessionSetup negotiateState authParams


///
/// Dispose the client and surface a negotiate failure.
let private failNegotiate (client : TcpClient) (err : AuthError) : Result<AuthenticatedResponse, AuthError> =
    client.Dispose()
    err |> Error


///
/// Dispose negotiate client and surface a session-setup failure.
let private failSessionSetup (negotiateState : SmbNegotiateState) (err : AuthError) : Result<AuthenticatedResponse, AuthError> =
    negotiateState.client.Dispose()
    err |> Error


///
/// Continue after successful dialect negotiate.
let private continueAfterNegotiate (authParams : ProtocolHandlerParams) (prebuilt : (KerberosTicketParams * byte array) option) (negotiateState : SmbNegotiateState) : Result<AuthenticatedResponse, AuthError> =
    match runSessionSetup negotiateState authParams prebuilt with
    | Error e -> failSessionSetup negotiateState e
    | Ok sessionState ->
        wrapSmbResponse (buildSmbSession negotiateState sessionState authParams) authParams
        |> Ok


///
/// Continue after a live TCP client is open.
let private continueAfterOpen (preferred : SmbDialect) (authParams : ProtocolHandlerParams) (prebuilt : (KerberosTicketParams * byte array) option) (clientResult : Result<System.Net.Sockets.TcpClient, AuthError>) : Result<AuthenticatedResponse, AuthError> =
    match clientResult with
    | Error e -> e |> Error
    | Ok client ->
        match negotiateDialects client preferred with
        | Error e -> failNegotiate client e
        | Ok negotiateState -> continueAfterNegotiate authParams prebuilt negotiateState


///
/// Establish an authenticated SMB session on a preferred SMB 2.x dialect.
/// Negotiates that dialect only, then performs session setup.
/// Returns AuthSmb (SmbSession). No tree connect — Fauli hands off here.
/// When the server requires encryption (RejectUnencryptedAccess / SessionFlags.ENCRYPT_DATA),
/// SmbSession.Encryption is populated and callers must use sendSmb2 for further traffic.
/// 
let internal handleSmbWithDialect (host : Host) (authParams : ProtocolHandlerParams) (preferred : SmbDialect) : Result<AuthenticatedResponse, AuthError> =
    let prebuilt = prebuiltKerberosSessionSetup authParams
    openSmbConnection host
    |> continueAfterOpen preferred authParams prebuilt


///
/// Establish an authenticated SMB session.
/// Defaults to SMB 3.1.1 so encryption-capable dialects are preferred when the
/// server has RejectUnencryptedAccess (or otherwise requires SMB3 encryption).
/// 
let internal handleSmb (host : Host) (authParams : ProtocolHandlerParams) : Result<AuthenticatedResponse, AuthError> =
    handleSmbWithDialect host authParams Smb311


///
/// Sign the inner SMB2 message when signing material is available.
let private prepareSignedMessage (session : SmbSession) (smb2Message : byte array) : byte array =
    let dialect = toSigningDialect session.Dialect
    match session.SigningKey, session.Dialect with
    | _, d when d = Fauli.Constants.smbDialect202 || d = Fauli.Constants.smbDialect21 ->
        signMessage dialect session.SessionKey None smb2Message
    | Some _, _ ->
        signMessage dialect session.SessionKey session.SigningKey smb2Message
    | None, _ ->
        smb2Message


///
/// Optionally wrap a prepared message in SMB3 TRANSFORM_HEADER encryption.
let private maybeEncryptWirePayload (session : SmbSession) (prepared : byte array) : byte array =
    match session.Encryption with
    | Some enc -> encryptSmbMessage enc session.SessionId prepared
    | None -> prepared


///
/// Decrypt a response when the server replied with a transform packet.
let private maybeDecryptResponse (session : SmbSession) (raw : byte array) : Result<byte array, AuthError> =
    match session.Encryption with
    | Some enc when isTransformPacket raw ->
        decryptSmbMessage enc raw
    | _ when isTransformPacket raw ->
        UnexpectedError "Received encrypted SMB transform without session encryption keys" |> Error
    | _ ->
        raw |> Ok


///
/// Map SMB send/recv transport failures onto domain errors.
let private mapSmbIoException (ex : exn) : AuthError =
    match ex with
    | :? SocketException -> ProtocolConnectionFailed
    | _ -> UnexpectedError $"SMB send/recv failed: {ex.Message}"


///
/// Sign (when keys present) and optionally TRANSFORM-encrypt an SMB2 message,
/// send it, read one response, and decrypt if the server replied with a transform.
/// Use this for all traffic after SESSION_SETUP when Encryption may be Some.
/// 
let internal sendSmb2 (session : SmbSession) (smb2Message : byte array) : Result<byte array, AuthError> =
    try
        let wirePayload =
            smb2Message
            |> prepareSignedMessage session
            |> maybeEncryptWirePayload session
        let wrapped = wrapNetbiosMessage wirePayload
        session.Stream.Write(wrapped, 0, wrapped.Length)
        session.Stream.Flush()
        readNetbiosMessage session.Stream
        |> maybeDecryptResponse session
    with ex ->
        mapSmbIoException ex |> Error
