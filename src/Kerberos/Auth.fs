module internal Fauli.Kerberos.Auth


open System
open System.Net.Sockets
open System.Text

open Fauli.Domain
open Fauli.Kerberos.Encoding
open Fauli.Kerberos.Encryption
open Fauli.Kerberos.Parsing


///
/// KDC_ERR_PREAUTH_REQUIRED (25) — client must provide pre-authentication.
let private krbPreauthRequired = 0x19


///
/// PA-ENC-TIMESTAMP padata type (2) — encrypted timestamp pre-auth.
let private paEncTimestamp = 2


///
/// PA-ETYPE-INFO padata type (11) — etype/salt pairs from KDC.
let private paEtypeInfo = 11


///
/// PA-ETYPE-INFO2 padata type (19) — extended etype/salt pairs from KDC.
let private paEtypeInfo2 = 19


///
/// PA-SUPPORTED-ETYPES padata type (165) — raw etype integers from KDC.
let private paSupportedEtypes = 165


///
/// PrincipalName name-type: service instance (e.g. "cifs/server.domain.com").
let private nameSrvInst = Fauli.Constants.Kerberos.NameSrvInst


///
/// Read all remaining bytes from a socket until it closes.
/// Uses ResizeArray (backed by List<byte>) because we're appending in a hot I/O loop —
/// pre-allocating a fixed-size array isn't possible when the remote end controls framing.
/// 
let private readUntilClose (client : Socket) : byte array =
    let buffer = ResizeArray<byte>()
    let chunk = Array.zeroCreate<byte> 4096
    let rec loop () =
        let received = client.Receive(chunk, 0, chunk.Length, SocketFlags.None)
        match received > 0 with
        | true ->
            Array.iter buffer.Add (Array.sub chunk 0 received)
            loop ()
        | false -> ()
    loop ()
    buffer.ToArray()


///
/// Read exactly `count` bytes into `buf`. Unit return type to indicate side-effectfulness
let private readExactly (client : Socket) (buf : byte array) (count : int) =
    let rec loop off remaining =
        match remaining = 0 with
        | true -> buf
        | false ->
            let r = client.Receive(buf, off, remaining, SocketFlags.None)
            match r = 0 with
            | true -> buf  // partial read — caller decides
            | false -> loop (off + r) (remaining - r)
    loop 0 count |> ignore


let internal sendKdcRequest (kdcHost : string) (port : int) (request : byte array) : byte array =
    use client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
    client.ReceiveTimeout <- 10000
    client.SendTimeout <- 10000
    client.Connect(kdcHost, port)
    client.Send(BitConverter.GetBytes(uint32 request.Length) |> Array.rev) |> ignore
    client.Send(request : byte array) |> ignore
    let lenBuf = Array.zeroCreate<byte> 4
    readExactly client lenBuf 4  // read the 4-byte length prefix; result discarded as we only need lenBuf mutated
    let respLen = int (BitConverter.ToInt32(lenBuf |> Array.rev, 0))
    match respLen > 1048576 with
    | true ->
        let buffer = ResizeArray<byte>(lenBuf.Length + 4096)
        Array.iter buffer.Add lenBuf
        let remaining = readUntilClose client
        Array.iter buffer.Add remaining
        buffer.ToArray()
    | false ->
        let buffer = Array.zeroCreate<byte> respLen
        readExactly client buffer respLen  // reads into pre-allocated buffer; result discarded
        buffer


///
/// Extract salt string from an etype entry's context field [1].
let private extractSaltString (v : BerValue) : string option =
    match v with
    | BerOctetString b -> Encoding.ASCII.GetString b |> Some
    | BerGeneralString s -> s |> Some
    | _ -> None


///
/// Extract raw octet bytes from a BerValue.
let private extractOctetBytesFromValue (v : BerValue) : byte array option =
    match v with
    | BerOctetString bytes -> bytes |> Some
    | _ -> None


let internal extractEtypeFromEntry (entry : BerValue) : (int * string option) option =
    match entry with
    | BerSequence fields ->
        let etype =
            match contextAt fields 0 with
            | Some v -> defaultArg (asInteger v) -1
            | None -> -1
        let salt =
            match contextAt fields 1 with
            | None -> None
            | Some v -> extractSaltString v
        match etype <> -1 with
        | true -> Some (etype, salt)
        | false -> None
    | _ -> None


///
/// Extract etype entries from a PA-ETYPE-INFO or PA-ETYPE-INFO2 padata value.
let internal extractEtypesFromOctetField (fields : BerValue list) : (int * string option) list =
    let extractOctetBytes (fields : BerValue list) : byte array option =
        match contextAt fields 2 with
        | None -> None
        | Some v -> extractOctetBytesFromValue v
    let parseAsSequence (bytes : byte array) : BerValue list option =
        asSequence (parseBer bytes)
    let chooseEtypes (entries : BerValue list) : (int * string option) list =
        entries |> List.choose extractEtypeFromEntry
    match extractOctetBytes fields |> Option.bind parseAsSequence with
    | None -> []
    | Some entries -> chooseEtypes entries


///
/// Extract raw etype integers from a PA-SUPPORTED-ETYPES padata value.
let internal extractEtypesFromRawField (fields : BerValue list) : (int * string option) list =
    let parseRawEtypes (bytes : byte array) : (int * string option) list =
        let rec loop i acc =
            match i + 4 > bytes.Length with
            | true -> acc
            | false ->
                let et = BitConverter.ToInt32(bytes, i)
                loop (i + 4) ((et, None) :: acc)
        loop 0 []
    match contextAt fields 2 |> Option.bind extractOctetBytesFromValue with
    | None -> []
    | Some bytes -> parseRawEtypes bytes


let internal extractEtypesFromPaData (paData : BerValue) : (int * string option) list =
    match paData with
    | BerSequence fields ->
        let paType =
            match contextAt fields 1 with
            | Some v -> defaultArg (asInteger v) -1
            | None -> -1
        match paType with
        | n when n = paEtypeInfo || n = paEtypeInfo2 ->
            extractEtypesFromOctetField fields
        | n when n = paSupportedEtypes ->
            extractEtypesFromRawField fields
        | _ -> []
    | _ -> []


let extractSupportedEtypes (errorData : byte array) : (int * string option) list =
    errorData
    |> extractPaDataFromError
    |> List.collect extractEtypesFromPaData
    |> List.rev


///
/// Build the initial (pre-auth discovery) AS-REQ with the given parameters.
let private buildInitialAsReqWithParams (username : string) (realm : string) (now : DateTime) (nonce : int) : byte array =
    let pacRequest = encodePaPacRequest true
    let paPac = encodePaData Fauli.Constants.Kerberos.PaPacRequest pacRequest
    let kdcOptions = encodeKdcOptions ["forwardable"; "renewable"; "proxiable"]
    let cname = encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| username |] |> Some
    let realmBytes = encodeRealm realm
    let sname = encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| "krbtgt"; realm |] |> Some
    let till = now.AddHours 24.0 |> Some
    let rtime = now.AddHours 24.0 |> Some
    let etype = [| 18; 17; 23 |]
    let reqBody =
        encodeKdcReqBody
            { kdcOptions = kdcOptions
              cname = cname
              realm = realmBytes
              sname = sname
              till = till
              rtime = rtime
              nonce = nonce
              etype = etype
              additionalTickets = None }
    let kdcReq = encodeKdcReq 10 (Some [| paPac |]) reqBody
    encodeAsReq kdcReq


///
/// Build the initial (pre-auth discovery) AS-REQ.
/// The nonce is random; for deterministic testing use buildInitialAsReqForProver.
/// 
let internal buildInitialAsReq (username : string) (realm : string) : byte array =
    let now = DateTime.UtcNow
    let nonce = Random.Shared.Next(1, 2147483647)
    buildInitialAsReqWithParams username realm now nonce


///
/// Internal overload accepting a fixed nonce for deterministic testing.
/// Only exposed via InternalsVisibleTo for use by the prover test suite.
/// 
let internal buildInitialAsReqForProver (username : string) (realm : string) (nonce : int) : byte array =
    let now = DateTime.UtcNow
    buildInitialAsReqWithParams username realm now nonce


let internal buildAsReqWithPreAuth (username : string) (realm : string) (key : Key) (now : DateTime) : byte array =
    let nonce = Random.Shared.Next(1, 2147483647)
    let pacRequest = encodePaPacRequest true
    let paPac = encodePaData Fauli.Constants.Kerberos.PaPacRequest pacRequest
    let usec = int ((now.Ticks % 10000000L) / 10L)
    let timestampBytes = encodePaEncTsEnc now (usec |> Some)
    let encryptedTimestamp = encrypt key KeyUsage.AsReqPaEncTs timestampBytes None
    let encData = encodeEncryptedData (int key.enctype) None encryptedTimestamp
    let paEncTs = encodePaData paEncTimestamp encData
    let kdcOptions = encodeKdcOptions ["forwardable"; "renewable"; "proxiable"]
    let cname = encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| username |] |> Some
    let realmBytes = encodeRealm realm
    let sname = encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| "krbtgt"; realm |] |> Some
    let till = now.AddHours 24.0 |> Some
    let rtime = now.AddHours 24.0 |> Some
    let etype = [| int key.enctype |]
    let reqBody =
        encodeKdcReqBody
            { kdcOptions = kdcOptions
              cname = cname
              realm = realmBytes
              sname = sname
              till = till
              rtime = rtime
              nonce = nonce
              etype = etype
              additionalTickets = None }
    let kdcReq = encodeKdcReq 10 (Some [| paPac; paEncTs |]) reqBody
    encodeAsReq kdcReq


///
/// Internal overload accepting a fixed nonce for deterministic testing.
/// Only exposed via InternalsVisibleTo for use by the prover test suite.
/// 
let internal buildPreauthAsReqForProver (username : string) (realm : string) (key : Key) (now : DateTime) (nonce : int) : byte array =
    let pacRequest = encodePaPacRequest true
    let paPac = encodePaData Fauli.Constants.Kerberos.PaPacRequest pacRequest
    let usec = int ((now.Ticks % 10000000L) / 10L)
    let timestampBytes = encodePaEncTsEnc now (usec |> Some)
    let encryptedTimestamp = encrypt key KeyUsage.AsReqPaEncTs timestampBytes None
    let encData = encodeEncryptedData (int key.enctype) None encryptedTimestamp
    let paEncTs = encodePaData paEncTimestamp encData
    let kdcOptions = encodeKdcOptions ["forwardable"; "renewable"; "proxiable"]
    let cname = encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| username |] |> Some
    let realmBytes = encodeRealm realm
    let sname = encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| "krbtgt"; realm |] |> Some
    let till = now.AddHours 24.0 |> Some
    let rtime = now.AddHours 24.0 |> Some
    let etype = [| int key.enctype |]
    let reqBody =
        encodeKdcReqBody
            { kdcOptions = kdcOptions
              cname = cname
              realm = realmBytes
              sname = sname
              till = till
              rtime = rtime
              nonce = nonce
              etype = etype
              additionalTickets = None }
    let kdcReq = encodeKdcReq 10 (Some [| paPac; paEncTs |]) reqBody
    encodeAsReq kdcReq


type internal TgtResult = 
    { ticketBytes : byte array
      sessionKey : Key
      sessionKeyType : int
      cname : BerValue option
      crealm : string option
      serverTime : DateTime option }


///
/// Private accumulating state for the AS exchange (TGT acquisition).
/// Threaded through named pure steps to avoid deep nesting.
/// 
type private AsExchange =
    { kdcHost : string
      username : string
      password : string
      realm : string
      requestedEtype : EncryptionType option
      initialResponse : byte array
      preAuthNow : DateTime
      supportedEtypes : (int * string option) list
      preAuthResponse : byte array }


///
/// Match a preferred etype from the KDC's supported list.
let private matchPreferredEtype (targetEtype : int) (targetEnum : EncryptionType) (supported : (int * string option) list) : (EncryptionType * string option) option =
    let matchingSalt (et, salt) =
        match et = targetEtype with
        | true -> Some (targetEnum, salt)
        | false -> None
    supported
    |> List.tryPick matchingSalt


let private pickPreferredEtype (supported : (int * string option) list) : EncryptionType * string option =
    let preferences =
        [ 18, EncryptionType.AES256_CTS_HMAC_SHA1_96
          17, EncryptionType.AES128_CTS_HMAC_SHA1_96
          23, EncryptionType.ARCFOUR_HMAC_MD5 ]
    let tryPreference (targetEtype, targetEnum) =
        matchPreferredEtype targetEtype targetEnum supported
    preferences
    |> List.tryPick tryPreference
    |> Option.defaultValue (EncryptionType.AES256_CTS_HMAC_SHA1_96, None)


///
/// Derive the salt string from optional salt or realm/username fallback.
let private deriveSaltStr (salt : string option) (realm : string) (username : string) : string =
    match salt with
    | Some s -> s
    | None -> $"{realm.ToUpperInvariant()}\\{username}"


///
/// Check the initial AS-REP and return the appropriate error or the supported etypes.
let private checkInitialAsRep (response : byte array) : Result<(int * string option) list, AuthError> =
    match isKrbError response with
    | false -> KerberosTGTAcquisitionFailed |> Error
    | true ->
        let errorCode, _ = decodeKrbError response
        match errorCode with
        | n when n = krbPreauthRequired ->
            extractSupportedEtypes response |> Ok
        | n when n = Fauli.Constants.Kerberos.KrbPreauthFailed ->
            KerberosPreauthFailed |> Error
        | _ ->
            KerberosTGTAcquisitionFailed |> Error


///
/// Derive the pre-auth key from etype and password, then build and send the pre-auth AS-REQ.
let private sendPreAuthAsReq (kdcHost : string) (username : string) (realm : string) (etype : EncryptionType) (saltStr : string) (password : string) (response : byte array) : Result<byte array, AuthError> =
    let key = stringToKey etype password saltStr
    let preAuthNow =
        match extractStimeFromKrbError response with
        | Some st -> st.AddSeconds(1.0) |> Some  // server time +1s
        | None -> DateTime.UtcNow |> Some
    let preAuthNow = preAuthNow.Value
    let preAuthReq = buildAsReqWithPreAuth username realm key preAuthNow
    sendKdcRequest kdcHost 88 preAuthReq |> Ok


///
/// Decode a KRB-ERROR response into an AuthError.
let private decodeKrbErrorToAuthError (asRep : byte array) : AuthError =
    let errCode, _ = decodeKrbError asRep
    match errCode with
    | n when n = Fauli.Constants.Kerberos.KrbPreauthFailed -> KerberosPreauthFailed
    | _ -> KerberosTGTAcquisitionFailed


///
/// Check the pre-auth AS-REP and return the appropriate error or the decoded KDC-REP.
let private checkPreAuthAsRep (asRep : byte array) : Result<BerValue, AuthError> =
    match isKrbError asRep with
    | true -> decodeKrbErrorToAuthError asRep |> Error
    | false -> decodeKdcRep asRep |> Ok


///
/// Extract session key bytes from EncASRepPart.
let private extractSessionKeyBytes (encAsRepPart : BerValue) (encEtype : int) : Key option =
    let extractKeyBytesFromKf (kf : BerValue list) : byte array option =
        match contextAt kf 1 with
        | Some v -> asOctetString v
        | None -> None
    let extractKeyTypeFromKf (kf : BerValue list) : int option =
        match contextAt kf 0 with
        | Some v -> asInteger v
        | None -> None
    let keyFieldsFromContext0 (fields : BerValue list) : BerValue list option =
        match contextAt fields 0 with
        | Some (BerSequence kf) -> Some kf
        | _ -> None
    let extractKeyBytes (fields : BerValue list) : byte array option =
        match keyFieldsFromContext0 fields with
        | None -> None
        | Some kf -> extractKeyBytesFromKf kf
    let extractKeyType (fields : BerValue list) : int =
        match keyFieldsFromContext0 fields with
        | None -> encEtype
        | Some kf -> defaultArg (extractKeyTypeFromKf kf) encEtype
    match encAsRepPart with
    | BerSequence fields ->
        let sessionKeyBytes = extractKeyBytes fields
        let sessionKeyType = extractKeyType fields
        match sessionKeyBytes with
        | Some skBytes ->
            { enctype = enum<EncryptionType> sessionKeyType
              contents = skBytes } |> Some
        | None -> None
    | _ -> None


///
/// Decrypt the AS-REP enc-part and extract the TGT session key.
let private extractTgtSessionKey (rep : BerValue) (etype : EncryptionType) (key : Key) (saltStr : string) (password : string) : Result<TgtResult, AuthError> =
    match extractEncPartCipher rep, extractEncPartEtype rep with
    | None, _ | _, None -> KerberosTGTAcquisitionFailed |> Error
    | Some encCipher, Some encEtype ->
        let decryptKey =
            match encEtype = int etype with
            | true -> key
            | false -> stringToKey (enum<EncryptionType> encEtype) password saltStr
        let encAsRepPart = parseBer (decrypt decryptKey KeyUsage.AsRepEncPart encCipher)
        match extractSessionKeyBytes encAsRepPart encEtype, extractTicketBytes rep with
        | None, _ | _, None -> KerberosTGTAcquisitionFailed |> Error
        | Some sessionKey, Some ticketBytes ->
            { ticketBytes = ticketBytes
              sessionKey = sessionKey
              sessionKeyType = int sessionKey.enctype
              cname = extractCname rep
              crealm = extractCrealm rep
              serverTime = None } |> Ok


///
/// Derive the key and salt for a given etype, then send the pre-auth AS-REQ.
let private sendPreAuthAsReqWithEtype (kdcHost : string) (username : string) (realm : string) (etype : EncryptionType) (salt : string option) (password : string) (response : byte array) : Result<byte array, AuthError> =
    let saltStr = deriveSaltStr salt realm username
    sendPreAuthAsReq kdcHost username realm etype saltStr password response


///
/// From supported etypes, pick the preferred etype and send the pre-auth AS-REQ.
let private buildAndSendPreAuthAsReq (kdcHost : string) (username : string) (realm : string) (password : string) (response : byte array) (supportedEtypes : (int * string option) list) : Result<byte array, AuthError> =
    let etype, salt = pickPreferredEtype supportedEtypes
    let saltStr = deriveSaltStr salt realm username
    sendPreAuthAsReq kdcHost username realm etype saltStr password response


///
/// Decrypt the AS-REP enc-part and extract the TGT session key, using auto-selected etype.
let private extractTgtSessionKeyFromRep (response : byte array) (password : string) (realm : string) (username : string) (rep : BerValue) : Result<TgtResult, AuthError> =
    let etype, salt = extractSupportedEtypes response |> pickPreferredEtype 
    let saltStr = deriveSaltStr salt realm username
    let key = stringToKey etype password saltStr
    extractTgtSessionKey rep etype key saltStr password


///
/// Set server time on the TGT result.
let private setServerTime (preAuthNow : DateTime) (tgt : TgtResult) : TgtResult =
    { tgt with serverTime = preAuthNow |> Some }


///
/// Salt advertised by the KDC for a requested encryption type, if any.
let private saltForRequestedEtype (requestedEtype : EncryptionType) (supportedEtypes : (int * string option) list) : string option =
    let matchingSalt (et, salt) =
        match et = int requestedEtype with
        | true -> Some salt
        | false -> None
    supportedEtypes
    |> List.tryPick matchingSalt
    |> Option.flatten


///
/// Verify etype support and send pre-auth AS-REQ with explicit etype.
let private buildAndSendPreAuthAsReqWithEtype (kdcHost : string) (username : string) (realm : string) (requestedEtype : EncryptionType) (password : string) (response : byte array) (supportedEtypes : (int * string option) list) : Result<byte array, AuthError> =
    let etypeSupported = List.exists (fun (et, _) -> et = int requestedEtype) supportedEtypes
    match etypeSupported with
    | false -> (UnexpectedError $"KDC does not support requested encryption type {requestedEtype}") |> Error
    | true ->
        let salt = saltForRequestedEtype requestedEtype supportedEtypes
        sendPreAuthAsReqWithEtype kdcHost username realm requestedEtype salt password response


///
/// Decrypt the AS-REP enc-part and extract the TGT session key, using explicit etype.
let private extractTgtSessionKeyFromRepWithEtype (response : byte array) (requestedEtype : EncryptionType) (password : string) (realm : string) (username : string) (rep : BerValue) : Result<TgtResult, AuthError> =
    let supportedEtypes = extractSupportedEtypes response
    let salt = saltForRequestedEtype requestedEtype supportedEtypes
    let saltStr = deriveSaltStr salt realm username
    let key = stringToKey requestedEtype password saltStr
    extractTgtSessionKey rep requestedEtype key saltStr password


///
/// Initialize the accumulating exchange state.
let private initializeAsExchange
        (kdcHost : string)
        (username : string)
        (password : string)
        (realm : string)
        (requestedEtype : EncryptionType option) : AsExchange =
    { kdcHost = kdcHost
      username = username
      password = password
      realm = realm
      requestedEtype = requestedEtype
      initialResponse = [||]
      preAuthNow = DateTime.UtcNow
      supportedEtypes = []
      preAuthResponse = [||] }


///
/// Step 1: Send initial AS-REQ and collect supported etypes + server time hint.
let private sendInitialRequest (state : AsExchange) : Result<AsExchange, AuthError> =
    let initialReq = buildInitialAsReq state.username state.realm
    let response = sendKdcRequest state.kdcHost 88 initialReq
    let preAuthNow =
        match extractStimeFromKrbError response with
        | Some st -> st.AddSeconds 1.0 
        | None -> DateTime.UtcNow
    match checkInitialAsRep response with
    | Error e -> e |> Error
    | Ok supported ->
        { state with
           initialResponse = response
           preAuthNow = preAuthNow
           supportedEtypes = supported } |> Ok


///
/// Step 2: Send the pre-authenticated AS-REQ (auto or explicit etype).
let private sendPreAuthRequest (state : AsExchange) : Result<AsExchange, AuthError> =
    match state.requestedEtype with
    | None ->
        let preAuthResp = buildAndSendPreAuthAsReq state.kdcHost state.username state.realm state.password state.initialResponse state.supportedEtypes
        match preAuthResp with
        | Error e -> e |> Error
        | Ok resp -> { state with preAuthResponse = resp } |> Ok
    | Some etype ->
        let preAuthResp =
            buildAndSendPreAuthAsReqWithEtype
                state.kdcHost
                state.username
                state.realm
                etype
                state.password
                state.initialResponse
                state.supportedEtypes
        match preAuthResp with
        | Error e -> e |> Error
        | Ok resp -> { state with preAuthResponse = resp } |> Ok


///
/// Step 3: Validate the pre-auth response and extract the TGT.
let private extractTgtFromState (state : AsExchange) : Result<TgtResult, AuthError> =
    match checkPreAuthAsRep state.preAuthResponse with
    | Error e -> e |> Error
    | Ok berRep ->
        match state.requestedEtype with
        | None ->
            extractTgtSessionKeyFromRep
                state.initialResponse
                state.password
                state.realm
                state.username
                berRep
        | Some etype ->
            extractTgtSessionKeyFromRepWithEtype
                state.initialResponse
                etype
                state.password
                state.realm
                state.username
                berRep


///
/// Stamp server-aligned time onto a successful TGT result.
let private applyServerTime (preAuthNow : DateTime) (tgtResult : Result<TgtResult, AuthError>) : Result<TgtResult, AuthError> =
    match tgtResult with
    | Error e -> e |> Error
    | Ok tgt -> setServerTime preAuthNow tgt |> Ok


///
/// Runs the full AS exchange using the state record and named steps.
let private runTgtAcquisition (initial : AsExchange) : Result<TgtResult, AuthError> =
    match sendInitialRequest initial with
    | Error e -> e |> Error
    | Ok afterInitial ->
        match sendPreAuthRequest afterInitial with
        | Error e -> e |> Error
        | Ok afterPreAuth ->
            extractTgtFromState afterPreAuth
            |> applyServerTime afterPreAuth.preAuthNow


///
/// Build the TGT acquisition pipeline (auto-selects strongest supported etype).
let private acquireTgt (kdcHost : string) (username : string) (password : string) (realm : string) : Result<TgtResult, AuthError> =
    initializeAsExchange kdcHost username password realm None
    |> runTgtAcquisition


///
/// Build the TGT acquisition pipeline with an explicit encryption type.
let private acquireTgtWithEtype (kdcHost : string) (username : string) (password : string) (realm : string) (requestedEtype : EncryptionType) : Result<TgtResult, AuthError> =
    initializeAsExchange kdcHost username password realm (Some requestedEtype)
    |> runTgtAcquisition


let internal getTgt (kdcHost : string) (username : string) (password : string) (realm : string) : Result<TgtResult, AuthError> =
    try
        acquireTgt kdcHost username password realm
    with
    | :? SocketException -> KerberosRealmUnreachable |> Error
    | ex -> UnexpectedError $"TGT acquisition failed: {ex.Message}" |> Error


///
/// Acquire a TGT using a specific encryption type (e.g. AES128 or RC4).
let internal getTgtWithEtype (kdcHost : string) (username : string) (password : string) (realm : string) (etype : EncryptionType) : Result<TgtResult, AuthError> =
    try
        acquireTgtWithEtype kdcHost username password realm etype
    with
    | :? SocketException -> KerberosRealmUnreachable |> Error
    | ex -> UnexpectedError $"TGT acquisition failed: {ex.Message}" |> Error


let private encodeCnameBytes (cname : BerValue) : byte array =
    let extractNameStrings (items : BerValue list) : string array =
        let asGeneralString item =
            match item with
            | BerGeneralString s -> Some s
            | _ -> None
        items
        |> List.choose asGeneralString
        |> List.toArray
    let extractNameSequence (v : BerValue) : BerValue list option =
        match v with
        | BerSequence s -> Some s
        | _ -> None
    let nameStringsFromContext (cnameFields : BerValue list) : string array =
        match contextAt cnameFields 1 with
        | None -> [| "" |]
        | Some v ->
            match extractNameSequence v with
            | None -> [| "" |]
            | Some items -> extractNameStrings items
    let parseCnameFields (cnameFields : BerValue list) : byte array =
        let nameType =
            match contextAt cnameFields 0 with
            | Some v -> defaultArg (asInteger v) Fauli.Constants.Kerberos.NamePrincipal
            | None -> Fauli.Constants.Kerberos.NamePrincipal
        encodePrincipalName nameType (nameStringsFromContext cnameFields)
    match cname with
    | BerSequence cnameFields -> parseCnameFields cnameFields
    | _ -> encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| "" |]


let internal buildTgsReq (tgtTicket : byte array) (sessionKey : Key) (spn : string) (realm : string) (crealm : string) (cname : BerValue) (now : DateTime) : byte array =
    let nonce = Random.Shared.Next(1, 2147483647)
    let spnParts =
        match spn.Split('/') with
        | [| service; rest |] -> [| service; rest |]
        | [| single |] -> [| single |]
        | parts -> parts
    let authenticator =
        encodeAuthenticator
            { crealm = encodeRealm crealm
              cname = encodeCnameBytes cname
              cksum = None
              cusec = int (now.Ticks % 10000000L / 10L)
              ctime = now
              seqNumber = None } 
    let paTgs = 
        encrypt sessionKey KeyUsage.TgsReqAuth authenticator None
        |> encodeEncryptedData (int sessionKey.enctype) None 
        |> encodeApReq [] tgtTicket 
        |> encodePaData 1 
    let kdcOptions = encodeKdcOptions ["forwardable"; "renewable"; "renewable-ok"; "canonicalize"]
    let realmBytes = encodeRealm realm
    let sname = encodePrincipalName nameSrvInst spnParts |> Some
    let till = now.AddHours 24.0 |> Some
    let etype = [| int sessionKey.enctype |]
    encodeKdcReqBody
        { kdcOptions = kdcOptions
          cname = None
          realm = realmBytes
          sname = sname
          till = till
          rtime = None
          nonce = nonce
          etype = etype
          additionalTickets = None }
    |> encodeKdcReq 12 (Some [| paTgs |]) 
    |> encodeTgsReq 


///
/// Result of a successful TGS-REQ/TGS-REP exchange.
/// Contains the service ticket, its session key, and client identity for AP-REQ construction.
/// 
type internal ServiceTicketResult = 
    { ticketBytes : byte array
      sessionKey : Key
      encPart : BerValue
      cname : BerValue option
      crealm : string option }


///
/// Extract the per-service session key from EncTGSRepPart.
let internal extractServiceKey
    (encTgsRepPart : BerValue)
    : Key option =
    let buildKeyFromTypes (keyType : int) (keyBytes : byte array) : Key =
        { enctype = enum<EncryptionType> keyType
          contents = keyBytes }
    let extractKeyFromKf (keyFields : BerValue list) : Key option =
        let keyType =
            match contextAt keyFields 0 with
            | Some v -> asInteger v
            | None -> None
        let keyBytes =
            match contextAt keyFields 1 with
            | Some v -> asOctetString v
            | None -> None
        match keyType, keyBytes with
        | Some kt, Some kb -> Some (buildKeyFromTypes kt kb)
        | _ -> None
    let extractKeyFromFields (fields : BerValue list) : Key option =
        let keyVal = contextAt fields 0
        match keyVal with
        | Some (BerSequence keyFields) -> extractKeyFromKf keyFields
        | _ -> None
    match encTgsRepPart with
    | BerSequence fields -> extractKeyFromFields fields
    | _ -> None


///
/// Extract cname from EncTGSRepPart field [22].
let private extractTgsCname (encTgsRepPart : BerValue) : BerValue option =
    match encTgsRepPart with
    | BerSequence fields -> contextAt fields 22
    | _ -> None


///
/// Extract crealm from EncTGSRepPart field [23].
let private extractTgsCrealm (encTgsRepPart : BerValue) : string option =
    let extractCrealmString (v : BerValue) : string option =
        match v with
        | BerGeneralString s -> s |> Some
        | _ -> None
    match encTgsRepPart with
    | BerSequence fields ->
        contextAt fields 23
        |> Option.bind extractCrealmString
    | _ -> None


///
/// Decrypt TGS-REP enc-part after cipher extraction.
let private decryptTgsEncPart (tgt : TgtResult) (rep : BerValue) : Result<BerValue, AuthError> =
    match extractEncPartCipher rep with
    | None -> KerberosServiceTicketFailed |> Error
    | Some cipher ->
        parseBer (decrypt tgt.sessionKey KeyUsage.TgsRepEncPartSesskey cipher) |> Ok


///
/// Package a service ticket after the TGS-REP enc-part is decrypted.
let private completeServiceTicket (tgt : TgtResult) (rep : BerValue) (encTgsRepPart : BerValue) : Result<ServiceTicketResult, AuthError> =
    match extractServiceKey encTgsRepPart, extractTicketBytes rep with
    | None, _ | _, None -> KerberosServiceTicketFailed |> Error
    | Some svcSessionKey, Some ticketBytes ->
        { ticketBytes = ticketBytes
          sessionKey = svcSessionKey
          encPart = encTgsRepPart
          cname = extractTgsCname encTgsRepPart |> Option.map Some |> Option.defaultValue tgt.cname
          crealm = extractTgsCrealm encTgsRepPart |> Option.map Some |> Option.defaultValue tgt.crealm } |> Ok


///
/// Continue TGS after the KDC reply is known not to be a KRB-ERROR.
let private finishServiceTicketAfterReply (tgt : TgtResult) (tgsRep : byte array) : Result<ServiceTicketResult, AuthError> =
    let rep = decodeKdcRep tgsRep
    match decryptTgsEncPart tgt rep with
    | Error e -> e |> Error
    | Ok encTgsRepPart -> completeServiceTicket tgt rep encTgsRepPart


///
/// Build the service ticket acquisition pipeline.
let private acquireServiceTicket (kdcHost : string) (tgt : TgtResult) (spn : string) (realm : string) : Result<ServiceTicketResult, AuthError> =
    let crealm = defaultArg tgt.crealm realm
    let cname =
        match tgt.cname with
        | Some cn -> cn
        | None ->
            encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| "" |]
            |> parseBer
    let tgsRep =
        buildTgsReq tgt.ticketBytes tgt.sessionKey spn realm crealm cname
            (defaultArg tgt.serverTime DateTime.UtcNow)
        |> sendKdcRequest kdcHost 88
    match isKrbError tgsRep with
    | true -> KerberosServiceTicketFailed |> Error
    | false -> finishServiceTicketAfterReply tgt tgsRep


let internal getServiceTicket (kdcHost : string) (tgt : TgtResult) (spn : string) (realm : string) : Result<ServiceTicketResult, AuthError> =
    try
        acquireServiceTicket kdcHost tgt spn realm
    with
    | :? SocketException -> KerberosRealmUnreachable |> Error
    | ex -> UnexpectedError $"TGS acquisition failed: {ex.Message}" |> Error


///
/// Extract ticket bytes and session key from a ServiceTicketResult.
let private extractTicketAndKey (svcTicket : ServiceTicketResult) : byte array * Key =
    svcTicket.ticketBytes, svcTicket.sessionKey


///
/// Acquire a service ticket and extract its bytes and key.
let private acquireServiceTicketBytes (kdcHost : string) (tgt : TgtResult) (spn : string) (realm : string) : Result<byte array * Key, AuthError> =
    match getServiceTicket kdcHost tgt spn realm with
    | Error e -> e |> Error
    | Ok svcTicket -> extractTicketAndKey svcTicket |> Ok


///
/// Full Kerberos authentication: password → TGT → service ticket.
/// Returns the service ticket bytes and the *service* session key (not the TGT key).
/// 
let authenticateWithPassword (kdcHost : string) (username : string) (password : string) (realm : string) (spn : string) : Result<byte array * Key, AuthError> =
    match getTgt kdcHost username password realm with
    | Error e -> e |> Error
    | Ok tgt -> acquireServiceTicketBytes kdcHost tgt spn realm


///
/// Encode a BerValue to raw BER bytes for storage in domain types.
/// CRITICAL: Kerberos PrincipalName fields are context-tagged ([0] name-type, [1] name-string).
/// Dropping BerContext (the old `| _ -> [||]` arm) produced empty cnames in AP-REQ
/// authenticators and caused the SMB acceptor to return KRB-ERROR / logon failure.
/// 
module private BerEncode =
    let concatMany (arrays : byte array array) : byte array =
        let result =
            arrays |> Array.sumBy Array.length
            |> Array.zeroCreate<byte>
        let rec copyLoop idx offset =
            match idx < arrays.Length with
            | false -> ()
            | true ->
                Array.Copy(arrays.[idx], 0, result, offset, arrays.[idx].Length)
                copyLoop (idx + 1) (offset + arrays.[idx].Length)
        copyLoop 0 0
        result
    let berLen (len : int) : byte array =
        match len with
        | n when n < 128 -> [| byte n |]
        | n when n < 256 -> [| 0x81uy; byte n |]
        | n -> [| 0x82uy; byte ((n >>> 8) &&& 0xFF); byte (n &&& 0xFF) |]
    let stripLeadingZeroes (raw : byte array) : byte array =
        let rec strip idx =
            match idx < raw.Length - 1 && raw.[idx] = 0uy with
            | true -> strip (idx + 1)
            | false -> idx
        let start = strip 0
        Array.sub raw start (raw.Length - start)
    let encodeSequenceContent (items : BerValue list) (encode : BerValue -> byte array) : byte array =
        items
        |> List.map encode
        |> List.toArray
        |> concatMany
    let encodeTagged (tag : byte array) (content : byte array) : byte array =
        concatMany [| tag; berLen content.Length; content |]
    let encodeInteger (n : int) : byte array =
        let content =
            BitConverter.GetBytes(int32 n)
            |> Array.rev
            |> stripLeadingZeroes
        encodeTagged [| Fauli.Constants.berInteger |] content
    let encodeBoolean (b : bool) : byte array =
        let body =
            match b with
            | true -> [| 0xFFuy |]
            | false -> [| 0x00uy |]
        encodeTagged [| 0x01uy |] body
    let encodeBitString (bits : byte array) : byte array =
        let content = concatMany [| [| 0x00uy |]; bits |]
        encodeTagged [| 0x03uy |] content
    let encodeGeneralizedTime (dt : DateTime) : byte array =
        let s = dt.ToUniversalTime().ToString("yyyyMMddHHmmssZ", System.Globalization.CultureInfo.InvariantCulture)
        let bytes = System.Text.Encoding.ASCII.GetBytes s
        encodeTagged [| 0x18uy |] bytes
    let encodeContextTag (n : int) : byte array =
        match n < 31 with
        | true -> [| byte (0xA0 ||| n) |]
        | false -> [| 0xBFuy; byte n |]
    let rec encode (value : BerValue) : byte array =
        match value with
        | BerSequence items ->
            encodeTagged [| Fauli.Constants.berSequence |] (encodeSequenceContent items encode)
        | BerOctetString bytes ->
            encodeTagged [| Fauli.Constants.berOctetString |] bytes
        | BerGeneralString s ->
            encodeTagged [| 0x1Buy |] (System.Text.Encoding.ASCII.GetBytes s)
        | BerInteger n -> encodeInteger n
        | BerBoolean b -> encodeBoolean b
        | BerBitString bits -> encodeBitString bits
        | BerGeneralizedTime dt -> encodeGeneralizedTime dt
        | BerContext (n, inner) ->
            encodeTagged (encodeContextTag n) (encode inner)
        | BerRaw bytes ->
            bytes


let internal berEncodeValue (v : BerValue) : byte array =
    BerEncode.encode v


///
/// Client principal bytes from an optional cname BER value.
let private clientNameBytesFromOption (cname : BerValue option) : byte array =
    match cname with
    | Some cn -> berEncodeValue cn
    | None -> [||]


///
/// Package a service-ticket result as ProtocolHandlerParams.
let private packageServiceTicketParams (spn : ServiceName) (svcTicket : ServiceTicketResult) : ProtocolHandlerParams =
    KerberosTicket
        { serviceTicket = ServiceTicket svcTicket.ticketBytes
          serviceName = spn
          sessionKey = ServiceSessionKey (svcTicket.sessionKey.contents, int svcTicket.sessionKey.enctype)
          clientName = ClientPrincipalName (clientNameBytesFromOption svcTicket.cname)
          clientRealm = defaultArg svcTicket.crealm "" }


///
/// Continue after getServiceTicket returns.
let private continueAfterServiceTicket (spn : ServiceName) (svcResult : Result<ServiceTicketResult, AuthError>) : Result<ProtocolHandlerParams, AuthError> =
    match svcResult with
    | Error e -> e |> Error
    | Ok svcTicket -> packageServiceTicketParams spn svcTicket |> Ok


///
/// Acquire a service ticket from a TGT, wrap as KerberosTicketParams,
/// and wrap inside the ProtocolHandlerParams DU.
/// 
let private acquireServiceTicketParams (kdcHost : string) (spn : ServiceName) (spnStr : string) (realmStr : string) (tgt : Result<TgtResult, AuthError>) : Result<ProtocolHandlerParams, AuthError> =
    match tgt with
    | Error e -> e |> Error
    | Ok tgt' ->
        getServiceTicket kdcHost tgt' spnStr realmStr
        |> continueAfterServiceTicket spn


///
/// Password path for kerberosSolve.
let private kerberosSolvePassword (kdcHost : string) (spn : ServiceName) (spnStr : string) (realmStr : string) (creds : UserNamePassword) : Result<ProtocolHandlerParams, AuthError> =
    let (UserName userName) = creds.userName
    let (Password password) = creds.password
    getTgt kdcHost userName password realmStr
    |> acquireServiceTicketParams kdcHost spn spnStr realmStr


///
/// Solve Kerberos authentication for the given request.
/// Derives the TGT (from password or existing ticket), acquires a service ticket,
/// and returns KerberosTicketParams wrapped in ProtocolHandlerParams.
/// 
let internal kerberosSolve (request : AuthenticationRequest) (spn : ServiceName) (realm : KerberosRealm) : Result<ProtocolHandlerParams, AuthError> =
    let (Host kdcHost) = request.kdcHost
    let (KerberosRealm realmStr) = realm
    let (ServiceName spnStr) = spn
    match request.credential with
    | UserPassword creds ->
        kerberosSolvePassword kdcHost spn spnStr realmStr creds
    | KerberosKirbi _
    | KerberosCcache _
    | KerberosWindowsTicket _ ->
        KerberosTGTAcquisitionFailed |> Error
    | _ ->
        NoSuitableAuthMethod |> Error


///
/// GSS-API checksum flags for DCE-style mutual auth:
/// CONF | INTEG | SEQUENCE | REPLAY | MUTUAL | DCE_STYLE
/// 
let private gssSmbChecksumFlags = 0x103Eu


///
/// Build Authenticator for SMB without mutual auth.
let private buildSmbAuthenticator (crealm : string) (cname : BerValue) (now : DateTime) : byte array =
    let cusec = int (now.Ticks % 10000000L / 10L)
    encodeAuthenticator
        { crealm = encodeRealm crealm
          cname = encodeCnameBytes cname
          cksum = None
          cusec = cusec
          ctime = now
          seqNumber = None }


///
/// Build Authenticator with GSS-API checksum for DCE-style mutual auth.
let private buildSmbAuthenticatorMutual (crealm : string) (cname : BerValue) (now : DateTime) : byte array =
    let cusec = int (now.Ticks % 10000000L / 10L)
    let cksumBody = encodeGssApiChecksumBody gssSmbChecksumFlags
    let cksum = encodeChecksum 0x8003 cksumBody
    encodeAuthenticator
        { crealm = encodeRealm crealm
          cname = encodeCnameBytes cname
          cksum = Some cksum
          cusec = cusec
          ctime = now
          seqNumber = Some 0 }


///
/// Build a KRB-AP-REQ for SMB session setup.
/// SMB authenticator construction:
///   - no mutual-required ap-option
///   - no GSS checksum in Authenticator
///   - key usage 11
/// Server returns STATUS_SUCCESS; SMB session key = ticket session key[0..15].
/// 
let internal buildApReq (ticketBytes : byte array) (sessionKey : Key) (crealm : string) (cname : BerValue) : byte array =
    let now = DateTime.UtcNow
    let authenticator = buildSmbAuthenticator crealm cname now
    let encryptedAuthenticator = encrypt sessionKey KeyUsage.ApReqAuth authenticator None
    encodeApReq [] ticketBytes (encodeEncryptedData (int sessionKey.enctype) None encryptedAuthenticator)


///
/// Build a KRB-AP-REQ with mutual authentication (APOptions.mutual-required + GSS cksum).
/// Use when the acceptor requires mutual auth / DCE style (e.g. some RPC binds).
/// 
let internal buildApReqMutual (ticketBytes : byte array) (sessionKey : Key) (crealm : string) (cname : BerValue) : byte array =
    let now = DateTime.UtcNow
    let authenticator = buildSmbAuthenticatorMutual crealm cname now
    let encryptedAuthenticator = encrypt sessionKey KeyUsage.ApReqAuth authenticator None
    encodeApReq [ "mutual-required" ] ticketBytes (encodeEncryptedData (int sessionKey.enctype) None encryptedAuthenticator)


///
/// Build a KRB-AP-REQ using domain-level types (ServiceSessionKey, ClientPrincipalName).
/// This is the entry point for protocol handlers that don't import Kerberos internals.
/// 
let internal buildApReqFromDomain (ticketBytes : byte array) (sessionKey : ServiceSessionKey) (crealm : string) (clientName : ClientPrincipalName) : byte array =
    let (ServiceSessionKey (keyBytes, enctype)) = sessionKey
    let (ClientPrincipalName nameBytes) = clientName
    let key =
        { enctype = enum<EncryptionType> enctype
          contents = keyBytes }
    let cname =
        match nameBytes.Length > 0 with
        | true ->
            try parseBer nameBytes
            with _ -> encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| "Administrator" |] |> parseBer
        | false -> encodePrincipalName Fauli.Constants.Kerberos.NamePrincipal [| "Administrator" |] |> parseBer
    buildApReq ticketBytes key crealm cname
