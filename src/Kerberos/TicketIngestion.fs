module internal Fauli.Kerberos.TicketIngestion

open System


open Fauli.Domain
open Fauli.Kerberos.Parsing
open Fauli.Kerberos.Auth
open Fauli.Kerberos.Encryption


type TicketParseError =
    | InvalidKirbiFormat
    | InvalidCcacheFormat
    | CcacheVersionNotSupported
    | NoTgtFound
    | TgtExpired of DateTime
    | ParseError of string


///
/// Parsed credential info from one KrbCredInfo entry in a .kirbi file.
type KirbiCredInfo =
    { sessionKey : Key
      clientName : string list
      clientRealm : string option
      serverName : string list
      serverRealm : string option
      endtime : DateTime option
      ticketBytes : byte array }


///
/// Binary reader state for .ccache parsing.
type CcacheReader =
    { data : byte array
      pos : int }


///
/// After keyblock: skip timestamps, flags, addresses, authdata; return endtime + ticket + next reader.
type private CredentialTail =
    { reader : CcacheReader
      endTimeTs : uint32
      ticketBytes : byte array }


///
/// Parsed credential from a .ccache file.
type CcacheCredential =
    { clientName : string list
      clientRealm : string
      serverName : string list
      serverRealm : string
      sessionKey : Key
      endtime : DateTime option
      ticketBytes : byte array }


type private CcachePrincipals =
    { clientName : string list
      clientRealm : string
      serverName : string list
      serverRealm : string }


///
/// Mutable byte buffer used only at the serialization edge.
type private CcacheWriter =
    { buffer : ResizeArray<byte> }


///
/// Kerberos string component from a BER name-string element.
let private kerberosStringFromBer (str : BerValue) : string option =
    match str with
    | BerGeneralString s -> Some s
    | BerOctetString b -> Some (System.Text.Encoding.UTF8.GetString b)
    | _ -> None


///
/// SEQUENCE body under a context tag, when present.
let private sequenceAt (items : BerValue list) (tag : int) : BerValue list option =
    match contextAt items tag with
    | Some (BerSequence ss) -> Some ss
    | _ -> None


///
/// GeneralString under a context tag, when present.
let private generalStringAt (items : BerValue list) (tag : int) : string option =
    match contextAt items tag with
    | Some (BerGeneralString s) -> Some s
    | _ -> None


///
/// Integer under a context tag, or a default when missing.
let private integerAtOr (items : BerValue list) (tag : int) (defaultValue : int) : int =
    match contextAt items tag with
    | Some v -> defaultArg (asInteger v) defaultValue
    | None -> defaultValue


///
/// OCTET STRING under a context tag, or empty when missing.
let private octetStringAtOrEmpty (items : BerValue list) (tag : int) : byte array =
    match contextAt items tag with
    | Some v -> defaultArg (asOctetString v) [||]
    | None -> [||]


///
/// Parse a PrincipalName from BER (RFC 4120 §7.5.1).
/// [0] name-type (Int32), [1] name-string (SEQUENCE OF KerberosString)
/// 
let private parsePrincipalName (items : BerValue list) : string list =
    match sequenceAt items 1 with
    | None -> []
    | Some ss -> ss |> List.choose kerberosStringFromBer


///
/// True when the server principal names a TGT (krbtgt/...).
let private isTgtServerName (serverName : string list) : bool =
    match serverName with
    | [] -> true
    | head :: _ -> head = "krbtgt"


///
/// Parse an EncryptionKey from BER (RFC 4120 §7.5.1).
/// [0] keytype (Int32), [1] keyvalue (OCTET STRING)
/// 
let private parseEncryptionKey (v : BerValue) : Key option =
    match v with
    | BerSequence kf ->
        let keyType = integerAtOr kf 0 -1
        let keyValue = octetStringAtOrEmpty kf 1
        
        match keyType <> -1 && keyValue.Length > 0 with
        | true ->
            { enctype = enum<EncryptionType> keyType
              contents = keyValue } 
            |> Some
                
        | false -> None
    | _ -> None


///
/// Encryption key under context tag 0 of KrbCredInfo (sequence or bare).
let private sessionKeyFromCredInfo (items : BerValue list) : Key =
    let fallback =
        { enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
          contents = [||] }
    match contextAt items 0 with
    | Some (BerSequence kf) -> defaultArg (parseEncryptionKey (BerSequence kf)) fallback
    | Some v -> defaultArg (parseEncryptionKey v) fallback
    | None -> fallback


///
/// Find the TGT credential among parsed KrbCredInfo entries.
let private findTgtInKirbi (creds : KirbiCredInfo list) : Result<KirbiCredInfo, TicketParseError> =
    let isKirbiTgt (c : KirbiCredInfo) = isTgtServerName c.serverName
    match creds |> List.tryFind isKirbiTgt with
    | Some cred -> cred |> Ok
    | None -> NoTgtFound |> Error


///
/// Parse one KrbCredInfo from BER (RFC 4120 §5.5).
/// Ticket bytes are paired later from the KRB-CRED tickets field.
/// 
let private parseKrbCredInfo (items : BerValue list) : KirbiCredInfo option =
    let clientName =
        match sequenceAt items 2 with
        | None -> []
        | Some sn -> parsePrincipalName sn
    let serverName =
        match sequenceAt items 9 with
        | None -> []
        | Some sn -> parsePrincipalName sn
    let endtime =
        match contextAt items 6 with
        | Some v -> asGeneralizedTime v
        | None -> None
    
    { KirbiCredInfo.sessionKey = sessionKeyFromCredInfo items
      clientName = clientName
      clientRealm = generalStringAt items 1
      serverName = serverName
      serverRealm = generalStringAt items 8
      endtime = endtime
      ticketBytes = [||] }
    |> Some


///
/// Attach raw ticket TLV bytes by index to each credential info.
let private pairCredWithTicket (rawTickets : byte array list) (index : int) (cred : KirbiCredInfo) : KirbiCredInfo =
    let ticketBytes =
        match index < List.length rawTickets with
        | true -> List.item index rawTickets
        | false -> [||]
    { cred with ticketBytes = ticketBytes }


///
/// Parse SEQUENCE OF KrbCredInfo into domain records.
let private parseKrbCredInfoList (ticketInfos : BerValue list) : KirbiCredInfo list =
    let fromInfo info =
        match info with
        | BerSequence items -> parseKrbCredInfo items
        | _ -> None
    ticketInfos |> List.choose fromInfo


///
/// Advance past a high-tag-number tag encoding.
let private skipHighTagNumber (data : byte array) (pos : int) : int =
    let rec loop p =
        match data.[p] &&& 0x80uy <> 0uy with
        | true -> loop (p + 1)
        | false -> p + 1
    loop pos


///
/// Decode definite BER length at lenBytePos → (contentStart, contentEnd).
let private decodeDefiniteLength (data : byte array) (lenBytePos : int) : int * int =
    let lenByte = data.[lenBytePos]
    match lenByte &&& 0x80uy = 0uy with
    | true ->
        let contentStart = lenBytePos + 1
        contentStart, contentStart + int lenByte
    | false ->
        let numLenBytes = int (lenByte &&& 0x0Fuy)
        let rec foldLen i p acc =
            match i >= numLenBytes with
            | true -> acc, p
            | false -> foldLen (i + 1) (p + 1) (acc <<< 8 ||| int data.[p])
        let length, contentStart = foldLen 0 (lenBytePos + 1) 0
        contentStart, contentStart + length


///
/// Returns (contentStart, contentEnd) for the TLV at pos.
let private parseTlvBytes (data : byte array) (pos : int) : int * int =
    let tagByte = data.[pos]
    let afterTag = pos + 1
    let tagNumLow = int (tagByte &&& 0x1Fuy)
    let lenBytePos =
        match tagNumLow < 31 with
        | true -> afterTag
        | false -> skipHighTagNumber data afterTag
    decodeDefiniteLength data lenBytePos


///
/// List of (tlvStart, nextPos) for each item in a BER sequence span.
let private parseSequenceItems (data : byte array) (start : int) (end_ : int) : (int * int) list =
    let rec loop pos acc =
        match pos >= end_ with
        | true -> List.rev acc
        | false ->
            let _, nextPos = parseTlvBytes data pos
            loop nextPos ((pos, nextPos) :: acc)
    loop start []


///
/// Locate context [2] (tickets) inside a KRB-CRED SEQUENCE item list.
let private findTicketsContextOffset (rawData : byte array) (seqItems : (int * int) list) : int option =
    let isTicketsContext (tlvStart, _) =
        match rawData.[tlvStart] = 0xA2uy with
        | true -> Some tlvStart
        | false -> None
    seqItems |> List.tryPick isTicketsContext


///
/// Extract full Ticket TLVs from the original KRB-CRED bytes.
let private extractRawTickets (rawData : byte array) : byte array list =
    let appCs, _ = parseTlvBytes rawData 0
    let seqCs, seqCe = parseTlvBytes rawData appCs
    let seqItems = parseSequenceItems rawData seqCs seqCe
    
    match findTicketsContextOffset rawData seqItems with
    | None -> []
    | Some ticketsCtx ->
        let ctxCs, _ = parseTlvBytes rawData ticketsCtx
        let ticketSeqCs, ticketSeqCe = parseTlvBytes rawData ctxCs
        parseSequenceItems rawData ticketSeqCs ticketSeqCe
        |> List.map (fun (tlvStart, nextPos) -> Array.sub rawData tlvStart (nextPos - tlvStart))


///
/// EncryptedData fields: etype + cipher octets from enc-part [3].
let private encryptedDataParts (encPartVal : BerValue) : int * byte array =
    match encPartVal with
    | BerSequence ep -> integerAtOr ep 0 0, octetStringAtOrEmpty ep 2
    | _ -> 0, [||]


///
/// Ticket-info SEQUENCE OF KrbCredInfo under EncKrbCredPart [0].
let private ticketInfoSequence (encFields : BerValue list) : BerValue list =
    defaultArg (sequenceAt encFields 0) []


///
/// Build credential list with paired ticket TLVs from a parsed EncKrbCredPart.
let private credentialsFromEncKrbCredPart (rawData : byte array) (encFields : BerValue list) : Result<KirbiCredInfo, TicketParseError> =
    parseKrbCredInfoList (ticketInfoSequence encFields)
    |> List.mapi (rawData |> extractRawTickets |> pairCredWithTicket)
    |> findTgtInKirbi


///
/// Continue kirbi parse after outer KRB-CRED SEQUENCE is obtained.
let private parseKirbiFromCredSequence (rawData : byte array) (fields : BerValue list) : Result<KirbiCredInfo, TicketParseError> =
    let encPartVal = defaultArg (contextAt fields 3) (BerSequence [])
    let _, cipherBytes = encryptedDataParts encPartVal
    
    match cipherBytes.Length = 0 with
    | true -> InvalidKirbiFormat |> Error
    | false ->
        match parseBer cipherBytes with
        | BerSequence encFields -> credentialsFromEncKrbCredPart rawData encFields
        | _ -> InvalidKirbiFormat |> Error


///
/// Parse a .kirbi file (KRB-CRED, APPLICATION 22) and extract the TGT credential.
let parseKirbi (rawData : byte array) : Result<KirbiCredInfo, TicketParseError> =
    try
        match rawData.Length < 4 with
        | true -> InvalidKirbiFormat |> Error
        | false ->
            match parseBer rawData with
            | BerSequence fields -> parseKirbiFromCredSequence rawData fields
            | _ -> InvalidKirbiFormat |> Error
    with ex ->
        ParseError ex.Message |> Error


let private ccacheRequire (r : CcacheReader) (needed : int) : Result<CcacheReader, TicketParseError> =
    match r.pos + needed > r.data.Length with
    | true -> InvalidCcacheFormat |> Error
    | false -> r |> Ok


let private ccacheReadBytes (r : CcacheReader) (count : int) : Result<byte array * CcacheReader, TicketParseError> =
    match ccacheRequire r count with
    | Error e -> e |> Error
    | Ok ready ->
        (Array.sub ready.data ready.pos count, { ready with pos = ready.pos + count }) |> Ok


let private ccacheReadByte (r : CcacheReader) : Result<byte * CcacheReader, TicketParseError> =
    match ccacheRequire r 1 with
    | Error e -> e |> Error
    | Ok ready ->
        (ready.data.[ready.pos], { ready with pos = ready.pos + 1 }) |> Ok


///
/// Read a big-endian uint16 (network byte order).
let private ccacheReadUint16 (r : CcacheReader) : Result<uint16 * CcacheReader, TicketParseError> =
    match ccacheReadBytes r 2 with
    | Error e -> e |> Error
    | Ok (bytes, r') -> (uint16 (int bytes.[0] <<< 8 ||| int bytes.[1]), r') |> Ok


///
/// Read a big-endian uint32 (network byte order).
let private ccacheReadUint32 (r : CcacheReader) : Result<uint32 * CcacheReader, TicketParseError> =
    match ccacheReadBytes r 4 with
    | Error e -> e |> Error
    | Ok (b, r') ->
        ((uint32 b.[0] <<< 24) ||| (uint32 b.[1] <<< 16) ||| (uint32 b.[2] <<< 8) ||| uint32 b.[3], r') |> Ok


///
/// Read a CountedOctetString: uint32 length + that many bytes.
let private ccacheReadCountedOctetString (r : CcacheReader) : Result<byte array * CcacheReader, TicketParseError> =
    match ccacheReadUint32 r with
    | Error e -> e |> Error
    | Ok (len, r') -> ccacheReadBytes r' (int len)


///
/// Read a CountedOctetString as ASCII string.
let private ccacheReadString (r : CcacheReader) : Result<string * CcacheReader, TicketParseError> =
    match ccacheReadCountedOctetString r with
    | Error e -> e |> Error
    | Ok (bytes, r') -> (System.Text.Encoding.ASCII.GetString bytes, r') |> Ok


///
/// Parse a ccache Principal (version 4).
let private ccacheReadComponents (count : int) (r : CcacheReader) : Result<string list * CcacheReader, TicketParseError> =
    let rec loop i acc reader =
        match i >= count with
        | true -> (List.rev acc, reader) |> Ok
        | false ->
            match ccacheReadString reader with
            | Error e -> e |> Error
            | Ok (comp, r') -> loop (i + 1) (comp :: acc) r'
    loop 0 [] r


let private principalWithComponents (nameType : uint32) (numComponents : uint32) (realm : string) (r3 : CcacheReader) : Result<(int * string list * string) * CcacheReader, TicketParseError> =
    match ccacheReadComponents (int numComponents) r3 with
    | Error e -> e |> Error
    | Ok (components, rFinal) -> ((int nameType, components, realm), rFinal) |> Ok


let private finishPrincipal (nameType : uint32) (numComponents : uint32) (r2 : CcacheReader) : Result<(int * string list * string) * CcacheReader, TicketParseError> =
    match ccacheReadString r2 with
    | Error e -> e |> Error
    | Ok (realm, r3) -> principalWithComponents nameType numComponents realm r3


let private readPrincipalAfterNameType (nameType : uint32) (r1 : CcacheReader) : Result<(int * string list * string) * CcacheReader, TicketParseError> =
    match ccacheReadUint32 r1 with
    | Error e -> e |> Error
    | Ok (numComponents, r2) -> finishPrincipal nameType numComponents r2


let private ccacheReadPrincipal (r : CcacheReader) : Result<(int * string list * string) * CcacheReader, TicketParseError> =
    match ccacheReadUint32 r with
    | Error e -> e |> Error
    | Ok (nameType, r1) -> readPrincipalAfterNameType nameType r1


///
/// Parse a KeyBlockV4.
let private readKeyValue (keyType : uint16) (keyLen : uint16) (r3 : CcacheReader) : Result<Key * CcacheReader, TicketParseError> =
    match ccacheReadBytes r3 (int keyLen) with
    | Error e -> e |> Error
    | Ok (keyValue, r4) ->
        ({ enctype = enum<EncryptionType> (int keyType)
           contents = keyValue }, r4) |> Ok


let private readKeyLength (keyType : uint16) (r2 : CcacheReader) : Result<Key * CcacheReader, TicketParseError> =
    match ccacheReadUint16 r2 with
    | Error e -> e |> Error
    | Ok (keyLen, r3) -> readKeyValue keyType keyLen r3


let private skipDuplicateEtype (keyType : uint16) (r1 : CcacheReader) : Result<Key * CcacheReader, TicketParseError> =
    match ccacheReadUint16 r1 with
    | Error e -> e |> Error
    | Ok (_, r2) -> readKeyLength keyType r2


let private ccacheReadKeyBlockV4 (r : CcacheReader) : Result<Key * CcacheReader, TicketParseError> =
    match ccacheReadUint16 r with
    | Error e -> e |> Error
    | Ok (keyType, r1) -> skipDuplicateEtype keyType r1


///
/// Parse an Address: addrtype (uint16), addrdata (CountedOctetString).
let private skipAddressData (r1 : CcacheReader) : Result<CcacheReader, TicketParseError> =
    match ccacheReadCountedOctetString r1 with
    | Error e -> e |> Error
    | Ok (_, r2) -> r2 |> Ok


let private ccacheReadAddress (r : CcacheReader) : Result<CcacheReader, TicketParseError> =
    match ccacheReadUint16 r with
    | Error e -> e |> Error
    | Ok (_, r1) -> skipAddressData r1


///
/// Parse an AuthData: authtype (uint16), authdata (CountedOctetString).
let private skipAuthDataPayload (r1 : CcacheReader) : Result<CcacheReader, TicketParseError> =
    match ccacheReadCountedOctetString r1 with
    | Error e -> e |> Error
    | Ok (_, r2) -> r2 |> Ok


let private ccacheReadAuthData (r : CcacheReader) : Result<CcacheReader, TicketParseError> =
    match ccacheReadUint16 r with
    | Error e -> e |> Error
    | Ok (_, r1) -> skipAuthDataPayload r1


///
/// Skip N address records.
let private ccacheSkipAddresses (count : int) (r : CcacheReader) : Result<CcacheReader, TicketParseError> =
    let rec loop i reader =
        match i >= count with
        | true -> reader |> Ok
        | false ->
            match ccacheReadAddress reader with
            | Error e -> e |> Error
            | Ok next -> loop (i + 1) next
    loop 0 r


///
/// Skip N authdata records.
let private ccacheSkipAuthData (count : int) (r : CcacheReader) : Result<CcacheReader, TicketParseError> =
    let rec loop i reader =
        match i >= count with
        | true -> reader |> Ok
        | false ->
            match ccacheReadAuthData reader with
            | Error e -> e |> Error
            | Ok next -> loop (i + 1) next
    loop 0 r


let private continueTail (read : CcacheReader -> Result<'a * CcacheReader, TicketParseError>) (update : CredentialTail -> 'a -> CcacheReader -> CredentialTail) (t : CredentialTail) : Result<CredentialTail, TicketParseError> =
    match read t.reader with
    | Error e -> e |> Error
    | Ok (value, next) -> update t value next |> Ok


let private skipAuthTime (t : CredentialTail) : Result<CredentialTail, TicketParseError> =
    continueTail ccacheReadUint32 (fun cur _ next -> { cur with reader = next }) t


let private skipStartTime (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> continueTail ccacheReadUint32 (fun cur _ next -> { cur with reader = next }) t


let private takeEndTime (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> continueTail ccacheReadUint32 (fun cur ts next -> { cur with reader = next; endTimeTs = ts }) t


let private skipRenewTill (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> continueTail ccacheReadUint32 (fun cur _ next -> { cur with reader = next }) t


let private skipIsSkey (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> continueTail ccacheReadByte (fun cur _ next -> { cur with reader = next }) t


let private skipTktFlags (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> continueTail ccacheReadUint32 (fun cur _ next -> { cur with reader = next }) t


let private addressesAfterCount (t : CredentialTail) (numAddr : uint32) (afterCount : CcacheReader) : Result<CredentialTail, TicketParseError> =
    match ccacheSkipAddresses (int numAddr) afterCount with
    | Error e -> e |> Error
    | Ok next -> { t with reader = next } |> Ok


let private addressCountOf (t : CredentialTail) : Result<CredentialTail, TicketParseError> =
    match ccacheReadUint32 t.reader with
    | Error e -> e |> Error
    | Ok (numAddr, afterCount) -> addressesAfterCount t numAddr afterCount


let private skipAddressList (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> addressCountOf t


let private authDataAfterCount (t : CredentialTail) (numAuthData : uint32) (afterCount : CcacheReader) : Result<CredentialTail, TicketParseError> =
    match ccacheSkipAuthData (int numAuthData) afterCount with
    | Error e -> e |> Error
    | Ok next -> { t with reader = next } |> Ok


let private authDataCountOf (t : CredentialTail) : Result<CredentialTail, TicketParseError> =
    match ccacheReadUint32 t.reader with
    | Error e -> e |> Error
    | Ok (numAuthData, afterCount) -> authDataAfterCount t numAuthData afterCount


let private skipAuthDataList (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> authDataCountOf t


let private takeTicketBytes (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> continueTail ccacheReadCountedOctetString (fun cur bytes next -> { cur with reader = next; ticketBytes = bytes }) t


let private skipSecondTicket (tail : Result<CredentialTail, TicketParseError>) : Result<CredentialTail, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> continueTail ccacheReadCountedOctetString (fun cur _ next -> { cur with reader = next }) t


let private startCredentialTail (r : CcacheReader) : Result<CredentialTail, TicketParseError> =
    skipAuthTime
        { reader = r
          endTimeTs = 0u
          ticketBytes = [||] }


let private finishCredentialTail (tail : Result<CredentialTail, TicketParseError>) : Result<uint32 * byte array * CcacheReader, TicketParseError> =
    match tail with
    | Error e -> e |> Error
    | Ok t -> (t.endTimeTs, t.ticketBytes, t.reader) |> Ok


let private ccacheReadCredentialTail (r : CcacheReader) : Result<uint32 * byte array * CcacheReader, TicketParseError> =
    r
    |> startCredentialTail
    |> skipStartTime
    |> takeEndTime
    |> skipRenewTill
    |> skipIsSkey
    |> skipTktFlags
    |> skipAddressList
    |> skipAuthDataList
    |> takeTicketBytes
    |> skipSecondTicket
    |> finishCredentialTail


///
/// Skip an entire config credential (X-CACHECONF) without materializing it.
let private skipConfigAfterKey (r3 : CcacheReader) : Result<CcacheReader, TicketParseError> =
    match ccacheReadCredentialTail r3 with
    | Error e -> e |> Error
    | Ok (_, _, r15) -> r15 |> Ok


let private ccacheSkipConfigCredential (r : CcacheReader) : Result<CcacheReader, TicketParseError> =
    match ccacheReadKeyBlockV4 r with
    | Error e -> e |> Error
    | Ok (_, r3) -> skipConfigAfterKey r3


///
/// Find the TGT credential among parsed ccache credentials.
let private findTgtInCcache (creds : CcacheCredential list) : Result<CcacheCredential, TicketParseError> =
    let isCcacheTgt (c : CcacheCredential) = isTgtServerName c.serverName
    match creds |> List.tryFind isCcacheTgt with
    | Some cred -> cred |> Ok
    | None -> NoTgtFound |> Error


///
/// Convert a Unix timestamp (seconds since epoch) to DateTime UTC.
let private unixTimestampToDateTime (ts : uint32) : DateTime option =
    match ts with
    | 0u -> None
    | _ -> Some (DateTimeOffset.FromUnixTimeSeconds(int64 ts).UtcDateTime)


///
/// Materialize one non-config credential from principals + remaining body.
let private credentialFromTail (principals : CcachePrincipals) (sessionKey : Key) (endTimeTs : uint32) (ticketBytes : byte array) (r15 : CcacheReader) : CcacheCredential * CcacheReader =
    { CcacheCredential.clientName = principals.clientName
      clientRealm = principals.clientRealm
      serverName = principals.serverName
      serverRealm = principals.serverRealm
      sessionKey = sessionKey
      endtime = unixTimestampToDateTime endTimeTs
      ticketBytes = ticketBytes }, r15


let private credentialAfterKey (principals : CcachePrincipals) (sessionKey : Key) (r3 : CcacheReader) : Result<CcacheCredential * CcacheReader, TicketParseError> =
    match ccacheReadCredentialTail r3 with
    | Error e -> e |> Error
    | Ok (endTimeTs, ticketBytes, r15) ->
        credentialFromTail principals sessionKey endTimeTs ticketBytes r15 |> Ok


let private ccacheBuildCredential (principals : CcachePrincipals) (r : CcacheReader) : Result<CcacheCredential * CcacheReader, TicketParseError> =
    match ccacheReadKeyBlockV4 r with
    | Error e -> e |> Error
    | Ok (sessionKey, r3) -> credentialAfterKey principals sessionKey r3


///
/// Read one credential entry; None means stop (EOF / parse failure).
let private credentialFromServer (principals : CcachePrincipals) (r2 : CcacheReader) : (CcacheCredential option * CcacheReader) option =
    match principals.serverRealm with
    | "X-CACHECONF:" ->
        match ccacheSkipConfigCredential r2 with
        | Error _ -> None
        | Ok next -> Some (None, next)
    | _ ->
        match ccacheBuildCredential principals r2 with
        | Error _ -> None
        | Ok (cred, rNext) -> Some (Some cred, rNext)


let private credentialAfterClient (clientName : string list) (clientRealm : string) (r1 : CcacheReader) : (CcacheCredential option * CcacheReader) option =
    match ccacheReadPrincipal r1 with
    | Error _ -> None
    | Ok ((_, serverName, serverRealm), r2) ->
        credentialFromServer
            { CcachePrincipals.clientName = clientName
              clientRealm = clientRealm
              serverName = serverName
              serverRealm = serverRealm } r2


let private ccacheTryReadOneCredential (r : CcacheReader) : (CcacheCredential option * CcacheReader) option =
    match r.pos >= r.data.Length with
    | true -> None
    | false ->
        match ccacheReadPrincipal r with
        | Error _ -> None
        | Ok ((_, clientName, clientRealm), r1) -> credentialAfterClient clientName clientRealm r1


///
/// Parse all credential entries until EOF or a hard parse failure.
let private ccacheReadAllCredentials (r : CcacheReader) : CcacheCredential list =
    let rec loop acc reader =
        match ccacheTryReadOneCredential reader with
        | None -> List.rev acc
        | Some (None, next) -> loop acc next
        | Some (Some cred, next) -> loop (cred :: acc) next
    loop [] r


///
/// Skip header tag entries after the mini-header.
let private ccacheSkipHeaders (remaining : int) (r : CcacheReader) : CcacheReader =
    let rec loop left reader =
        match left <= 0 || reader.pos + 4 > reader.data.Length with
        | true -> reader
        | false ->
            let taglen = uint16 (int reader.data.[reader.pos + 2] <<< 8 ||| int reader.data.[reader.pos + 3])
            loop (left - 4 - int taglen) { reader with pos = reader.pos + 4 + int taglen }
    loop remaining r


///
/// Parse ccache v4 body after version bytes have been validated.
let private tgtFromCredentials (afterPrincipal : CcacheReader) : Result<CcacheCredential, TicketParseError> =
    match ccacheReadAllCredentials afterPrincipal with
    | [] -> InvalidCcacheFormat |> Error
    | credentials -> findTgtInCcache credentials


let private credentialsAfterDefaultPrincipal (afterHeaders : CcacheReader) : Result<CcacheCredential, TicketParseError> =
    match ccacheReadPrincipal afterHeaders with
    | Error e -> e |> Error
    | Ok (_, afterPrincipal) -> tgtFromCredentials afterPrincipal


let private parseCcacheV4Body (rawData : byte array) : Result<CcacheCredential, TicketParseError> =
    match ccacheReadUint16 { data = rawData; pos = 2 } with
    | Error e -> e |> Error
    | Ok (headerLen, _) ->
        { data = rawData; pos = 4 }
        |> ccacheSkipHeaders (int headerLen)
        |> credentialsAfterDefaultPrincipal


let private parseCcacheVersioned (rawData : byte array) : Result<CcacheCredential, TicketParseError> =
    match rawData.[0], rawData.[1] with
    | 0x05uy, 0x04uy -> parseCcacheV4Body rawData
    | _ -> InvalidCcacheFormat |> Error


///
/// Parse a .ccache file (MIT credential cache, version 4) and extract the TGT credential.
let parseCcache (rawData : byte array) : Result<CcacheCredential, TicketParseError> =
    match rawData.Length < 6 with
    | true -> InvalidCcacheFormat |> Error
    | false -> parseCcacheVersioned rawData


let private createCcacheWriter () : CcacheWriter =
    { buffer = ResizeArray<byte>() }


let private writeByte (w : CcacheWriter) (b : byte) : unit =
    w.buffer.Add(b) |> ignore


let private writeBytes (w : CcacheWriter) (arr : byte array) : unit =
    arr |> Array.iter (writeByte w)


let private writeUint16BE (w : CcacheWriter) (v : uint16) : unit =
    writeByte w (byte (int v >>> 8 &&& 0xFF))
    writeByte w (byte (int v &&& 0xFF))


let private writeUint32BE (w : CcacheWriter) (v : uint32) : unit =
    writeByte w (byte (int v >>> 24 &&& 0xFF))
    writeByte w (byte (int v >>> 16 &&& 0xFF))
    writeByte w (byte (int v >>> 8 &&& 0xFF))
    writeByte w (byte (int v &&& 0xFF))


let private writeCountedString (w : CcacheWriter) (s : string) : unit =
    let b = System.Text.Encoding.ASCII.GetBytes s
    writeUint32BE w (uint32 b.Length)
    writeBytes w b


let private writeCountedBytes (w : CcacheWriter) (b : byte array) : unit =
    writeUint32BE w (uint32 b.Length)
    writeBytes w b


///
/// Client principal name components from an optional cname BER value.
let private cnameComponentsFromTgt (tgt : TgtResult) : string list =
    match tgt.cname with
    | Some (BerSequence fields) ->
        match sequenceAt fields 1 with
        | None -> []
        | Some ss -> ss |> List.choose kerberosStringFromBer
    | _ -> []


let private toUnixTimestamp (dt : DateTime) : uint32 =
    let epoch = DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
    uint32 (int64 (dt - epoch).TotalSeconds)


///
/// Write mini-header + default header entry for ccache v4.
let private writeCcacheHeader (w : CcacheWriter) : unit =
    writeUint16BE w 0x0504us
    writeUint16BE w 12us
    writeUint16BE w 1us
    writeUint16BE w 8us
    writeBytes w [| 0xFFuy; 0xFFuy; 0xFFuy; 0xFFuy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]


///
/// Write a simple one-component principal (name_type=1).
let private writeSimplePrincipal (w : CcacheWriter) (realm : string) (name : string) : unit =
    writeUint32BE w 1u
    writeUint32BE w 1u
    writeCountedString w realm
    writeCountedString w name


///
/// Write krbtgt/REALM server principal (NT-SRV-INST).
let private writeKrbtgtPrincipal (w : CcacheWriter) (realm : string) : unit =
    writeUint32BE w 2u
    writeUint32BE w 2u
    writeCountedString w realm
    writeCountedString w "krbtgt"
    writeCountedString w realm


///
/// Write KeyBlockV4 for the TGT session key.
let private writeSessionKeyBlock (w : CcacheWriter) (tgt : TgtResult) : unit =
    let keyBytes = tgt.sessionKey.contents
    writeUint16BE w (uint16 tgt.sessionKeyType)
    writeUint16BE w (uint16 tgt.sessionKeyType)
    writeUint16BE w (uint16 keyBytes.Length)
    writeBytes w keyBytes


///
/// Write credential timestamps derived from TGT server time.
let private writeCredentialTimestamps (w : CcacheWriter) (tgt : TgtResult) : unit =
    let now = DateTime.UtcNow
    let startTime = defaultArg tgt.serverTime now
    let endTime =
        match tgt.serverTime with
        | Some t -> t.AddHours 24.0
        | None -> now.AddHours 24.0
    writeUint32BE w (toUnixTimestamp startTime)
    writeUint32BE w (toUnixTimestamp startTime)
    writeUint32BE w (toUnixTimestamp endTime)
    writeUint32BE w 0u


///
/// Serialize a TgtResult back to a .ccache v4 byte array.
let internal writeCcache (tgt : TgtResult) : byte array =
    let w = createCcacheWriter ()
    let crealm = defaultArg tgt.crealm "UNKNOWN"
    let principalName = defaultArg (List.tryHead (cnameComponentsFromTgt tgt)) "unknown"
    
    writeCcacheHeader w
    writeSimplePrincipal w crealm principalName
    writeSimplePrincipal w crealm principalName
    writeKrbtgtPrincipal w crealm
    writeSessionKeyBlock w tgt
    writeCredentialTimestamps w tgt
    writeByte w 0uy            // is_skey
    writeUint32BE w 0u         // tktflags
    writeUint32BE w 0u         // num_addresses
    writeUint32BE w 0u         // num_authdata
    writeCountedBytes w tgt.ticketBytes
    writeUint32BE w 0u         // second_ticket empty
    w.buffer.ToArray()


///
/// Convert a parsed KirbiCredInfo to a TgtResult for use with getServiceTicket.
let private kirbiToTgtResult (cred : KirbiCredInfo) : TgtResult =
    { TgtResult.ticketBytes = cred.ticketBytes
      sessionKey = cred.sessionKey
      sessionKeyType = int cred.sessionKey.enctype
      cname = None
      crealm = cred.clientRealm
      serverTime = None }


///
/// Convert a parsed CcacheCredential to a TgtResult for use with getServiceTicket.
let private ccacheToTgtResult (cred : CcacheCredential) : TgtResult =
    { TgtResult.ticketBytes = cred.ticketBytes
      sessionKey = cred.sessionKey
      sessionKeyType = int cred.sessionKey.enctype
      cname = None
      crealm = Some cred.clientRealm
      serverTime = None }


///
/// Reject expired TGTs; otherwise return the built TgtResult.
let private tgtResultIfNotExpired (endtime : DateTime option) (tgt : TgtResult) : Result<TgtResult, AuthError> =
    match endtime with
    | Some dt when dt < DateTime.UtcNow -> KerberosTGTExpired |> Error
    | _ -> tgt |> Ok


///
/// Map TicketParseError to AuthError for the solver boundary.
let private mapTicketParseError (err : TicketParseError) : AuthError =
    match err with
    | ParseError msg -> UnexpectedError msg
    | InvalidKirbiFormat
    | InvalidCcacheFormat
    | CcacheVersionNotSupported
    | NoTgtFound
    | TgtExpired _ -> KerberosTGTAcquisitionFailed


///
/// Continue after a successful kirbi parse.
let private continueAfterKirbiParse (parsed : Result<KirbiCredInfo, TicketParseError>) : Result<TgtResult, AuthError> =
    match parsed with
    | Error e -> mapTicketParseError e |> Error
    | Ok cred -> tgtResultIfNotExpired cred.endtime (kirbiToTgtResult cred)


///
/// Continue after a successful ccache parse.
let private continueAfterCcacheParse (parsed : Result<CcacheCredential, TicketParseError>) : Result<TgtResult, AuthError> =
    match parsed with
    | Error e -> mapTicketParseError e |> Error
    | Ok cred -> tgtResultIfNotExpired cred.endtime (ccacheToTgtResult cred)


///
/// Parse a .kirbi file and extract the TGT as a TgtResult.
let internal extractTgtFromKirbi (rawData : byte array) : Result<TgtResult, AuthError> =
    rawData
    |> parseKirbi
    |> continueAfterKirbiParse


///
/// Parse a .ccache file and extract the TGT as a TgtResult.
let internal extractTgtFromCcache (rawData : byte array) : Result<TgtResult, AuthError> =
    rawData
    |> parseCcache
    |> continueAfterCcacheParse
