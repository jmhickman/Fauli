module internal Fauli.Kerberos.Parsing


open System


type public BerTag = 
    { tagClass : int
      constructed : bool
      tagNumber : int }


type public BerValue =
    | BerInteger of int
    | BerOctetString of byte array
    | BerGeneralString of string
    | BerBoolean of bool
    | BerSequence of BerValue list
    | BerBitString of byte array
    | BerGeneralizedTime of DateTime
    | BerRaw of byte array
    | BerContext of int * BerValue  // context tag number + inner value


type ParserState =
    { data : byte array
      pos : int }


type BerParseError =
    | TruncatedInput


let private requireBytes (state : ParserState) (needed : int) : Result<ParserState, BerParseError> =
    match state.pos + needed > state.data.Length with
    | true -> TruncatedInput |> Error
    | false -> state |> Ok


let private readBytes (state : ParserState) (count : int) : Result<byte array * ParserState, BerParseError> =
    match requireBytes state count with
    | Error e -> e |> Error
    | Ok ready ->
        (Array.sub ready.data ready.pos count, { ready with pos = ready.pos + count }) |> Ok


let private readByte (state : ParserState) : Result<byte * ParserState, BerParseError> =
    match requireBytes state 1 with
    | Error e -> e |> Error
    | Ok ready ->
        (ready.data.[ready.pos], { ready with pos = ready.pos + 1 }) |> Ok


///
/// High bit set means another septet follows ([X.690] §8.1.2.4).
let private hasMoreTagOctets (b : byte) : bool =
    b &&& 0x80uy <> 0uy


///
/// Fold one 7-bit tag-number septet into the accumulator.
let private appendTagSeptet (acc : int) (b : byte) : int =
    acc <<< 7 ||| (int b &&& 0x7F)


///
/// Long-form tag number: septets until the continuation bit clears.
let private parseLongTagNumber (state : ParserState) : Result<int * ParserState, BerParseError> =
    let rec readSeptets st acc =
        match readByte st with
        | Error e -> e |> Error
        | Ok (b, next) ->
            let tagNumber = appendTagSeptet acc b
            match hasMoreTagOctets b with
            | true -> readSeptets next tagNumber
            | false -> (tagNumber, next) |> Ok
    readSeptets state 0


///
/// Short-form tag number when the low five bits are not the 0x1F escape.
let private shortFormTagNumber (tagByte : byte) : int option =
    match int (tagByte &&& 0x1Fuy) with
    | n when n < 31 -> Some n
    | _ -> None


let private berTag (tagByte : byte) (tagNumber : int) : BerTag =
    { tagClass = int tagByte >>> 6
      constructed = tagByte &&& 0x20uy <> 0uy
      tagNumber = tagNumber }


let private attachLongTagNumber (tagByte : byte) (afterFirst : ParserState) : Result<BerTag * ParserState, BerParseError> =
    match parseLongTagNumber afterFirst with
    | Error e -> e |> Error
    | Ok (tagNumber, afterTag) -> (berTag tagByte tagNumber, afterTag) |> Ok


let private tagFromFirstByte (tagByte : byte) (afterFirst : ParserState) : Result<BerTag * ParserState, BerParseError> =
    match shortFormTagNumber tagByte with
    | Some n -> (berTag tagByte n, afterFirst) |> Ok
    | None -> attachLongTagNumber tagByte afterFirst


let private parseTag (state : ParserState) : Result<BerTag * ParserState, BerParseError> =
    match readByte state with
    | Error e -> e |> Error
    | Ok (tagByte, afterFirst) -> tagFromFirstByte tagByte afterFirst


let private assembleLength (lenBytes : byte array) : int =
    let rec loop idx acc =
        match idx >= lenBytes.Length with
        | true -> acc
        | false -> loop (idx + 1) (acc <<< 8 ||| int lenBytes.[idx])
    loop 0 0


let private parseLongLength (afterLenByte : ParserState) (numLenBytes : int) : Result<int * ParserState, BerParseError> =
    match readBytes afterLenByte numLenBytes with
    | Error e -> e |> Error
    | Ok (lenBytes, afterLenBytes) -> (assembleLength lenBytes, afterLenBytes) |> Ok


let private parseLength (state : ParserState) : Result<int * ParserState, BerParseError> =
    match readByte state with
    | Error e -> e |> Error
    | Ok (lenByte, afterLenByte) ->
        match lenByte &&& 0x80uy = 0uy with
        | true -> (int lenByte, afterLenByte) |> Ok
        | false -> parseLongLength afterLenByte (int (lenByte &&& 0x0Fuy))


let private parseTlvValue (tag : BerTag) (afterLength : ParserState) (len : int) : Result<BerTag * byte array * ParserState, BerParseError> =
    match readBytes afterLength len with
    | Error e -> e |> Error
    | Ok (value, afterValue) -> (tag, value, afterValue) |> Ok


let private parseTlvAfterTag (tag : BerTag) (afterTag : ParserState) : Result<BerTag * byte array * ParserState, BerParseError> =
    match parseLength afterTag with
    | Error e -> e |> Error
    | Ok (len, afterLength) -> parseTlvValue tag afterLength len


let private parseTlv (state : ParserState) : Result<BerTag * byte array * ParserState, BerParseError> =
    match parseTag state with
    | Error e -> e |> Error
    | Ok (tag, afterTag) -> parseTlvAfterTag tag afterTag


///
/// Try to parse a GeneralizedTime string. Falls back to BerRaw on any parse failure.
let private tryParseGeneralizedTime (value : byte array) : BerValue =
    try
        let s = System.Text.Encoding.ASCII.GetString value
        let dt =
            match DateTime.TryParseExact(s, "yyyyMMddHHmmss.0Z", Globalization.CultureInfo.InvariantCulture, Globalization.DateTimeStyles.AssumeUniversal) with
            | true, parsed -> parsed
            | false, _ ->
                DateTime.ParseExact(s, "yyyyMMddHHmmssZ", Globalization.CultureInfo.InvariantCulture, Globalization.DateTimeStyles.AssumeUniversal)
        BerGeneralizedTime dt
    with _ -> BerRaw value


///
/// Accumulate bytes into an integer value for BER INTEGER parsing.
let private parseBerInteger (value : byte array) : BerValue =
    let rec accumulate idx acc =
        match idx >= value.Length with
        | true -> acc
        | false -> accumulate (idx + 1) ((acc <<< 8) ||| int value.[idx])
    let result = accumulate 0 0
    match value.Length > 4 with
    | true -> BerRaw value
    | false -> BerInteger result


///
/// Check whether the inner TLV consumed all of the content (explicit tag).
let private isCompleteInnerTlv (innerNext : ParserState) (content : byte array) : bool =
    innerNext.pos = content.Length


let rec private parseUniversalValue (tag : BerTag) (value : byte array) : BerValue =
    match tag.tagNumber with
    | 1 ->
        match value.Length >= 1 with
        | true -> BerBoolean (value.[value.Length - 1] <> 0uy)
        | false -> BerRaw value
    | 2 ->
        match value.Length = 0 with
        | true -> BerRaw value
        | false -> parseBerInteger value
    | 3 -> BerBitString value
    | 4 -> BerOctetString value
    | 16 -> parseConstructed value |> BerSequence
    | 17 -> parseConstructed value |> BerSequence
    | 24 -> tryParseGeneralizedTime value
    | 27 -> BerGeneralString (System.Text.Encoding.ASCII.GetString(value))
    | _ -> BerRaw value


///
/// Unwrap a single-element SEQUENCE or return the list as-is.
and private unwrapSingleSequence (innerValue : byte array) : BerValue =
    match parseConstructed innerValue with
    | [one] -> one
    | vs -> BerSequence vs


///
/// Decode a complete explicit context inner TLV.
and private decodeCompleteContextInner (innerTag : BerTag) (innerValue : byte array) : BerValue =
    match innerTag.tagClass = 1 && innerTag.constructed with
    | true -> unwrapSingleSequence innerValue
    | false -> parseUniversalValue innerTag innerValue


///
/// Try to parse a context-tagged inner value (explicit Kerberos tags).
and private tryParseContextInner (content : byte array) : Result<BerValue, BerParseError> =
    match parseTlv { data = content; pos = 0 } with
    | Error e -> e |> Error
    | Ok (innerTag, innerValue, innerNext) ->
        match isCompleteInnerTlv innerNext content with
        | false -> TruncatedInput |> Error
        | true -> decodeCompleteContextInner innerTag innerValue |> Ok


///
/// Context inner value, or the content interpreted as a universal value.
and private contextInnerOrRaw (tag : BerTag) (content : byte array) : BerValue =
    match tryParseContextInner content with
    | Ok inner -> inner
    | Error _ -> parseUniversalValue tag content


///
/// Parse one TLV element from the stream and return the BerValue.
and private parseOneBerValue (tag : BerTag) (content : byte array) : BerValue =
    match tag with
    | { tagClass = 2 } ->
        (tag.tagNumber, contextInnerOrRaw tag content) |> BerContext
    | { constructed = true } ->
        parseConstructed content |> BerSequence
    | _ ->
        parseUniversalValue tag content


and private parseRemainingElements (state : ParserState) : BerValue list =
    match parseTlv state with
    | Error _ -> []
    | Ok (tag, content, nextState) ->
        parseOneBerValue tag content :: parseConstructedFrom nextState


and private parseConstructedFrom (state : ParserState) : BerValue list =
    match state.pos >= state.data.Length with
    | true -> []
    | false -> parseRemainingElements state


and private parseConstructed (value : byte array) : BerValue list =
    parseConstructedFrom { data = value; pos = 0 }


let private decodeTopLevel (tag : BerTag) (value : byte array) : BerValue =
    match tag.tagClass = 1 with
    | true ->
        match parseConstructed value with
        | [v] -> v
        | vs -> BerSequence vs
    | false -> parseUniversalValue tag value


let parseBer (data : byte array) : BerValue =
    match parseTlv { data = data; pos = 0 } with
    | Error _ -> BerRaw data
    | Ok (tag, value, _) -> decodeTopLevel tag value


///
/// Structural converters. None when the BER value is the wrong shape.
let asInteger (v : BerValue) : int option =
    match v with
    | BerInteger n -> Some n
    | BerSequence [BerInteger n] -> Some n
    | _ -> None


let asOctetString (v : BerValue) : byte array option =
    match v with
    | BerOctetString b -> Some b
    | BerSequence [BerOctetString b] -> Some b
    | _ -> None


let asGeneralString (v : BerValue) : string option =
    match v with
    | BerGeneralString s -> Some s
    | BerSequence [BerGeneralString s] -> Some s
    | _ -> None


let asGeneralizedTime (v : BerValue) : DateTime option =
    match v with
    | BerGeneralizedTime dt -> Some dt
    | _ -> None


let asSequence (v : BerValue) : BerValue list option =
    match v with
    | BerSequence items -> Some items
    | _ -> None


let atIndex (items : BerValue list) (idx : int) : BerValue option =
    List.tryItem idx items


///
/// Find a context-tagged value by its tag number (handles optional fields correctly)
let contextAt (items : BerValue list) (tag : int) : BerValue option =
    items
    |> List.tryPick (fun item ->
        match item with
        | BerContext (n, v) when n = tag -> v |> Some
        | _ -> None)


let parseOctetStringContent (v : BerValue) : BerValue =
    match asOctetString v with
    | Some bytes -> parseBer bytes
    | None -> BerRaw [||]


///
/// Get the top-level APPLICATION tag number
let applicationTag (data : byte array) : int =
    match parseTag { data = data; pos = 0 } with
    | Error _ -> -1
    | Ok (tag, _) -> tag.tagNumber


///
/// Extract error code from KRB-ERROR fields [6].
let private extractErrorCodeContext (v : BerValue) : int =
    match v with
    | BerContext (_, inner) -> defaultArg (asInteger inner) -1
    | _ -> defaultArg (asInteger v) -1


let private extractErrorCode (fields : BerValue list) : int =
    match contextAt fields 6 with
    | Some v -> extractErrorCodeContext v
    | None -> -1


///
/// Extract error text from KRB-ERROR fields [11].
let private extractErrorTextValue (v : BerValue) : string option =
    match v with
    | BerOctetString b -> Some (System.Text.Encoding.ASCII.GetString b)
    | BerGeneralString s -> Some s
    | _ -> None


let private extractErrorText (fields : BerValue list) : string option =
    match contextAt fields 11 with
    | None -> None
    | Some v -> extractErrorTextValue v


///
/// KRB-ERROR fields by context tag:
/// [0] pvno, [1] msg-type, [2] ctime (opt), [3] cusec (opt),
/// [4] stime, [5] susec, [6] error-code, [7] crealm (opt),
/// [8] cname (opt), [9] realm, [10] sname, [11] e-text (opt), [12] e-data (opt)
/// 
let decodeKrbError (data : byte array) : int * string option =
    match parseBer data with
    | BerSequence fields -> extractErrorCode fields, extractErrorText fields
    | _ -> -1, None


let isKrbError (data : byte array) : bool =
    applicationTag data = 30


let decodeKdcRep (data : byte array) : BerValue =
    parseBer data


///
/// Extract a GeneralString string from a BerValue.
let private toGeneralString (v : BerValue) : string option =
    match v with
    | BerGeneralString s -> Some s
    | _ -> None


///
/// Unwrap a context-tagged inner value from KDC-REP ticket field.
let private unwrapTicketInner (v : BerValue) : BerValue =
    match v with
    | BerContext (_, inner) -> inner
    | BerRaw b -> parseBer b
    | other -> other


///
/// Extract the ticket value from KDC-REP fields [5].
let private extractTicketValue (fields : BerValue list) : BerValue =
    match contextAt fields 5 with
    | Some v -> unwrapTicketInner v
    | None -> BerSequence []


///
/// GeneralString components of a PrincipalName name-string SEQUENCE.
let private extractSnStrings (ss : BerValue list) : string array =
    let asGeneralString str =
        match str with
        | BerGeneralString s -> Some s
        | _ -> None
    ss
    |> List.choose asGeneralString
    |> List.toArray


///
/// Extract sname parts from a PrincipalName BER structure.
let private extractSnameParts (snFields : BerValue list) : byte array =
    let snType =
        match contextAt snFields 0 with
        | Some v -> defaultArg (asInteger v) 1
        | None -> 1
    let snStrs =
        match contextAt snFields 1 with
        | Some (BerSequence ss) -> extractSnStrings ss
        | _ -> [| "" |]
    Encoding.encodePrincipalName snType snStrs


///
/// Integer under a context tag, or a default when missing.
let private integerAtOr (fields : BerValue list) (tag : int) (defaultValue : int) : int =
    match contextAt fields tag with
    | Some v -> defaultArg (asInteger v) defaultValue
    | None -> defaultValue


///
/// GeneralString under a context tag, or empty when missing.
let private generalStringAtOrEmpty (fields : BerValue list) (tag : int) : string =
    match contextAt fields tag with
    | Some v -> defaultArg (asGeneralString v) ""
    | None -> ""


///
/// OCTET STRING under a context tag, or empty when missing.
let private octetStringAtOrEmpty (fields : BerValue list) (tag : int) : byte array =
    match contextAt fields tag with
    | Some v -> defaultArg (asOctetString v) [||]
    | None -> [||]


///
/// Optional integer under a context tag.
let private integerAtOpt (fields : BerValue list) (tag : int) : int option =
    match contextAt fields tag with
    | Some v -> asInteger v
    | None -> None


///
/// Encode EncryptedData fields back to wire bytes.
let private encodeEncPartBytes (epFields : BerValue list) : byte array =
    Encoding.encodeEncryptedData
        (integerAtOr epFields 0 18)
        (integerAtOpt epFields 1)
        (octetStringAtOrEmpty epFields 2)


///
/// Encode a Ticket SEQUENCE back to wire format.
let private encodeTicketFromFields (ticketFields : BerValue list) : byte array option =
    let tktVno = integerAtOr ticketFields 0 5
    let realmStr = generalStringAtOrEmpty ticketFields 1
    let snameVal = defaultArg (contextAt ticketFields 2) (BerSequence [])
    let encPartVal = defaultArg (contextAt ticketFields 3) (BerSequence [])
    let snameParts =
        match snameVal with
        | BerSequence snFields -> extractSnameParts snFields
        | _ -> Encoding.encodePrincipalName 1 [| "" |]
    match encPartVal with
    | BerSequence epFields ->
        Encoding.encodeTicket tktVno (Encoding.encodeRealm realmStr) snameParts (encodeEncPartBytes epFields) |> Some
    | _ -> None


///
/// Extract the raw ticket bytes from KDC-REP.
/// Re-encodes the ticket from parsed BER values back to wire format.
/// 
let extractTicketBytes (rep : BerValue) : byte array option =
    match rep with
    | BerSequence fields ->
        match extractTicketValue fields with
        | BerSequence ticketFields -> encodeTicketFromFields ticketFields
        | _ -> None
    | _ -> None


///
/// KDC-REP: [0] pvno, [1] msg-type, [2] padata (opt), [3] crealm,
/// [4] cname, [5] ticket, [6] enc-part
/// 
let extractEncPart (rep : BerValue) : BerValue option =
    match rep with
    | BerSequence fields -> contextAt fields 6
    | _ -> None


let extractEncPartCipher (rep : BerValue) : byte array option =
    match extractEncPart rep with
    | Some (BerSequence fields) -> Some (octetStringAtOrEmpty fields 2)
    | _ -> None


let extractEncPartEtype (rep : BerValue) : int option =
    match extractEncPart rep with
    | Some (BerSequence fields) -> Some (integerAtOr fields 0 18)
    | _ -> None


let extractCname (rep : BerValue) : BerValue option =
    match rep with
    | BerSequence fields -> contextAt fields 4
    | _ -> None


let extractCrealm (rep : BerValue) : string option =
    match rep with
    | BerSequence fields ->
        match contextAt fields 3 with
        | None -> None
        | Some v -> toGeneralString v
    | _ -> None


///
/// Try to parse an e-data field into a PA-DATA sequence.
let private tryParsePaDataSequence (v : BerValue) : BerValue list =
    match v with
    | BerOctetString b -> defaultArg (asSequence (parseBer b)) []
    | BerSequence items -> items
    | _ -> []


///
/// KRB-ERROR: [12] e-data contains PA-DATA sequence
let extractPaDataFromError (data : byte array) : BerValue list =
    match parseBer data with
    | BerSequence fields ->
        match contextAt fields 12 with
        | Some v -> tryParsePaDataSequence v
        | None -> []
    | _ -> []


///
/// Extract a GeneralizedTime from a BerValue (handles context-wrapped values).
let private extractGeneralizedTimeValue (v : BerValue) : DateTime option =
    match v with
    | BerGeneralizedTime dt -> Some dt
    | BerContext (_, BerGeneralizedTime dt) -> Some dt
    | _ -> None


///
/// Extract stime [4] from KRB-ERROR for clock skew correction
let extractStimeFromKrbError (data : byte array) : DateTime option =
    match parseBer data with
    | BerSequence fields ->
        match contextAt fields 4 with
        | None -> None
        | Some v -> extractGeneralizedTimeValue v
    | _ -> None
