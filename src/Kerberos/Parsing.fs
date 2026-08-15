/// BER/DER parser for Kerberos wire format responses.
module internal Fauli.Kerberos.Parsing

open System

// ---------------------------------------------------------------------------
// BER tag types
// ---------------------------------------------------------------------------

type public BerTag = {
    tagClass : int
    constructed : bool
    tagNumber : int
}

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

// ---------------------------------------------------------------------------
// Parser state
// ---------------------------------------------------------------------------

type ParserState =
    { data : byte array
      pos : int }

let private checkLength (state : ParserState) (needed : int) : unit =
    match state.pos + needed > state.data.Length with
    | true -> invalidArg "data" $"Expected {needed} bytes at position {state.pos}, but only {state.data.Length - state.pos} remaining"
    | false -> ()

let private readBytes (state : ParserState) (count : int) : byte array * ParserState =
    checkLength state count
    let bytes = Array.sub state.data state.pos count
    bytes, { state with pos = state.pos + count }

let private readByte (state : ParserState) : byte * ParserState =
    checkLength state 1
    state.data.[state.pos], { state with pos = state.pos + 1 }

// ---------------------------------------------------------------------------
// Parse BER tag
// ---------------------------------------------------------------------------

let private parseTag (state : ParserState) : BerTag * ParserState =
    let tagByte, state' = readByte state
    let tagClass = int tagByte >>> 6
    let constructed = (tagByte &&& 0x20uy) <> 0uy
    let tagNumLow = int (tagByte &&& 0x1Fuy)

    match tagNumLow < 31 with
    | true -> { tagClass = tagClass; constructed = constructed; tagNumber = tagNumLow }, state'
    | false ->
        let rec loop (st : ParserState) (acc : int) : int * ParserState =
            let b, next = readByte st
            let acc' = acc <<< 8 ||| (int b &&& 0x7F)
            match b &&& 0x80uy <> 0uy with
            | true -> loop next acc'
            | false -> acc', next
        let tagNum, state'' = loop state' 0
        { tagClass = tagClass; constructed = constructed; tagNumber = tagNum }, state''

// ---------------------------------------------------------------------------
// Parse BER length
// ---------------------------------------------------------------------------

let private parseLength (state : ParserState) : int * ParserState =
    let lenByte, state' = readByte state
    match (lenByte &&& 0x80uy) = 0uy with
    | true -> int lenByte, state'
    | false ->
        let numLenBytes = int (lenByte &&& 0x0Fuy)
        checkLength state' numLenBytes
        let lenBytes, state'' = readBytes state' numLenBytes
        let rec assemble idx acc =
            match idx >= lenBytes.Length with
            | true -> acc
            | false -> assemble (idx + 1) ((acc <<< 8) ||| int lenBytes.[idx])
        assemble 0 0, state''

// ---------------------------------------------------------------------------
// Parse a TLV
// ---------------------------------------------------------------------------

let private parseTlv (state : ParserState) : BerTag * byte array * ParserState =
    let tag, state' = parseTag state
    let len, state'' = parseLength state'
    checkLength state'' len
    let value, state''' = readBytes state'' len
    tag, value, state'''

// ---------------------------------------------------------------------------
// Parse value based on tag (mutually recursive with parseConstructed)
// ---------------------------------------------------------------------------

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

/// Unwrap a single-element SEQUENCE or return the list as-is.
and private unwrapSingleSequence (innerValue : byte array) : BerValue =
    match parseConstructed innerValue with
    | [one] -> one
    | vs -> BerSequence vs

/// Try to parse a context-tagged inner value (explicit Kerberos tags).
and private tryParseContextInner (tag : BerTag) (content : byte array) : BerValue =
    try
        let innerTag, innerValue, innerNext = parseTlv { data = content; pos = 0 }
        match isCompleteInnerTlv innerNext content with
        | true ->
            match innerTag.tagClass = 1 && innerTag.constructed with
            | true -> unwrapSingleSequence innerValue
            | false -> parseUniversalValue innerTag innerValue
        | false ->
            // Not a valid inner TLV — treat as primitive
            parseUniversalValue tag content
    with _ ->
        parseUniversalValue tag content

/// Parse one TLV element from the stream and return the BerValue.
and private parseOneBerValue (tag : BerTag) (content : byte array) : BerValue =
    match tag with
    | { tagClass = 2 } ->
        // Context-specific tag — always try to parse inner TLV first (Kerberos BER uses explicit tags)
        (tag.tagNumber, tryParseContextInner tag content) |> BerContext
    | { constructed = true } ->
        parseConstructed content |> BerSequence
    | _ ->
        parseUniversalValue tag content

and private parseConstructed (value : byte array) : BerValue list =
    let rec loop (state : ParserState) : BerValue list =
        match state.pos >= state.data.Length with
        | true -> []
        | false ->
            let tag, content, nextState = parseTlv state
            parseOneBerValue tag content :: loop nextState

    loop { data = value; pos = 0 }

// ---------------------------------------------------------------------------
// Top-level parser
// ---------------------------------------------------------------------------

let parseBer (data : byte array) : BerValue =
    let state = { data = data; pos = 0 }
    let tag, value, _ = parseTlv state
    // APPLICATION tags (class 1) wrap SEQUENCE content — parse inner and unwrap
    match tag.tagClass = 1 with
    | true ->
        match parseConstructed value with
        | [v] -> v  // single inner value — return it directly
        | vs -> BerSequence vs
    | false ->
        parseUniversalValue tag value

// ---------------------------------------------------------------------------
// Convenience accessors
// ---------------------------------------------------------------------------

/// Structural converters — throw `ArgumentException` on mismatch.
/// Callers in Auth.fs are wrapped in `try...with` at the boundary (`getTgt`/`getServiceTicket`),
/// so these exceptions surface as `UnexpectedError` (not domain validation errors).
let asInteger (v : BerValue) : int =
    match v with
    | BerInteger n -> n
    | BerSequence [BerInteger n] -> n  // explicit context tag unwraps to SEQUENCE of one INTEGER
    | _ -> invalidArg "value" $"Expected BerInteger, got {v}"

let asOctetString (v : BerValue) : byte array =
    match v with
    | BerOctetString b -> b
    | BerSequence [BerOctetString b] -> b
    | _ -> invalidArg "value" $"Expected BerOctetString, got {v}"

let asGeneralString (v : BerValue) : string =
    match v with
    | BerGeneralString s -> s
    | BerSequence [BerGeneralString s] -> s
    | _ -> invalidArg "value" $"Expected BerGeneralString, got {v}"

let asGeneralizedTime (v : BerValue) : DateTime =
    match v with
    | BerGeneralizedTime dt -> dt
    | _ -> invalidArg "value" $"Expected BerGeneralizedTime, got {v}"

let asSequence (v : BerValue) : BerValue list =
    match v with
    | BerSequence items -> items
    | _ -> invalidArg "value" $"Expected BerSequence, got {v}"

let atIndex (items : BerValue list) (idx : int) : BerValue =
    List.item idx items

/// Find a context-tagged value by its tag number (handles optional fields correctly)
let contextAt (items : BerValue list) (tag : int) : BerValue option =
    items
    |> List.tryPick (fun item ->
        match item with
        | BerContext (n, v) when n = tag -> v |> Some
        | _ -> None)

let parseOctetStringContent (v : BerValue) : BerValue =
    v |> asOctetString |> parseBer

/// Get the top-level APPLICATION tag number
let applicationTag (data : byte array) : int =
    let tag, _ = parseTag { data = data; pos = 0 }
    tag.tagNumber

// ---------------------------------------------------------------------------
// Kerberos-specific decoders
// ---------------------------------------------------------------------------

/// Extract error code from KRB-ERROR fields [6].
let private extractErrorCodeContext (v : BerValue) : int =
    match v with
    | BerContext (_, inner) -> asInteger inner
    | _ -> asInteger v


let private extractErrorCode (fields : BerValue list) : int =
    match contextAt fields 6 with
    | Some v -> extractErrorCodeContext v
    | None -> -1


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


/// KRB-ERROR fields by context tag:
/// [0] pvno, [1] msg-type, [2] ctime (opt), [3] cusec (opt),
/// [4] stime, [5] susec, [6] error-code, [7] crealm (opt),
/// [8] cname (opt), [9] realm, [10] sname, [11] e-text (opt), [12] e-data (opt)
let decodeKrbError (data : byte array) : int * string option =
    try
        match parseBer data with
        | BerSequence fields -> extractErrorCode fields, extractErrorText fields
        | _ -> -1, None
    with _ ->
        -1, None


let isKrbError (data : byte array) : bool =
    applicationTag data = 30


let decodeKdcRep (data : byte array) : BerValue =
    parseBer data


/// Extract a GeneralString string from a BerValue.
let private toGeneralString (v : BerValue) : string option =
    match v with
    | BerGeneralString s -> Some s
    | _ -> None


/// Unwrap a context-tagged inner value from KDC-REP ticket field.
let private unwrapTicketInner (v : BerValue) : BerValue =
    match v with
    | BerContext (_, inner) -> inner
    | BerRaw b ->
        try parseBer b
        with _ -> BerSequence []
    | other -> other


/// Extract the ticket value from KDC-REP fields [5].
let private extractTicketValue (fields : BerValue list) : BerValue =
    match contextAt fields 5 with
    | Some v -> unwrapTicketInner v
    | None -> BerSequence []


/// GeneralString components of a PrincipalName name-string SEQUENCE.
let private extractSnStrings (ss : BerValue list) : string array =
    let asGeneralString str =
        match str with
        | BerGeneralString s -> Some s
        | _ -> None
    ss
    |> List.choose asGeneralString
    |> List.toArray


/// Extract sname parts from a PrincipalName BER structure.
let private extractSnameParts (snFields : BerValue list) : byte array =
    let snType =
        match contextAt snFields 0 with
        | Some v -> asInteger v
        | None -> 1
    let snStrs =
        match contextAt snFields 1 with
        | Some (BerSequence ss) -> extractSnStrings ss
        | _ -> [| "" |]
    Encoding.encodePrincipalName snType snStrs


/// Integer under a context tag, or a default when missing.
let private integerAtOr (fields : BerValue list) (tag : int) (defaultValue : int) : int =
    match contextAt fields tag with
    | Some v -> asInteger v
    | None -> defaultValue


/// GeneralString under a context tag, or empty when missing.
let private generalStringAtOrEmpty (fields : BerValue list) (tag : int) : string =
    match contextAt fields tag with
    | Some v -> asGeneralString v
    | None -> ""


/// OCTET STRING under a context tag, or empty when missing.
let private octetStringAtOrEmpty (fields : BerValue list) (tag : int) : byte array =
    match contextAt fields tag with
    | Some v -> asOctetString v
    | None -> [||]


/// Optional integer under a context tag.
let private integerAtOpt (fields : BerValue list) (tag : int) : int option =
    match contextAt fields tag with
    | Some v -> Some (asInteger v)
    | None -> None


/// Encode EncryptedData fields back to wire bytes.
let private encodeEncPartBytes (epFields : BerValue list) : byte array =
    Encoding.encodeEncryptedData
        (integerAtOr epFields 0 18)
        (integerAtOpt epFields 1)
        (octetStringAtOrEmpty epFields 2)


/// Encode a Ticket SEQUENCE back to wire format.
let private encodeTicketFromFields (ticketFields : BerValue list) : byte array =
    let tktVno = integerAtOr ticketFields 0 5
    let realmStr = generalStringAtOrEmpty ticketFields 1
    let snameVal = defaultArg (contextAt ticketFields 2) (BerSequence [])
    let encPartVal = defaultArg (contextAt ticketFields 3) (BerSequence [])

    let snameParts =
        match snameVal with
        | BerSequence snFields -> extractSnameParts snFields
        | _ -> Encoding.encodePrincipalName 1 [| "" |]

    let encPartBytes =
        match encPartVal with
        | BerSequence epFields -> encodeEncPartBytes epFields
        | _ -> invalidArg "value" "enc-part is not a sequence"

    Encoding.encodeTicket tktVno (Encoding.encodeRealm realmStr) snameParts encPartBytes


/// Extract the raw ticket bytes from KDC-REP.
/// Re-encodes the ticket from parsed BER values back to wire format.
let extractTicketBytes (rep : BerValue) : byte array =
    match rep with
    | BerSequence fields ->
        match extractTicketValue fields with
        | BerSequence ticketFields -> encodeTicketFromFields ticketFields
        | _ -> invalidArg "value" "Unexpected ticket format"
    | _ -> invalidArg "value" "Not a KDC-REP"


/// KDC-REP: [0] pvno, [1] msg-type, [2] padata (opt), [3] crealm,
/// [4] cname, [5] ticket, [6] enc-part
let extractEncPart (rep : BerValue) : BerValue =
    match rep with
    | BerSequence fields -> defaultArg (contextAt fields 6) (BerSequence [])
    | _ -> invalidArg "value" "Not a KDC-REP"


let extractEncPartCipher (rep : BerValue) : byte array =
    match extractEncPart rep with
    | BerSequence fields -> octetStringAtOrEmpty fields 2
    | _ -> invalidArg "value" "enc-part is not a sequence"


let extractEncPartEtype (rep : BerValue) : int =
    match extractEncPart rep with
    | BerSequence fields -> integerAtOr fields 0 18
    | _ -> invalidArg "value" "enc-part is not a sequence"


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


/// Try to parse an e-data field into a PA-DATA sequence.
let private tryParsePaDataSequence (v : BerValue) : BerValue list =
    match v with
    | BerOctetString b ->
        try parseBer b |> asSequence
        with _ -> []
    | BerSequence items -> items
    | _ -> []


/// KRB-ERROR: [12] e-data contains PA-DATA sequence
let extractPaDataFromError (data : byte array) : BerValue list =
    match parseBer data with
    | BerSequence fields ->
        match contextAt fields 12 with
        | Some v -> tryParsePaDataSequence v
        | None -> []
    | _ -> []


/// Extract a GeneralizedTime from a BerValue (handles context-wrapped values).
let private extractGeneralizedTimeValue (v : BerValue) : DateTime option =
    match v with
    | BerGeneralizedTime dt -> Some dt
    | BerContext (_, BerGeneralizedTime dt) -> Some dt
    | _ -> None


/// Extract stime [4] from KRB-ERROR for clock skew correction
let extractStimeFromKrbError (data : byte array) : DateTime option =
    try
        match parseBer data with
        | BerSequence fields ->
            match contextAt fields 4 with
            | None -> None
            | Some v -> extractGeneralizedTimeValue v
        | _ -> None
    with _ ->
        None
