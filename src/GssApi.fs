module internal Fauli.GssApi


open System

open Fauli.Kerberos.Auth
open Fauli.Kerberos.Encryption
open Fauli.Kerberos.Parsing
open Fauli.Constants


let private concat2 (a : byte array) (b : byte array) : byte array =
    let result = Array.zeroCreate<byte> (a.Length + b.Length)
    Array.Copy(a, 0, result, 0, a.Length)
    Array.Copy(b, 0, result, a.Length, b.Length)
    result


let private concatMany (arrays : byte array array) : byte array =
    let result = Array.zeroCreate<byte> (arrays |> Array.sumBy Array.length)
    let rec copyLoop idx offset =
        match idx < arrays.Length with
        | false -> ()
        | true ->
            Array.Copy(arrays.[idx], 0, result, offset, arrays.[idx].Length)
            copyLoop (idx + 1) (offset + arrays.[idx].Length)
    copyLoop 0 0
    
    result


let private derTag (tagClass : int) (constructed : bool) (tagNumber : int) : byte array =
    let constructionBit = match constructed with | true -> 0x20 | false -> 0
    [| byte (tagClass <<< 6 ||| constructionBit ||| tagNumber) |]


let private derLength (len : int) : byte array =
    match len < 128 with
    | true -> [| byte len |]
    | false ->
        let bytes = BitConverter.GetBytes(uint32 len) |> Array.rev
        let rec skipLeadingZeros (arr : byte array) idx =
            match idx < arr.Length - 1 && arr.[idx] = 0uy with
            | true -> skipLeadingZeros arr (idx + 1)
            | false -> idx
        let start = skipLeadingZeros bytes 0
        let actual = Array.sub bytes start (bytes.Length - start)
        concat2 [| byte (0x80 ||| actual.Length) |] actual


let private derTlv (tag : byte array) (value : byte array) : byte array =
    concatMany [| tag; derLength value.Length; value |]


let private derSequence (content : byte array) : byte array =
    derTlv (derTag 0 true 0x10) content


let private derOctetString (content : byte array) : byte array =
    derTlv (derTag 0 false 0x04) content


///
/// Encode OID arc values as the bare OID *value* bytes (no tag/length).
/// Callers wrap with their own TLV when needed.
/// 
let private rawOidValue (oidStr : string) : byte array =
    let oid = new Security.Cryptography.Oid(oidStr)
    let components = oid.Value.Split('.') |> Array.map int
    
    let encodeValue (v : int) : byte array =
        let rec collect n acc =
            match n with
            | 0 -> acc
            | _ -> collect (n >>> 7) ((n &&& 0x7F) :: acc)
        let groups = collect v [] |> Array.ofList
        Array.init groups.Length (fun i ->
            match i < groups.Length - 1 with
            | true -> byte (0x80 ||| groups.[i])
            | false -> byte groups.[i])

    Array.concat [| [| byte (components.[0] * 40 + components.[1]) |]
                    components.[2..] |> Array.collect encodeValue |]


///
/// Kerberos mechanism OID: 1.2.840.113554.1.2.2
let private krb5Oid = rawOidValue krb5MechOid


///
/// MS Kerberos 5 OID (for SPNEGO mechTypes): 1.2.840.113554.1.2.2.1
let private msKrb5Oid = rawOidValue msKrb5MechOid


///
/// SPNEGO mechanism OID: 1.3.6.1.5.5.2
let private spnegoOid = rawOidValue snegoMechOid


///
/// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
let private ntlmOid = rawOidValue ntlmsspMechOid


///
/// Build a GSS-API InitContextToken wrapping the given AP-REQ.
/// This is the format expected by RFC 4121-aware acceptors.
/// 
let internal buildGssInitContextToken (apReq : byte array) : byte array =
    derSequence (concatMany 
        [| [| 0x01uy |]
           derOctetString (Array.zeroCreate<byte> 16)
           derOctetString apReq |])


///
/// Wrap a GSS-API token inside SPNEGO negTokenInit.
/// This is the format SMB, LDAP, HTTP Negotiate, and RPC expect.
/// 
let internal wrapSpnego (gssToken : byte array) : byte array =
    let mechTypesSet = derTlv (derTag 0 true 0x11) krb5Oid  // SET OF { krb5Oid }
    derSequence (concatMany [| mechTypesSet; derOctetString gssToken |])


///
/// Wrap NTLMSSP Type1 inside SPNEGO NegTokenInit (RFC 4178):
///   AID { SPNEGO_OID ; [0] SEQUENCE { [0] mechTypes{NTLM} ; [2] mechToken{Type1} } }
/// 
let internal wrapNtlmSpnego (ntlmType1 : byte array) : byte array =
    let aidTag = [| 0x60uy |]  // GSS-API AID
    let ctx0 = [| byte 0xA0uy |]
    let ctx2 = [| byte 0xA2uy |]
    let ntlmOidTlv = concatMany [| derTag 0 false 6; derLength ntlmOid.Length; ntlmOid |]
    let mechTypes = derTlv ctx0 (derSequence ntlmOidTlv)
    let mechToken = derTlv ctx2 (derOctetString ntlmType1)
    let negInit = derTlv ctx0 (derSequence (concatMany [| mechTypes; mechToken |]))
    let spnegoOidTlv = concatMany [| derTag 0 false 6; derLength spnegoOid.Length; spnegoOid |]
    let body = concatMany [| spnegoOidTlv; negInit |]
    
    concat2 aidTag (concat2 (derLength body.Length) body)


///
/// Wrap NTLMSSP Type3 inside SPNEGO NegTokenResp:
///   [1] SEQUENCE { [2] OCTET STRING { Type3 } }
/// 
let internal wrapNtlmNegTokenResp (ntlmType3 : byte array) : byte array =
    let ctx1 = [| byte 0xA1uy |]  // SPNEGO context [1]
    let ctx2 = [| byte 0xA2uy |]  // SPNEGO context [2]
    let respToken = derTlv ctx2 (derOctetString ntlmType3)
    derTlv ctx1 (derSequence respToken)


///
/// GSS-API response token (AP-REP or KRB-ERROR) extracted from a SPNEGO blob.
type GssResponseToken = GssResponseToken of byte array


///
/// Classification of a GSS response token: AP-REP, KRB-ERROR, or no response.
type GssNegotiationOutcome =
    | ApRep of GssResponseToken
    | KrbError of int
    | NoResponse


///
/// Final establishment result for SMB signing key material after SESSION_SETUP.
type SmbGssKeyEstablishment =
    | SessionKeyReady of byte array
    | KerberosRejected of int
    | ContextIncomplete


///
/// Build a SPNEGO NegTokenInit wrapping an AP-REQ (RFC 4178 + RFC 4121).
/// MechTypes list standard Kerberos first, then MS KRB5 — Windows-like ordering,
/// not the MS-KRB5-only profile common in some tooling.
/// 
let internal buildSpnegoToken (apReq : byte array) : byte array =
    let aidTag = [| 0x60uy |]  // GSS-API AID
    let ctx0Constructed = [| byte 0xA0uy |]
    let ctx2Constructed = [| byte 0xA2uy |]
    let krb5OidTlv = concatMany [| derTag 0 false 6; derLength krb5Oid.Length; krb5Oid |]
    let msKrb5OidTlv = concatMany [| derTag 0 false 6; derLength msKrb5Oid.Length; msKrb5Oid |]
    let mechTypeInner =
        derTlv ctx0Constructed (derSequence (concatMany [| krb5OidTlv; msKrb5OidTlv |]))
    let krb5ApReqMagic = [| 0x01uy; 0x00uy |]
    let gssContent = concatMany [| krb5OidTlv; krb5ApReqMagic; apReq |]
    let gssToken = concat2 aidTag (concat2 (derLength gssContent.Length) gssContent)
    let mechToken = derTlv ctx2Constructed (derOctetString gssToken)
    let negTokenInitPayload = derTlv ctx0Constructed (derSequence (concatMany [| mechTypeInner; mechToken |]))
    let spnegoOidTlv = concatMany [| derTag 0 false 6; derLength spnegoOid.Length; spnegoOid |]
    let gssApiHeader = concatMany [| spnegoOidTlv; negTokenInitPayload |]
    
    concat2 aidTag (concat2 (derLength gssApiHeader.Length) gssApiHeader)


///
/// SPNEGO negotiation state from the server's support byte.
type SnegoState =
    | AcceptCompleted  /// Authentication succeeded; mechToken contains the server's GSS-API token
    | RequestMic       /// Server requests a message integrity code (MIC)
    | NegotiateState   /// More negotiation rounds needed


///
/// Parse the 1-byte support field from negTokenResp.
/// RFC 4178: ENUMERATED { accept-completed(0), accept-incomplete(1), reject(2), request-mic(3) }
/// 
let private parseSnegoState (b : byte) : SnegoState =
    match b with
    | 0x00uy -> AcceptCompleted
    | 0x01uy -> NegotiateState   // accept-incomplete
    | 0x02uy -> NegotiateState   // reject — treated as non-success
    | 0x03uy -> RequestMic
    | 0xA0uy -> AcceptCompleted
    | 0xA1uy -> NegotiateState
    | 0xA2uy -> RequestMic
    | _ -> NegotiateState


///
/// Read a DER length at `offset`. Returns `(contentStart, contentLen)`.
/// Total: out-of-range / invalid long-form → None (no exceptions).
/// 
let private readDerLengthAt (data : byte array) (offset : int) : (int * int) option =
    match offset < data.Length with
    | false -> None
    | true ->
        let lenByte = data.[offset]
        let num = int (lenByte &&& 0x7Fuy)
        
        match lenByte &&& 0x80uy = 0uy, num > 0 && num <= 4 && offset + 1 + num <= data.Length with
        | true, _ ->
            Some (offset + 1, int lenByte)
        | false, false ->
            None
        | false, true ->
            match Array.sub data (offset + 1) num |> Array.fold (fun acc b -> (acc <<< 8) ||| int b) 0 with
            | len when len >= 0 -> Some (offset + 1 + num, len)
            | _ -> None


///
/// One TLV at `pos`: `(tag, content, nextPos)`.
let private readTlvAt (data : byte array) (pos : int) : (byte * byte array * int) option =
    match pos < data.Length, readDerLengthAt data (pos + 1) with
    | true, Some (contentStart, contentLen) when contentLen >= 0 && contentStart + contentLen <= data.Length ->
        Some (data.[pos], Array.sub data contentStart contentLen, contentStart + contentLen)
    | _ ->
        None


///
/// Extract OCTET STRING value bytes from a context-tagged field whose content is an OCTET STRING TLV.
let private unwrapOctetFromContextValue (value : byte array) : byte array option =
    match value.Length < 2, value.Length >= 1 && value.[0] = berOctetString with
    | true, _ ->
        None
    | false, false ->
        Some value
    | false, true ->
        match readDerLengthAt value 1 with
        | Some (start, len) when start + len <= value.Length -> Some (Array.sub value start len)
        | _ -> None


///
/// Slice content under a constructed tag when the buffer starts with that tag.
let private unwrapTaggedContent (expectedTag : byte) (data : byte array) : byte array =
    match data.Length > 0 && data.[0] = expectedTag, readDerLengthAt data 1 with
    | true, Some (s, l) when s + l <= data.Length -> Array.sub data s l
    | _ -> data


///
/// Unwrap outer NegTokenResp context [0] or [1] when present (RFC 4178).
let private unwrapOuterNegTokenContext (data : byte array) : byte array =
    match data.Length > 0, data.Length > 0 && (data.[0] = 0xA0uy || data.[0] = 0xA1uy) with
    | true, true -> unwrapTaggedContent data.[0] data
    | _ -> data


///
/// Unwrap SEQUENCE body when present.
let private unwrapSequenceBody (data : byte array) : byte array =
    unwrapTaggedContent berSequence data


///
/// Accumulated fields from a negTokenResp SEQUENCE walk.
type private NegTokenRespFields =
    { negStateByte : byte option
      responseToken : byte array option }


let private emptyNegTokenRespFields : NegTokenRespFields =
    { negStateByte = None
      responseToken = None }


///
/// True when content is a BER ENUMERATED (tag 0x0A) carrying the negState value.
let private isEnumeratedContent (value : byte array) : bool =
    value.Length >= 2 && value.[0] = 0x0Auy


///
/// ENUMERATED payload byte (last content octet per DER small enums).
let private enumeratedValueByte (value : byte array) : byte =
    value.[value.Length - 1]


///
/// Apply one negTokenResp SEQUENCE field (RFC 4178 §4.2.2).
///   [0] negState ENUMERATED
///   [1] supportedMech OID (ignored here)
///   [2] responseToken OCTET STRING
///   [3] mechListMIC OCTET STRING (ignored here)
/// 
let private applyNegTokenRespField (fields : NegTokenRespFields) (tag : byte) (value : byte array) : NegTokenRespFields =
    match tag with
    | 0xA0uy when isEnumeratedContent value ->
        { fields with negStateByte = Some (enumeratedValueByte value) }
    | 0xA2uy ->
        { fields with responseToken = unwrapOctetFromContextValue value }
    | _ ->
        fields


///
/// Walk the negTokenResp SEQUENCE body and collect negState + responseToken.
let private collectNegTokenRespFields (seqBody : byte array) : NegTokenRespFields =
    let rec loop pos fields =
        match readTlvAt seqBody pos with
        | None -> fields
        | Some (tag, value, next) ->
            loop next (applyNegTokenRespField fields tag value)
    loop 0 emptyNegTokenRespFields


///
/// Map optional support byte onto SnegoState.
let private snegoStateFromFields (fields : NegTokenRespFields) : SnegoState =
    match fields.negStateByte with
    | Some b -> parseSnegoState b
    | None -> NegotiateState


///
/// Structural parse of a SPNEGO NegTokenResp body (after outer unwraps).
let private parseNegTokenRespBody (seqBody : byte array) : SnegoState * byte array option =
    let fields = collectNegTokenRespFields seqBody
    snegoStateFromFields fields, fields.responseToken


///
/// Parse a SPNEGO negTokenResp and extract the negotiation state and responseToken.
/// Handles the common SMB / LDAP form (RFC 4178):
///   [1] IMPLICIT SEQUENCE {
///         [0] ENUMERATED negState OPTIONAL,
///         [1] OID supportedMech OPTIONAL,
///         [2] OCTET STRING responseToken OPTIONAL,
///         [3] OCTET STRING mechListMIC OPTIONAL
///       }
/// Total function: malformed input yields NegotiateState * None (no exceptions).
/// 
let internal parseSnegoNegTokenResp (data : byte array) : SnegoState * byte array option =
    match data.Length < 2 with
    | true -> NegotiateState, None
    | false ->
        data
        |> unwrapOuterNegTokenContext
        |> unwrapSequenceBody
        |> parseNegTokenRespBody


///
/// Extract the raw responseToken bytes from a (possibly already parsed) negTokenResp mechToken.
/// The value passed here is usually the inner of the [2] context (the OCTET STRING value after tag+len).
/// 
let internal extractResponseToken (mechTokenValue : byte array) : byte array option =
    match mechTokenValue.Length < 2 with
    | true -> None
    | false when mechTokenValue.[0] <> berOctetString ->
        Some mechTokenValue
    | false ->
        match readDerLengthAt mechTokenValue 1 with
        | Some (start, len) when start + len <= mechTokenValue.Length ->
            Some (Array.sub mechTokenValue start len)
        | _ -> None


///
/// Strip outer wrappers and return AP-REP bytes suitable for BER parse + decrypt.
let private sliceFromIndex (gssToken : byte array) (i : int) : byte array =
    Array.sub gssToken i (gssToken.Length - i)


///
/// Locate AP-REP (0x6F) or SEQUENCE (0x30) after a GSS wrapper OID.
let private findApRepOffsetAfterOid (gssToken : byte array) : int option =
    let findFrom = min 15 (gssToken.Length - 2)
    let isApRepOrSequence i =
        gssToken.[i] = 0x6Fuy || gssToken.[i] = berSequence
    [ findFrom .. gssToken.Length - 1 ]
    |> List.tryFind isApRepOrSequence


///
/// Last-resort: scan for APPLICATION 15 AP-REP tag.
let private findApRepByScan (gssToken : byte array) : byte array option =
    match Array.tryFindIndex (fun b -> b = 0x6Fuy) gssToken with
    | Some i -> Some (sliceFromIndex gssToken i)
    | None -> Some gssToken


let internal stripGssApRepWrapper (gssToken : byte array) : byte array option =
    match gssToken.Length < 2 with
    | true -> None
    | false ->
        match gssToken.[0] with
        | 0x6Fuy -> Some gssToken  // APPLICATION 15 = AP-REP
        | 0x30uy -> Some gssToken  // SEQUENCE
        | 0x60uy ->
            match findApRepOffsetAfterOid gssToken with
            | Some i -> Some (sliceFromIndex gssToken i)
            | None -> None
        | _ -> findApRepByScan gssToken


///
/// Prefer a raw AP-REP token; otherwise unwrap nested response tokens.
let private apRepFromMechToken (mt : byte array) : byte array option =
    match mt.Length > 0 && mt.[0] = 0x6Fuy with
    | true -> Some mt
    | false ->
        match extractResponseToken mt with
        | None -> None
        | Some respTok -> stripGssApRepWrapper respTok


///
/// High-level: given a full security blob from SESSION_SETUP response (NegTokenResp),
/// extract the inner AP_REP token bytes.
/// 
let internal extractApRepToken (blob : byte array) : byte array option =
    let _, mechTokenOpt = parseSnegoNegTokenResp blob
    match mechTokenOpt with
    | None -> None
    | Some mt -> apRepFromMechToken mt


///
/// OCTET STRING payload when the value is (or unwraps to) one.
let rec private tryAsOctetString (v : BerValue) : byte array option =
    match v with
    | BerOctetString b -> Some b
    | BerContext (_, inner) -> tryAsOctetString inner
    | BerSequence [ inner ] -> tryAsOctetString inner
    | _ -> None


///
/// SEQUENCE fields when the value is (or unwraps to) a SEQUENCE.
let rec private tryAsSequenceFields (v : BerValue) : BerValue list option =
    match v with
    | BerSequence fields -> Some fields
    | BerContext (_, inner) -> tryAsSequenceFields inner
    | _ -> None


///
/// EncryptedData.cipher [2] and etype [0] from an EncryptedData value.
let private encryptedDataEtypeAndCipher (encPart : BerValue) : (int * byte array) option =
    match tryAsSequenceFields encPart with
    | None -> None
    | Some fields ->
        let etype =
            match contextAt fields 0 with
            | Some v -> defaultArg (asInteger v) (int EncryptionType.AES256_CTS_HMAC_SHA1_96)
            | None -> int EncryptionType.AES256_CTS_HMAC_SHA1_96
        match contextAt fields 2 with
        | None -> None
        | Some cipherVal ->
            match tryAsOctetString cipherVal with
            | None -> None
            | Some cipher when cipher.Length = 0 -> None
            | Some cipher -> Some (etype, cipher)


///
/// AP-REP.enc-part [2] from a parsed AP-REP body.
let private apRepEncPart (apRep : BerValue) : BerValue option =
    match tryAsSequenceFields apRep with
    | None -> None
    | Some fields -> contextAt fields 2


///
/// Locate EncryptedData.cipher (+ etype) inside raw AP-REP bytes via structure.
let private locateApRepCipher (apRepBytes : byte array) : (int * byte array) option =
    match apRepEncPart (parseBer apRepBytes) with
    | None -> None
    | Some encPart -> encryptedDataEtypeAndCipher encPart


///
/// EncryptionKey.keyvalue [1] — the raw key octets.
let private encryptionKeyValue (key : BerValue) : byte array option =
    match tryAsSequenceFields key with
    | None -> tryAsOctetString key
    | Some fields ->
        match contextAt fields 1 with
        | None -> None
        | Some v -> tryAsOctetString v


///
/// EncAPRepPart.subkey [2] keyvalue, when present.
let private subkeyFromEncApRepPart (part : BerValue) : byte array option =
    match tryAsSequenceFields part with
    | None -> None
    | Some fields ->
        match contextAt fields 2 with
        | None -> None
        | Some subkey -> encryptionKeyValue subkey


///
/// Extract optional subkey from decrypted EncAPRepPart plaintext.
let private findSubkeyInPlaintext (plain : byte array) : byte array option =
    subkeyFromEncApRepPart (parseBer plain)


///
/// Wrap optional AP-REP bytes as a GSS response token.
let private extractGssToken (blob : byte array) : GssResponseToken option =
    match extractApRepToken blob with
    | None -> None
    | Some bytes -> Some (GssResponseToken bytes)


///
/// Heuristic: treat tokens carrying KRB-ERROR markers as errors.
let private classifyGssToken (GssResponseToken bytes) : GssNegotiationOutcome =
    let prefix = Array.take (min 20 bytes.Length) bytes
    let hasErrorCode =
        bytes.Length > 10
        && (bytes.[5] = 0x1Euy
            || bytes.[11] = 0x1Euy
            || Array.exists ((=) 0x1Euy) prefix)
    match hasErrorCode with
    | true -> KrbError 60
    | false -> ApRep (GssResponseToken bytes)


let private truncateToSmbKey (keyBytes : byte array) : byte array =
    Array.sub keyBytes 0 (min 16 keyBytes.Length)


let private tryDecryptEncApRepPart (keyBytes : byte array) (etype : int) (cipher : byte array) : byte array option =
    match decrypt { enctype = enum<EncryptionType> etype; contents = keyBytes } KeyUsage.ApRepEncPart cipher with
    | Ok plain when plain.Length > 8 -> Some plain
    | _ -> None


///
/// Accept only subkeys that are at least 16 bytes (SMB signing material floor).
let private acceptSubkey (sk : byte array) : byte array option =
    match sk.Length >= 16 with
    | true -> Some sk
    | false -> None


let private decryptWithTicketKey (keyBytes : byte array) (etype : int, cipher : byte array) : byte array option =
    tryDecryptEncApRepPart keyBytes etype cipher


let private extractSubkeyFromApRep (apRepBytes : byte array) (keyBytes : byte array) : byte array option =
    apRepBytes
    |> locateApRepCipher
    |> Option.bind (decryptWithTicketKey keyBytes)
    |> Option.bind findSubkeyInPlaintext
    |> Option.bind acceptSubkey


let private establishSmbGssKey (keyBytes : byte array) (outcome : GssNegotiationOutcome) : SmbGssKeyEstablishment =
    match outcome with
    | ApRep (GssResponseToken apRepBytes) ->
        match extractSubkeyFromApRep apRepBytes keyBytes with
        | Some sk -> SessionKeyReady sk
        | None -> SessionKeyReady (truncateToSmbKey keyBytes)
    | KrbError code -> KerberosRejected code
    | NoResponse -> ContextIncomplete


let private classifyBlobOutcome (blob : byte array) : GssNegotiationOutcome =
    match extractGssToken blob with
    | None -> NoResponse
    | Some t -> classifyGssToken t


///
/// Process a SESSION_SETUP response blob (AP-REP or KRB-ERROR).
/// Returns typed establishment result so callers cannot treat KRB-ERROR as success.
/// ticketSessionKey must be the FULL service ticket session key (32 bytes for AES256).
/// 
let internal processApRepForSmbKey (blob : byte array) (ticketSessionKey : byte array) : SmbGssKeyEstablishment =
    blob
    |> classifyBlobOutcome
    |> establishSmbGssKey ticketSessionKey
