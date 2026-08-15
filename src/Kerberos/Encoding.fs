/// Hand-rolled BER/DER encoder for Kerberos wire format (RFC 4120 / RFC 4506).
/// Kerberos uses BER encoding over UDP/TCP to port 88.
///
/// KEY RULE: All explicit context tags in Kerberos ASN.1 are CONSTRUCTED — they wrap inner tags.
module internal Fauli.Kerberos.Encoding

open System
open System.Text
open Fauli.Constants

// ---------------------------------------------------------------------------
// BER tag classes
// ---------------------------------------------------------------------------

type TagClass =
    | Universal = 0b00
    | Application = 0b01
    | Context = 0b10
    | Private = 0b11

type TagConstruction =
    | Primitive = 0uy
    | Constructed = 0x20uy  // bit 5 = 0x20 (32)

// ---------------------------------------------------------------------------
// Byte array helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Low-level BER encoding primitives
// ---------------------------------------------------------------------------

let private encodeTag (tagClass : TagClass) (construction : TagConstruction) (tagNumber : int) : byte array =
    match tagNumber < 31 with
    | true -> [| byte (int tagClass <<< 6) ||| byte construction ||| byte tagNumber |]
    | false ->
        let tagBytes = BitConverter.GetBytes tagNumber |> Array.rev
        let rec findStart (arr : byte array) idx =
            if idx < arr.Length - 1 && arr.[idx] = 0uy then findStart arr (idx + 1)
            else idx
        let startIdx = findStart tagBytes 0
        // Actual bytes
        Array.sub tagBytes startIdx (tagBytes.Length - startIdx)
        |> concat2 [| byte (int tagClass <<< 6) ||| byte construction ||| 0x1Fuy |]

let private encodeLength (len : int) : byte array =
    match len < 128 with
    | true -> [| byte len |]
    | false ->
        let lenBytes = BitConverter.GetBytes(uint32 len) |> Array.rev
        let rec findStart (arr : byte array) idx =
            if idx < arr.Length - 1 && arr.[idx] = 0uy then findStart arr (idx + 1)
            else idx
        let actualBytes = Array.sub lenBytes (findStart lenBytes 0) (lenBytes.Length - findStart lenBytes 0)
        concat2 [| byte (0x80 ||| actualBytes.Length) |] actualBytes

let encodeTlv (tagBytes : byte array) (value : byte array) : byte array =
    let lenBytes = encodeLength value.Length
    concatMany [| tagBytes; lenBytes; value |]

// ---------------------------------------------------------------------------
// BER type encoders
// ---------------------------------------------------------------------------

let encodeInteger (value : int) : byte array =
    let raw = BitConverter.GetBytes(value) |> Array.rev
    let rec stripLeading (arr : byte array) idx =
        match idx < arr.Length - 1 && arr.[idx] = 0uy with
        | true when (arr.[idx + 1] &&& 0x80uy) <> 0uy -> idx
        | true -> stripLeading arr (idx + 1)
        | false -> idx
    let tag = encodeTag TagClass.Universal TagConstruction.Primitive 2
    encodeTlv tag (Array.sub raw (stripLeading raw 0) (raw.Length - stripLeading raw 0))

let encodeGeneralString (value : string) : byte array =
    let bytes = Encoding.ASCII.GetBytes value
    let tag = encodeTag TagClass.Universal TagConstruction.Primitive 27
    encodeTlv tag bytes

let encodeOctetString (value : byte array) : byte array =
    let tag = encodeTag TagClass.Universal TagConstruction.Primitive 4
    encodeTlv tag value

let encodeBoolean (value : bool) : byte array =
    let bytes =
        match value with
        | true -> [| 0xFFuy |]
        | false -> [| 0x00uy |]
    let tag = encodeTag TagClass.Universal TagConstruction.Primitive 1
    encodeTlv tag bytes

let encodeSequence (children : byte array array) : byte array =
    let content = concatMany children
    let tag = encodeTag TagClass.Universal TagConstruction.Constructed 16
    encodeTlv tag content

let encodeSequenceOf (childEncoder : 'a -> byte array) (items : 'a array) : byte array =
    encodeSequence (Array.map childEncoder items)

/// Encode a BIT STRING with the given flag positions set.
/// BER convention: bit 0 is the MSB of the first octet.
/// Kerberos requires at least 32 bits (RFC 4120 §5.2.8).
let encodeBitString (flagPositions : int list) : byte array =
    // KerberosFlags ::= BIT STRING (SIZE (32..MAX))
    let byteCount =
        match flagPositions with
        | [] -> 4
        | flags -> max 4 ((List.max flags / 8) + 1)
    let bytes = Array.zeroCreate<byte> byteCount
    List.iter (fun pos ->
        bytes.[pos / 8] <- bytes.[pos / 8] ||| byte (1 <<< (7 - (pos % 8)))) flagPositions
    let content = concat2 [| 0x00uy |] bytes  // unused bits = 0
    let tag = encodeTag TagClass.Universal TagConstruction.Primitive 3
    encodeTlv tag content

let encodeGeneralizedTime (dt : DateTime) : byte array =
    let tag = encodeTag TagClass.Universal TagConstruction.Primitive 24
    let s = dt.ToUniversalTime().ToString("yyyyMMddHHmmssZ", System.Globalization.CultureInfo.InvariantCulture)
    encodeTlv tag (Encoding.ASCII.GetBytes s)

let encodeContextPrimitive (n : int) (value : byte array) : byte array =
    let tag = encodeTag TagClass.Context TagConstruction.Primitive n
    encodeTlv tag value

let encodeContextConstructed (n : int) (value : byte array) : byte array =
    let tag = encodeTag TagClass.Context TagConstruction.Constructed n
    encodeTlv tag value

let encodeApplicationConstructed (n : int) (content : byte array) : byte array =
    let tag = encodeTag TagClass.Application TagConstruction.Constructed n
    encodeTlv tag content

let encodeOptional (encoder : 'a -> byte array) (option : 'a option) : byte array =
    match option with
    | Some v -> encoder v
    | None -> [||]

// ---------------------------------------------------------------------------
// Kerberos-specific composite encoders
//
// All explicit context tags in Kerberos ASN.1 are CONSTRUCTED.
// They wrap inner tags (e.g., [0] INTEGER → 80 LL 02 LL value).
// ---------------------------------------------------------------------------

let encodePrincipalName (nameType : int) (nameString : string array) : byte array =
    encodeSequence
        [| encodeContextConstructed 0 (encodeInteger nameType)
           encodeContextConstructed 1 (encodeSequenceOf encodeGeneralString nameString) |]

let encodeRealm (realm : string) : byte array =
    encodeGeneralString realm

let encodeEncryptedData (etype : int) (kvno : int option) (cipher : byte array) : byte array =
    encodeSequence
        [| encodeContextConstructed 0 (encodeInteger etype)
           encodeOptional (fun v -> encodeContextConstructed 1 (encodeInteger v)) kvno
           encodeContextConstructed 2 (encodeOctetString cipher) |]

let encodeEncryptionKey (keyType : int) (keyValue : byte array) : byte array =
    encodeSequence
        [| encodeContextConstructed 0 (encodeInteger keyType)
           encodeContextConstructed 1 (encodeOctetString keyValue) |]

/// Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }
let encodeChecksum (cksumtype : int) (checksum : byte array) : byte array =
    encodeSequence
        [| encodeContextConstructed 0 (encodeInteger cksumtype)
           encodeContextConstructed 1 (encodeOctetString checksum) |]

/// RFC 4121 §4.1.1 GSS-API checksum body used inside Authenticator.cksum
/// (cksumtype 0x8003). Layout is little-endian:
///   Lgth (uint32=16) || Bnd (16 octets) || Flags (uint32)
let encodeGssApiChecksumBody (flags : uint32) : byte array =
    let lgth = BitConverter.GetBytes 16u
    let bnd = Array.zeroCreate<byte> 16
    let flagsBytes = BitConverter.GetBytes flags
    concatMany [| lgth; bnd; flagsBytes |]

let encodePaEncTsEnc (timestamp : DateTime) (usec : int option) : byte array =
    encodeSequence
        [| encodeContextConstructed 0 (encodeGeneralizedTime timestamp)
           encodeOptional (fun v -> encodeContextConstructed 1 (encodeInteger v)) usec |]

let encodePaPacRequest (includePac : bool) : byte array =
    encodeSequence [| encodeContextConstructed 0 (encodeBoolean includePac) |]

let encodePaData (padataType : int) (padataValue : byte array) : byte array =
    encodeSequence
        [| encodeContextConstructed 1 (encodeInteger padataType)
           encodeContextConstructed 2 (encodeOctetString padataValue) |]

/// KDC options: map option names to bit positions
let private kdcOptionMap =
    Map [ "forwardable", 1
          "forwarded", 2
          "proxiable", 3
          "proxy", 4
          "allow-postdate", 5
          "postdated", 6
          "renewable", 8
          "opt-hardware-auth", 11
          "constrained-delegation", 14
          "canonicalize", 15
          "request-anonymous", 16
          "disable-transited-check", 26
          "renewable-ok", 27
          "enc-tkt-in-skey", 28
          "renew", 30
          "validate", 31 ]

let encodeKdcOptions (options : string list) : byte array =
    options
    |> List.choose (fun opt -> Map.tryFind opt kdcOptionMap)
    |> encodeBitString

let encodeApOptions (options : string list) : byte array =
    options
    |> List.choose (fun opt ->
        match opt with
        | "use-session-key" -> Some 1
        | "mutual-required" -> Some 2
        | _ -> None)
    |> encodeBitString

/// Encode KDC-REQ-BODY per RFC 4120:
/// [0] kdc-options, [1] cname (opt), [2] realm, [3] sname (opt),
/// [4] from (opt), [5] till (opt), [6] rtime (opt), [7] nonce,
/// [8] etype, [9] addresses (opt), [10] enc-authorization-data (opt),
/// [11] additional-tickets (opt)
let encodeKdcReqBody
    kdcOptions cname realm sname till rtime nonce etype additionalTickets : byte array =
    encodeSequence
        [| encodeContextConstructed 0 kdcOptions
           Option.defaultValue [||] (Option.map (fun c -> encodeContextConstructed 1 c) cname)
           encodeContextConstructed 2 realm
           Option.defaultValue [||] (Option.map (fun s -> encodeContextConstructed 3 s) sname)
           encodeOptional (fun v -> encodeContextConstructed 5 (encodeGeneralizedTime v)) till
           encodeOptional (fun v -> encodeContextConstructed 6 (encodeGeneralizedTime v)) rtime
           encodeContextConstructed 7 (encodeInteger nonce)
           encodeContextConstructed 8 (encodeSequenceOf encodeInteger etype)
           Option.defaultValue [||] (Option.map (fun ticks ->
               encodeContextConstructed 11 (encodeSequence ticks)) additionalTickets) |]

/// Encode KDC-REQ (base for AS-REQ and TGS-REQ)
/// All EXPLICIT tags in Kerberos are constructed (wrap inner tag).
let encodeKdcReq (msgType : int) (padata : byte array array option) (reqBody : byte array) : byte array =
    encodeSequence
        [| encodeContextConstructed 1 (encodeInteger 5)
           encodeContextConstructed 2 (encodeInteger msgType)
           Option.defaultValue [||] (Option.map (fun pa ->
               encodeContextConstructed 3 (encodeSequence pa)) padata)
           encodeContextConstructed 4 reqBody |]

let encodeAsReq (kdcReq : byte array) : byte array =
    encodeApplicationConstructed 10 kdcReq

let encodeTgsReq (kdcReq : byte array) : byte array =
    encodeApplicationConstructed 12 kdcReq

/// Encode Ticket: [APPLICATION 1]
let encodeTicket tktVno realm sname encPart : byte array =
    let content =
        encodeSequence
            [| encodeContextConstructed 0 (encodeInteger tktVno)
               encodeContextConstructed 1 realm
               encodeContextConstructed 2 sname
               encodeContextConstructed 3 encPart |]
    encodeApplicationConstructed 1 content

/// Encode AP-REQ: [APPLICATION 14]
let encodeApReq apOptions ticket authenticator : byte array =
    let content =
        encodeSequence
            [| encodeContextConstructed 0 (encodeInteger 5)
               encodeContextConstructed 1 (encodeInteger 14)
               encodeContextConstructed 2 (encodeApOptions apOptions)
               encodeContextConstructed 3 ticket
               encodeContextConstructed 4 authenticator |]
    encodeApplicationConstructed 14 content

/// Encode Authenticator: [APPLICATION 2]
let encodeAuthenticator crealm cname cusec ctime cksum seqNumber : byte array =
    encodeApplicationConstructed 2
        (encodeSequence
            [| encodeContextConstructed 0 (encodeInteger 5)
               encodeContextConstructed 1 crealm
               encodeContextConstructed 2 cname
               Option.defaultValue [||] (Option.map (fun cs -> encodeContextConstructed 3 cs) cksum)
               encodeContextConstructed 4 (encodeInteger cusec)
               encodeContextConstructed 5 (encodeGeneralizedTime ctime)
               Option.defaultValue [||] (Option.map (fun v ->
                   encodeContextConstructed 7 (encodeInteger v)) seqNumber) |])
