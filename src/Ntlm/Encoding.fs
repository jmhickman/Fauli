module internal Fauli.Ntlm.Encoding


open System
open System.Text



let private signature = Fauli.Constants.ntlmsspSignature  // "NTLMSSP\0"


///
/// Message type identifiers
let private ntLmNegotiate = 0x00000001


let private ntLmChallenge = 0x00000002


let private ntLmAuthenticate = 0x00000003


///
/// NTLMSSP negotiate flag constants per [MS-NLMP] §2.2.2.5.
module NtlmFlags =
    let NegotiateUnicode = 0x00000001u
    let NegotiateOem = 0x00000002u
    let RequestTarget = 0x00000080u
    let NegotiateDatagram = 0x00000010u
    let NegotiateSign = 0x00000020u
    let NegotiateSeal = 0x00000040u
    let NegotiateLmKey = 0x00000200u
    let NegotiateNtlm = 0x00000200u
    let NegotiateOemDomainSupplied = 0x00001000u
    let NegotiateOemWorkstationSupplied = 0x00002000u
    let NegotiateAlwaysSign = 0x00008000u
    let TargetTypeDomain = 0x00010000u
    let TargetTypeServer = 0x00020000u
    let NegotiateExtendedSessionSecurity = 0x00080000u
    let NegotiateIdentify = 0x00100000u
    let RequestNonNtSessionKey = 0x00400000u
    let NegotiateTargetInfo = 0x00800000u
    let NegotiateVersion = 0x02000000u
    let Negotiate128 = 0x20000000u
    let NegotiateKeyExch = 0x40000000u
    let Negotiate56 = 0x80000000u


///
/// Default negotiate flags for Fauli: Unicode, extended session security,
/// signing/sealing, key exchange, 128/56-bit encryption, target request.
/// 
let defaultNegotiateFlags : uint32 =
    NtlmFlags.NegotiateUnicode |||
    NtlmFlags.RequestTarget |||
    NtlmFlags.NegotiateSign |||
    NtlmFlags.NegotiateSeal |||
    NtlmFlags.NegotiateNtlm |||
    NtlmFlags.NegotiateAlwaysSign |||
    NtlmFlags.NegotiateExtendedSessionSecurity |||
    NtlmFlags.NegotiateTargetInfo |||
    NtlmFlags.NegotiateVersion |||
    NtlmFlags.NegotiateKeyExch |||
    NtlmFlags.Negotiate128 |||
    NtlmFlags.Negotiate56


type AvId =
    | MsvAvEOL = 0x0000
    | MsvAvNbComputerName = 0x0001
    | MsvAvNbDomainName = 0x0002
    | MsvAvDnsComputerName = 0x0003
    | MsvAvDnsDomainName = 0x0004
    | MsvAvDnsTreeName = 0x0005
    | MsvAvTimestamp = 0x0007
    | MsvAvSingleHost = 0x0008
    | MsvAvTargetName = 0x0009
    | MsvAvChannelBindings = 0x000A
    | MsvAvFlags = 0x000B


///
/// AV_PAIR: AvId (2 bytes LE) + AvLen (2 bytes LE) + Value (AvLen bytes).
type AvPair = { avId : AvId; value : byte array }


let private writeUint16Le (arr : byte array) (offset : int) (value : uint16) : unit =
    arr.[offset] <- byte (value &&& 0xFFus)
    arr.[offset + 1] <- byte ((value >>> 8) &&& 0xFFus)


let private writeUint32Le (arr : byte array) (offset : int) (value : uint32) : unit =
    arr.[offset] <- byte (value &&& 0xFFu)
    arr.[offset + 1] <- byte (value >>> 8 &&& 0xFFu)
    arr.[offset + 2] <- byte (value >>> 16 &&& 0xFFu)
    arr.[offset + 3] <- byte (value >>> 24 &&& 0xFFu)


let private readUint16Le (arr : byte array) (offset : int) : uint16 =
    uint16 arr.[offset] ||| (uint16 arr.[offset + 1] <<< 8)


let private readUint32Le (arr : byte array) (offset : int) : uint32 =
    uint32 arr.[offset] ||| (uint32 arr.[offset + 1] <<< 8) |||
    (uint32 arr.[offset + 2] <<< 16) ||| (uint32 arr.[offset + 3] <<< 24)


let private writeStringField (buffer : byte array) (fieldOffset : int) (payloadOffset : int) (strBytes : byte array) : unit = 
    writeUint16Le buffer fieldOffset (uint16 strBytes.Length)
    writeUint16Le buffer (fieldOffset + 2) (uint16 strBytes.Length)
    writeUint32Le buffer (fieldOffset + 4) (uint32 payloadOffset)


///
/// Encode a string to UTF-16LE bytes (no BOM).
let private toUtf16Le (s : string) : byte array =
    Encoding.Unicode.GetBytes s


///
/// Encode a string to OEM bytes.
let private toOem (s : string) : byte array =
    Encoding.Default.GetBytes s


///
/// Parse a sequence of AV_PAIR structures from the TargetInfo payload.
let private parseAvPairs (data : byte array) (offset : int) (len : int) : AvPair list =
    let buildAvPair data pos avId avLen =
        { avId = avId; value = Array.sub data (pos + 4) avLen }
    let rec loop pos acc =
        match pos + 4 > offset + len with
        | true -> List.rev acc
        | false ->
            let avId = enum<AvId> (int (readUint16Le data pos))
            let avLen = int (readUint16Le data (pos + 2))
            match avId = AvId.MsvAvEOL with
            | true -> List.rev acc
            | false ->
                let pair = buildAvPair data pos avId avLen
                loop (pos + 4 + avLen) (pair :: acc)
    loop offset []


///
/// Serialize AV_PAIR list (including MsvAvEOL terminator).
let internal encodeAvPairs (pairs : AvPair list) : byte array =
    let parts =
        pairs
        |> List.collect (fun p ->
            let id = uint16 (int p.avId)
            let len = uint16 p.value.Length
            let hdr = Array.zeroCreate<byte> 4
            writeUint16Le hdr 0 id
            writeUint16Le hdr 2 len
            [ hdr; p.value ])
    let eol = Array.zeroCreate<byte> 4  // MsvAvEOL id=0 len=0
    Array.concat (parts @ [ eol ])


///
/// Decode a UTF-16LE string from an AvPair value.
let avPairToString (pair : AvPair) : string =
    match pair.value.Length = 0 with
    | true -> ""
    | false -> Encoding.Unicode.GetString(pair.value)


///
/// Extract the TargetName AV_PAIR from the server's TargetInfo.
let extractTargetName (pairs : AvPair list) : string option =
    pairs
    |> List.tryPick (fun p ->
        match p.avId = AvId.MsvAvTargetName with
        | true -> Some (avPairToString p)
        | false -> None)


///
/// Extract the Timestamp AV_PAIR from the server's TargetInfo.
let extractTimestamp (pairs : AvPair list) : DateTime option =
    pairs
    |> List.tryPick (fun p ->
        match p.avId = AvId.MsvAvTimestamp && p.value.Length = 8 with
        | true ->
            let ticks = BitConverter.ToInt64(p.value, 0)
            try Some (DateTime.FromFileTime(ticks)) with _ -> None
        | false -> None)


///
/// Encode a NEGOTIATE_MESSAGE (Type 1).
/// If `domain` and `workstation` are provided, the corresponding flags are set
/// and the strings are appended to the payload.
/// 
let internal encodeNegotiateMessage
    (domain : string option)
    (workstation : string option)
    : byte array =
    let domainBytes, flags' =
        match domain with
        | Some d ->
            toOem d, defaultNegotiateFlags ||| NtlmFlags.NegotiateOemDomainSupplied
        | None -> [||], defaultNegotiateFlags
    let workstationBytes, flags'' =
        match workstation with
        | Some w ->
            toOem w, flags' ||| NtlmFlags.NegotiateOemWorkstationSupplied
        | None -> [||], flags'
    let flags = flags''
    let fixedSize = 48
    let buf = Array.zeroCreate<byte> (fixedSize + domainBytes.Length + workstationBytes.Length)
    Array.Copy(signature, buf, 8)
    writeUint32Le buf 8 (uint32 ntLmNegotiate)
    writeUint32Le buf 12 (uint32 flags)
    match domainBytes.Length > 0 with
    | true ->
        let domPayloadOffset = fixedSize
        writeStringField buf 16 domPayloadOffset domainBytes
    | false ->
        writeUint16Le buf 16 0us
        writeUint16Le buf 18 0us
        writeUint32Le buf 20 (uint32 fixedSize)
    match workstationBytes.Length > 0 with
    | true ->
        let wsPayloadOffset = fixedSize + domainBytes.Length
        writeStringField buf 24 wsPayloadOffset workstationBytes
    | false ->
        writeUint16Le buf 24 0us
        writeUint16Le buf 26 0us
        writeUint32Le buf 28 (uint32 fixedSize)
    match domainBytes.Length > 0, workstationBytes.Length > 0 with
    | true, true ->
        Array.Copy(domainBytes, 0, buf, fixedSize, domainBytes.Length)
        Array.Copy(workstationBytes, 0, buf, fixedSize + domainBytes.Length, workstationBytes.Length)
    | true, false ->
        Array.Copy(domainBytes, 0, buf, fixedSize, domainBytes.Length)
    | false, true ->
        Array.Copy(workstationBytes, 0, buf, fixedSize, workstationBytes.Length)
    | false, false -> ()
    buf


///
/// Parsed CHALLENGE_MESSAGE fields.
type ChallengeMessage =
    { targetName : string option
      negotiateFlags : uint32
      serverChallenge : byte array  // 8 bytes
      targetInfo : AvPair list }


///
/// Parse a CHALLENGE_MESSAGE (Type 2) from raw bytes.
/// Decode a target name string from raw bytes using the negotiated encoding.
/// 
let private decodeTargetNameString (negotiateFlags : uint32) (bytes : byte array) : string =
    match negotiateFlags &&& uint32 NtlmFlags.NegotiateUnicode <> 0u with
    | true -> Encoding.Unicode.GetString(bytes)
    | false -> Encoding.Default.GetString(bytes)


let internal decodeChallengeMessage (data : byte array) : ChallengeMessage =
    match data.Length < 40 with
    | true -> invalidArg "data" "CHALLENGE_MESSAGE too short"
    | false -> ()
    match data.[0..7] <> signature with
    | true -> invalidArg "data" "Invalid NTLMSSP signature"
    | false -> ()
    match readUint32Le data 8 <> uint32 ntLmChallenge with
    | true -> invalidArg "data" "Not a CHALLENGE_MESSAGE"
    | false -> ()
    let targetNameLen = int (readUint16Le data 12)
    let targetNameOffset = int (readUint32Le data 16)
    let negotiateFlags = readUint32Le data 20
    let serverChallenge = Array.sub data 24 8
    let targetInfoLen = int (readUint16Le data 40)
    let targetInfoOffset = int (readUint32Le data 44)
    let targetName =
        match targetNameLen > 0 with
        | true ->
            let bytes = Array.sub data targetNameOffset targetNameLen
            decodeTargetNameString negotiateFlags bytes |> Some
        | false ->
            None
    let targetInfo =
        match targetInfoLen > 0 with
        | true -> parseAvPairs data targetInfoOffset targetInfoLen
        | false -> []
    { targetName = targetName
      negotiateFlags = negotiateFlags
      serverChallenge = serverChallenge
      targetInfo = targetInfo }


///
/// Encode an AUTHENTICATE_MESSAGE (Type 3) for NetNTLMv2.
let internal encodeAuthenticateMessage (negotiateFlags : uint32) (lmResponse : byte array) (ntResponse : byte array) (domain : string) (username : string) (workstation : string) (encryptedRandomSessionKey : byte array) (mic : byte array) : byte array =
    let useUnicode = negotiateFlags &&& uint32 NtlmFlags.NegotiateUnicode <> 0u
    let encodeString (s : string) : byte array =
        match useUnicode with
        | true -> toUtf16Le s
        | false -> toOem s
    let domainBytes = encodeString domain
    let userBytes = encodeString username
    let wsBytes = encodeString workstation
    let encKey = encryptedRandomSessionKey
    let fixedSize = 88
    let totalSize =
        fixedSize + lmResponse.Length + ntResponse.Length + domainBytes.Length
        + userBytes.Length + wsBytes.Length + encKey.Length
    let buf = Array.zeroCreate<byte> totalSize
    Array.Copy(signature, buf, 8)
    writeUint32Le buf 8 (uint32 ntLmAuthenticate)
    let lmPayloadOffset = fixedSize
    writeStringField buf 12 lmPayloadOffset lmResponse
    let ntPayloadOffset = lmPayloadOffset + lmResponse.Length
    writeStringField buf 20 ntPayloadOffset ntResponse
    let domPayloadOffset = ntPayloadOffset + ntResponse.Length
    writeStringField buf 28 domPayloadOffset domainBytes
    let userPayloadOffset = domPayloadOffset + domainBytes.Length
    writeStringField buf 36 userPayloadOffset userBytes
    let wsPayloadOffset = userPayloadOffset + userBytes.Length
    writeStringField buf 44 wsPayloadOffset wsBytes
    let encPayloadOffset = wsPayloadOffset + wsBytes.Length
    writeStringField buf 52 encPayloadOffset encKey
    writeUint32Le buf 60 negotiateFlags
    Array.Copy(mic, 0, buf, 72, min 16 mic.Length)
    Array.Copy(lmResponse, 0, buf, lmPayloadOffset, lmResponse.Length)
    Array.Copy(ntResponse, 0, buf, ntPayloadOffset, ntResponse.Length)
    Array.Copy(domainBytes, 0, buf, domPayloadOffset, domainBytes.Length)
    Array.Copy(userBytes, 0, buf, userPayloadOffset, userBytes.Length)
    Array.Copy(wsBytes, 0, buf, wsPayloadOffset, wsBytes.Length)
    if encKey.Length > 0 then
        Array.Copy(encKey, 0, buf, encPayloadOffset, encKey.Length)
    buf


///
/// Parsed NEGOTIATE_MESSAGE fields.
type NegotiateMessage =
    { negotiateFlags : uint32
      domainName : string option
      workstation : string option }


///
/// Parse a NEGOTIATE_MESSAGE (Type 1) from raw bytes.
let internal decodeNegotiateMessage (data : byte array) : NegotiateMessage =
    match data.Length < 32 with
    | true -> invalidArg "data" "NEGOTIATE_MESSAGE too short"
    | false -> ()
    match data.[0..7] <> signature with
    | true -> invalidArg "data" "Invalid NTLMSSP signature"
    | false -> ()
    match readUint32Le data 8 <> uint32 ntLmNegotiate with
    | true -> invalidArg "data" "Not a NEGOTIATE_MESSAGE"
    | false -> ()
    let negotiateFlags = readUint32Le data 12
    let domainLen = int (readUint16Le data 16)
    let domainOffset = int (readUint32Le data 20)
    let wsLen = int (readUint16Le data 24)
    let wsOffset = int (readUint32Le data 28)
    let domainName =
        match domainLen > 0 with
        | true -> Encoding.Default.GetString(Array.sub data domainOffset domainLen) |> Some
        | false -> None
    let workstation =
        match wsLen > 0 with
        | true -> Encoding.Default.GetString(Array.sub data wsOffset wsLen) |> Some
        | false -> None
    { negotiateFlags = negotiateFlags
      domainName = domainName
      workstation = workstation }
