module internal Fauli.Ntlm.Encoding


open System
open System.Text

open Fauli.Domain


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


///
/// Parsed CHALLENGE_MESSAGE fields.
type ChallengeMessage =
    { targetName : string option
      negotiateFlags : uint32
      serverChallenge : byte array  // 8 bytes
      targetInfo : AvPair list }


type DecodeChallengeMessage = byte array -> Result<ChallengeMessage, AuthError>


type private ChallengeParseState =
    { data : byte array
      negotiateFlags : uint32
      serverChallenge : byte array
      targetName : string option
      targetInfo : AvPair list }


///
/// AUTHENTICATE_MESSAGE (Type 3) fields to encode.
type AuthenticateMessage =
    { negotiateFlags : uint32
      lmResponse : byte array
      ntResponse : byte array
      domain : string
      username : string
      workstation : string
      encryptedRandomSessionKey : byte array
      mic : byte array }


type EncodeAuthenticateMessage = AuthenticateMessage -> byte array


///
/// One Type-3 payload and the offset of its 8-byte security buffer ([MS-NLMP] §2.2.1.3).
type private AuthenticateField =
    { securityBufferOffset : int
      payload : byte array }


let private signature = Fauli.Constants.ntlmsspSignature  // "NTLMSSP\0"


///
/// Message type identifiers
let private ntLmNegotiate = 0x00000001


let private ntLmChallenge = 0x00000002


let private ntLmAuthenticate = 0x00000003


let private authenticateHeaderLength = 88


let private authenticateFlagsOffset = 60


let private authenticateMicOffset = 72


///
/// Minimum CHALLENGE_MESSAGE size: TargetInfoFields occupy offsets 40–47 ([MS-NLMP] §2.2.1.2).
let private challengeHeaderLength = 48


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


let private writeUint16Le (arr : byte array) (offset : int) (value : uint16) : unit =
    arr.[offset] <- byte (value &&& 0xFFus)
    arr.[offset + 1] <- byte (value >>> 8 &&& 0xFFus)


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


///
/// Write an MS-NLMP security buffer (Len, MaxLen, BufferOffset).
let private writeSecurityBuffer (buffer : byte array) (fieldOffset : int) (payloadOffset : int) (payload : byte array) : unit =
    writeUint16Le buffer fieldOffset (uint16 payload.Length)
    writeUint16Le buffer (fieldOffset + 2) (uint16 payload.Length)
    writeUint32Le buffer (fieldOffset + 4) (uint32 payloadOffset)


///
/// Encode a string to UTF-16LE bytes
let private toUtf16Le (s : string) : byte array =
    Encoding.Unicode.GetBytes s


///
/// Encode a string to OEM bytes.
let private toOem (s : string) : byte array =
    Encoding.Default.GetBytes s


///
/// Parse a sequence of AV_PAIR structures from the TargetInfo payload.
let private parseAvPairs (data : byte array) (offset : int) (len : int) : Result<AvPair list, AuthError> =
    let windowEnd = offset + len
    let rec loop pos acc =
        match pos + 4 > windowEnd with
        | true -> List.rev acc |> Ok
        | false ->
            let avId = enum<AvId> (int (readUint16Le data pos))
            let avLen = int (readUint16Le data (pos + 2))
            match avId = AvId.MsvAvEOL with
            | true -> List.rev acc |> Ok
            | false when avLen < 0 || pos + 4 + avLen > windowEnd ->
                NtlmChallengeFailed |> Error
            | false ->
                let pair = { avId = avId; value = Array.sub data (pos + 4) avLen }
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
            [ hdr; p.value ])  // MsvAvEOL id=0 len=0
    Array.concat (parts @ [ Array.zeroCreate<byte> 4 ])


///
/// Decode a UTF-16LE string from an AvPair value.
let avPairToString (pair : AvPair) : string =
    match pair.value.Length = 0 with
    | true -> ""
    | false -> Encoding.Unicode.GetString pair.value


///
/// Extract the TargetName AV_PAIR from the server's TargetInfo.
let extractTargetName (pairs : AvPair list) : string option =
    pairs
    |> List.tryPick (fun p ->
        match p.avId = AvId.MsvAvTargetName with
        | true ->  avPairToString p |> Some
        | false -> None)


///
/// Extract the Timestamp AV_PAIR from the server's TargetInfo.
let extractTimestamp (pairs : AvPair list) : DateTime option =
    pairs
    |> List.tryPick (fun p ->
        match p.avId = AvId.MsvAvTimestamp && p.value.Length = 8 with
        | true ->
            let ticks = BitConverter.ToInt64(p.value, 0)
            try Some (DateTime.FromFileTime ticks) with _ -> None
        | false -> None)


///
/// Encode a NEGOTIATE_MESSAGE (Type 1).
/// If `domain` and `workstation` are provided, the corresponding flags are set
/// and the strings are appended to the payload.
/// 
let internal encodeNegotiateMessage (domain : string option) (workstation : string option) : byte array =
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
        writeSecurityBuffer buf 16 domPayloadOffset domainBytes
    | false ->
        writeUint16Le buf 16 0us
        writeUint16Le buf 18 0us
        writeUint32Le buf 20 (uint32 fixedSize)
    
    match workstationBytes.Length > 0 with
    | true ->
        let wsPayloadOffset = fixedSize + domainBytes.Length
        writeSecurityBuffer buf 24 wsPayloadOffset workstationBytes
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
/// Decode a target name string from raw bytes using the negotiated encoding.
let private decodeTargetNameString (negotiateFlags : uint32) (bytes : byte array) : string =
    match negotiateFlags &&& uint32 NtlmFlags.NegotiateUnicode <> 0u with
    | true -> Encoding.Unicode.GetString bytes
    | false -> Encoding.Default.GetString bytes


///
/// Reject a buffer that cannot hold the CHALLENGE_MESSAGE header.
let private requireChallengeHeader (data : byte array) : Result<byte array, AuthError> =
    match data.Length < challengeHeaderLength with
    | true -> NtlmChallengeFailed |> Error
    | false -> data |> Ok


///
/// Reject a buffer that does not start with the NTLMSSP signature.
let private requireNtlmsspSignature (header : Result<byte array, AuthError>) : Result<byte array, AuthError> =
    match header with
    | Error e -> e |> Error
    | Ok data ->
        match data.[0..7] <> signature with
        | true -> NtlmChallengeFailed |> Error
        | false -> data |> Ok


///
/// Reject a buffer whose MessageType is not CHALLENGE_MESSAGE.
let private requireChallengeMessageType (header : Result<byte array, AuthError>) : Result<byte array, AuthError> =
    match header with
    | Error e -> e |> Error
    | Ok data ->
        match readUint32Le data 8 <> uint32 ntLmChallenge with
        | true -> NtlmChallengeFailed |> Error
        | false -> data |> Ok


///
/// Slice a payload field, or fail when the declared offset/length overruns the buffer.
let private trySlicePayload (data : byte array) (offset : int) (len : int) : Result<byte array, AuthError> =
    match offset < 0 || len < 0 || offset > data.Length || len > data.Length - offset with
    | true -> NtlmChallengeFailed |> Error
    | false -> Array.sub data offset len |> Ok


///
/// Capture the fixed-size CHALLENGE_MESSAGE fields.
let private readFixedChallengeFields (header : Result<byte array, AuthError>) : Result<ChallengeParseState, AuthError> =
    match header with
    | Error e -> e |> Error
    | Ok data ->
        { data = data
          negotiateFlags = readUint32Le data 20
          serverChallenge = Array.sub data 24 8
          targetName = None
          targetInfo = [] }
        |> Ok


///
/// Decode a present TargetName security buffer into the parse state.
let private targetNameFromSlice (state : ChallengeParseState) (slice : Result<byte array, AuthError>) : Result<ChallengeParseState, AuthError> =
    match slice with
    | Error e -> e |> Error
    | Ok bytes ->
        { state with targetName = decodeTargetNameString state.negotiateFlags bytes |> Some } |> Ok


///
/// Attach TargetName when the security buffer is present and in range.
let private readTargetName (stateResult : Result<ChallengeParseState, AuthError>) : Result<ChallengeParseState, AuthError> =
    match stateResult with
    | Error e -> e |> Error
    | Ok state ->
        let len = int (readUint16Le state.data 12)
        let offset = int (readUint32Le state.data 16)
        
        match len > 0 with
        | false -> { state with targetName = None } |> Ok
        | true -> trySlicePayload state.data offset len |> targetNameFromSlice state


///
/// Attach parsed AV_PAIRs to the parse state.
let private targetInfoFromPairs (state : ChallengeParseState) (pairsResult : Result<AvPair list, AuthError>) : Result<ChallengeParseState, AuthError> =
    match pairsResult with
    | Error e -> e |> Error
    | Ok pairs -> { state with targetInfo = pairs } |> Ok


///
/// Parse TargetInfo from a bounds-checked security buffer.
let private parseSlicedTargetInfo (state : ChallengeParseState) (offset : int) (len : int) (slice : Result<byte array, AuthError>) : Result<ChallengeParseState, AuthError> =
    match slice with
    | Error e -> e |> Error
    | Ok _ -> parseAvPairs state.data offset len |> targetInfoFromPairs state


///
/// Attach TargetInfo AV_PAIRs when the security buffer is present and in range.
let private readTargetInfo (stateResult : Result<ChallengeParseState, AuthError>) : Result<ChallengeParseState, AuthError> =
    match stateResult with
    | Error e -> e |> Error
    | Ok state ->
        let len = int (readUint16Le state.data 40)
        let offset = int (readUint32Le state.data 44)
        
        match len > 0 with
        | false -> { state with targetInfo = [] } |> Ok
        | true -> trySlicePayload state.data offset len |> parseSlicedTargetInfo state offset len


///
/// Project the parse state into the public CHALLENGE_MESSAGE record.
let private finishChallengeMessage (stateResult : Result<ChallengeParseState, AuthError>) : Result<ChallengeMessage, AuthError> =
    match stateResult with
    | Error e -> e |> Error
    | Ok state ->
        { targetName = state.targetName
          negotiateFlags = state.negotiateFlags
          serverChallenge = state.serverChallenge
          targetInfo = state.targetInfo }
        |> Ok


///
/// Parse a CHALLENGE_MESSAGE (Type 2) from raw bytes.
let internal decodeChallengeMessage : DecodeChallengeMessage = fun data ->
    data
    |> requireChallengeHeader
    |> requireNtlmsspSignature
    |> requireChallengeMessageType
    |> readFixedChallengeFields
    |> readTargetName
    |> readTargetInfo
    |> finishChallengeMessage


///
/// Encode a string with the encoding implied by NegotiateUnicode.
let private encodeAuthenticateString (negotiateFlags : uint32) (s : string) : byte array =
    match negotiateFlags &&& uint32 NtlmFlags.NegotiateUnicode <> 0u with
    | true -> toUtf16Le s
    | false -> toOem s


///
/// Type-3 payloads in wire order: LmResponse, NtResponse, Domain, User, Workstation, SessionKey.
let private authenticateFields (msg : AuthenticateMessage) : AuthenticateField list =
    [ { securityBufferOffset = 12; payload = msg.lmResponse }
      { securityBufferOffset = 20; payload = msg.ntResponse }
      { securityBufferOffset = 28; payload = encodeAuthenticateString msg.negotiateFlags msg.domain }
      { securityBufferOffset = 36; payload = encodeAuthenticateString msg.negotiateFlags msg.username }
      { securityBufferOffset = 44; payload = encodeAuthenticateString msg.negotiateFlags msg.workstation }
      { securityBufferOffset = 52; payload = msg.encryptedRandomSessionKey } ]


let private payloadBytesLength (fields : AuthenticateField list) : int =
    fields |> List.sumBy (fun field -> field.payload.Length)


///
/// Write one security buffer and its payload; return the next payload offset.
let private writeAuthenticateField (buf : byte array) (payloadOffset : int) (field : AuthenticateField) : int =
    writeSecurityBuffer buf field.securityBufferOffset payloadOffset field.payload
    Array.Copy(field.payload, 0, buf, payloadOffset, field.payload.Length)
    
    payloadOffset + field.payload.Length


///
/// Write signature, MessageType, NegotiateFlags, and MIC.
let private writeAuthenticateHeader (msg : AuthenticateMessage) (buf : byte array) : byte array =
    Array.Copy(signature, buf, 8)
    writeUint32Le buf 8 (uint32 ntLmAuthenticate)
    writeUint32Le buf authenticateFlagsOffset msg.negotiateFlags
    Array.Copy(msg.mic, 0, buf, authenticateMicOffset, min 16 msg.mic.Length)
    
    buf


///
/// Lay out every Type-3 payload after the fixed header.
let private writeAuthenticatePayloads (fields : AuthenticateField list) (buf : byte array) : byte array =
    fields
    |> List.fold (writeAuthenticateField buf) authenticateHeaderLength
    |> ignore
    
    buf


///
/// Encode an AUTHENTICATE_MESSAGE (Type 3) for NetNTLMv2.
let internal encodeAuthenticateMessage : EncodeAuthenticateMessage = fun msg ->
    let fields = authenticateFields msg
    Array.zeroCreate (authenticateHeaderLength + payloadBytesLength fields)
    |> writeAuthenticateHeader msg
    |> writeAuthenticatePayloads fields
