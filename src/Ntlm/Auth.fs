module internal Fauli.Ntlm.Auth


open System
open System.Net.Sockets

open Fauli.Domain
open Fauli.Ntlm.Encoding
open Fauli.Ntlm.Crypto


///
/// Raw NTLMSSP message bytes.
type NtlmMessage = NtlmMessage of byte array


///
/// Parsed CHALLENGE_MESSAGE from the server.
type NtlmChallenge = NtlmChallenge of ChallengeMessage


///
/// Result of a successful NetNTLMv2 authentication.
type NtlmResult =
    { authResponse : NtlmAuthResponse
      userName : UserName
      domain : DomainName }


///
/// Append one read chunk into the accumulator when bytes were received.
let private appendChunkIfPresent (buffer : ResizeArray<byte>) (chunk : byte array) (bytesRead : int) : bool =
    match bytesRead > 0 with
    | false -> false
    | true ->
        Array.sub chunk 0 bytesRead
        |> Array.iter buffer.Add
        true


///
/// Drain the TCP stream into a byte array (read until EOF / zero-length read).
let private drainStream (stream : NetworkStream) : byte array =
    let buffer = ResizeArray<byte>()
    let chunk = Array.zeroCreate<byte> 4096
    let rec loop () =
        match appendChunkIfPresent buffer chunk (stream.Read(chunk, 0, chunk.Length)) with
        | true -> loop ()
        | false -> ()
    loop ()
    buffer.ToArray()


///
/// Send an NTLMSSP message over a TCP connection and read the server's response.
/// NTLMSSP messages are sent as raw bytes (no length prefix — the protocol
/// handler wraps them in SPNEGO or SMB negotiate).
/// 
let private sendNtlmMessage (client : TcpClient) (message : byte array) : byte array =
    let stream = client.GetStream()
    stream.Write(message, 0, message.Length)
    stream.Flush()
    drainStream stream


///
/// Build the NEGOTIATE_MESSAGE (Type 1).
let internal buildNegotiateMessage (domain : string option) (workstation : string option) : byte array =
    encodeNegotiateMessage domain workstation


///
/// Map challenge parse failures onto domain errors.
let private mapChallengeParseException (ex : exn) : AuthError =
    match ex with
    | :? ArgumentException -> NtlmChallengeFailed
    | _ -> UnexpectedError $"Failed to parse NTLM challenge: {ex.Message}"


///
/// Parse the server's CHALLENGE_MESSAGE (Type 2).
let internal parseChallenge (data : byte array) : Result<ChallengeMessage, AuthError> =
    try
        decodeChallengeMessage data |> Ok
    with ex ->
        (mapChallengeParseException ex) |> Error


///
/// Default workstation label when none was supplied.
let private defaultWorkstation (workstation : string option) : string =
    match workstation with
    | Some w -> w
    | None ->
        try Environment.MachineName
        with _ -> "WORKSTATION"


///
/// Build the AUTHENTICATE_MESSAGE (Type 3) from the computed response.
let internal buildAuthenticateMessage (negotiateFlags : uint32) (ntlmV2Resp : NtlmV2Response) (negotiateMsg : byte array) (challengeMsg : byte array) (domain : string) (username : string) (workstation : string) : byte array =
    let micPlaceholder = Array.zeroCreate<byte> 16
    let authMsg =
        encodeAuthenticateMessage
            negotiateFlags
            ntlmV2Resp.lmResponse
            ntlmV2Resp.ntResponse
            domain
            username
            workstation
            ntlmV2Resp.encryptedRandomSessionKey
            micPlaceholder
    let mic = computeMic ntlmV2Resp.exportedSessionKey negotiateMsg challengeMsg authMsg
    Array.Copy(mic, 0, authMsg, 72, 16)
    authMsg


///
/// Package Type-3 bytes into the domain NtlmResult.
let private packageNtlmResult (username : string) (domain : string) (authMsg : byte array) : NtlmResult =
    { authResponse = NtlmAuthResponse authMsg
      userName = UserName username
      domain = DomainName domain }


///
/// After a successful challenge parse: compute Type-3 and package the result.
let private completeNtlmV2AfterChallenge (password : string) (username : string) (domain : string) (workstation : string option) (negotiateMsg : byte array) (challengeData : byte array) (challenge : ChallengeMessage) : NtlmResult =
    let ntlmV2Resp = computeNtlmV2Response password username domain challenge
    let authMsg =
        buildAuthenticateMessage
            challenge.negotiateFlags
            ntlmV2Resp
            negotiateMsg
            challengeData
            domain
            username
            (defaultWorkstation workstation)
    packageNtlmResult username domain authMsg


///
/// Continue after challenge parse Result.
let private continueAfterChallenge (password : string) (username : string) (domain : string) (workstation : string option) (negotiateMsg : byte array) (challengeData : byte array) (challengeResult : Result<ChallengeMessage, AuthError>) : Result<NtlmResult, AuthError> =
    match challengeResult with
    | Error e -> e |> Error
    | Ok challenge ->
        completeNtlmV2AfterChallenge password username domain workstation negotiateMsg challengeData challenge
        |> Ok


///
/// Map transport failures onto domain errors.
let private mapNtlmTransportException (ex : exn) : AuthError =
    match ex with
    | :? SocketException -> ProtocolConnectionFailed
    | _ -> UnexpectedError $"NTLM authentication failed: {ex.Message}"


///
/// Perform the complete NetNTLMv2 three-message exchange over an existing TCP connection.
/// Returns the NTLM auth response that can be used by protocol handlers.
/// 
let internal authenticateWithNtlmV2 (client : TcpClient) (username : string) (password : string) (domain : string) (workstation : string option) : Result<NtlmResult, AuthError> =
    let negotiateMsg = buildNegotiateMessage (Some domain) workstation
    try
        let challengeData = sendNtlmMessage client negotiateMsg
        parseChallenge challengeData
        |> continueAfterChallenge password username domain workstation negotiateMsg challengeData
    with ex ->
        mapNtlmTransportException ex |> Error
