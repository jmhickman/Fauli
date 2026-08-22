module internal Fauli.Ntlm.Crypto


open System
open System.Security.Cryptography
open System.Text

open Fauli.Kerberos.Encryption
open Fauli.Ntlm.Encoding


///
/// Result of computing the NetNTLMv2 response.
type NtlmV2Response =
    { lmResponse : byte array
      ntResponse : byte array
      exportedSessionKey : byte array
      encryptedRandomSessionKey : byte array }


///
/// MsvAvFlags = 0x00000002: authentication MIC is present ([MS-NLMP] §2.2.2.1).
let private micPresentFlag : AvPair =
    { avId = AvId.MsvAvFlags; value = BitConverter.GetBytes 0x00000002u }


///
/// Concatenate two byte arrays.
let private concat2 (a : byte array) (b : byte array) : byte array =
    let result = Array.zeroCreate<byte> (a.Length + b.Length)
    Array.Copy(a, 0, result, 0, a.Length)
    Array.Copy(b, 0, result, a.Length, b.Length)
    result


///
/// Concatenate multiple byte arrays.
let private concatMany (arrays : byte array array) : byte array =
    let totalLen = Array.sumBy Array.length arrays
    let result = Array.zeroCreate<byte> totalLen
    
    let rec copyLoop idx offset =
        if idx < arrays.Length then
            Array.Copy(arrays.[idx], 0, result, offset, arrays.[idx].Length)
            copyLoop (idx + 1) (offset + arrays.[idx].Length)
    copyLoop 0 0
    
    result


///
/// Compute the NT-Hash.
let internal computeNtHash (password : string) : byte array =
    md4 (Encoding.Unicode.GetBytes password)


///
/// Compute the NTLMv2 response key
let internal computeNtlmV2Hash (ntHash : byte array) (username : string) (domain : string) : byte array =
    use hmac = new HMACMD5(ntHash)
    let identity =
        concat2
            (Encoding.Unicode.GetBytes (username.ToUpperInvariant()))
            (Encoding.Unicode.GetBytes domain)
    hmac.ComputeHash identity


///
/// FILETIME for the client blob: prefer the server's MsvAvTimestamp, else now.
let private clientBlobTimestamp (serverTimestamp : DateTime option) : byte array =
    match serverTimestamp with
    | Some ts -> ts.ToFileTime()
    | None -> DateTime.UtcNow.ToFileTime()
    |> BitConverter.GetBytes


///
/// Drop EOL (re-emitted by encodeAvPairs) and any server MsvAvFlags we will replace.
let private isRetainedAvPair (pair : AvPair) : bool =
    pair.avId <> AvId.MsvAvEOL && pair.avId <> AvId.MsvAvFlags


let private withMicPresentFlag (pairs : AvPair list) : AvPair list =
    pairs @ [ micPresentFlag ]


///
/// TargetInfo for the client blob: server AV_PAIRs plus the MIC-present flag.
let private clientAvPairs (targetInfo : AvPair list) : byte array =
    targetInfo
    |> List.filter isRetainedAvPair
    |> withMicPresentFlag
    |> encodeAvPairs


///
/// Build NTLMv2_CLIENT_CHALLENGE per [MS-NLMP] §2.2.2.7:
/// RespType(1) HiRespType(1) Reserved1(2) Reserved2(4) TimeStamp(8)
/// ChallengeFromClient(8) Reserved3(4) AvPairs (server TargetInfo + MIC flag).
/// 
let private buildClientBlob (clientChallenge : byte array) (targetInfo : AvPair list) (serverTimestamp : DateTime option) : byte array =
    Array.concat
        [ [| 0x01uy; 0x01uy |]
          Array.zeroCreate 6
          clientBlobTimestamp serverTimestamp
          clientChallenge
          Array.zeroCreate 4
          clientAvPairs targetInfo ]


///
/// Compute NTProofStr from the NTLMv2 hash, server challenge, and client blob.
let private computeNtProofStr (ntlmV2Hash : byte array) (serverChallenge : byte array) (clientBlob : byte array) : byte array =
    use hmac = new HMACMD5(ntlmV2Hash)
    hmac.ComputeHash(concat2 serverChallenge clientBlob)


///
/// Compute the full NTLMv2 response: NTProofStr || ClientBlob.
let private computeNtV2Response (ntlmV2Hash : byte array) (serverChallenge : byte array) (clientBlob : byte array) : byte array =
    let ntProofStr = computeNtProofStr ntlmV2Hash serverChallenge clientBlob
    concat2 ntProofStr clientBlob


///
/// Compute the LMv2 response (used in the LmChallengeResponse field).
let private computeLmV2Response (ntlmV2Hash : byte array) (serverChallenge : byte array) (clientChallenge : byte array) : byte array =
    use hmac = new HMACMD5(ntlmV2Hash)
    let lmHash = hmac.ComputeHash(concat2 serverChallenge clientChallenge)
    concat2 lmHash clientChallenge


///
/// Derive the exported session key from the NTLMv2 hash and NTProofStr.
let internal computeExportedSessionKey (ntlmV2Hash : byte array) (ntProofStr : byte array) : byte array = 
    use hmac = new HMACMD5(ntlmV2Hash)
    hmac.ComputeHash ntProofStr 


///
/// Compute the Message Integrity Code (MIC).
let internal computeMic (exportedSessionKey : byte array) (negotiateMessage : byte array) (challengeMessage : byte array) (authenticateMessage : byte array) : byte array =
    use hmac = new HMACMD5(exportedSessionKey)
    hmac.ComputeHash(concatMany [| negotiateMessage; challengeMessage; authenticateMessage |])


///
/// RC4 encrypt/decrypt
let private rc4 (key : byte array) (data : byte array) : byte array =
    let s = Array.init 256 id
    let mutable j = 0
    for i in 0..255 do
        j <- j + s.[i] + int key.[i % key.Length] &&& 0xFF
        let tmp = s.[i]
        s.[i] <- s.[j]
        s.[j] <- tmp
    let out = Array.zeroCreate<byte> data.Length
    let mutable i = 0
    j <- 0
    for n in 0 .. data.Length - 1 do
        i <- i + 1 &&& 0xFF
        j <- j + s.[i] &&& 0xFF
        let tmp = s.[i]
        s.[i] <- s.[j]
        s.[j] <- tmp
        let k = s.[(s.[i] + s.[j]) &&& 0xFF]
        out.[n] <- data.[n] ^^^ byte k
    
    out


///
/// Compute the complete NetNTLMv2
let internal computeNtlmV2Response (password : string) (username : string) (domain : string) (challenge : ChallengeMessage) : NtlmV2Response =
    let ntHash = computeNtHash password
    let ntlmV2Hash = computeNtlmV2Hash ntHash username domain
    let clientChallenge = Array.zeroCreate<byte> 8
    
    use rng = RandomNumberGenerator.Create()
    rng.GetBytes clientChallenge 
    
    let clientBlob =
        buildClientBlob clientChallenge challenge.targetInfo (challenge.targetInfo |> extractTimestamp)
    let ntProofStr = computeNtProofStr ntlmV2Hash challenge.serverChallenge clientBlob
    let ntResponse = computeNtV2Response ntlmV2Hash challenge.serverChallenge clientBlob
    let lmResponse = computeLmV2Response ntlmV2Hash challenge.serverChallenge clientChallenge
    let keyExchangeKey = computeExportedSessionKey ntlmV2Hash ntProofStr
    let keyExch =  challenge.negotiateFlags &&& NtlmFlags.NegotiateKeyExch <> 0u
    
    let exportedSessionKey, encryptedRandomSessionKey =
        match keyExch with
        | false -> keyExchangeKey, [||]
        | true ->
            let randomKey = Array.zeroCreate<byte> 16
            rng.GetBytes randomKey 
            let enc = rc4 keyExchangeKey randomKey
            randomKey, enc
    
    { lmResponse = lmResponse
      ntResponse = ntResponse
      exportedSessionKey = exportedSessionKey
      encryptedRandomSessionKey = encryptedRandomSessionKey }
