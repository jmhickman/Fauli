/// Cryptographic primitives for NetNTLMv2 per [MS-NLMP].
/// NT-Hash (MD4 of UTF-16LE password), NTLMv2 response key, challenge response,
/// session key derivation, and MIC computation.
module internal Fauli.Ntlm.Crypto

open System
open System.Security.Cryptography
open System.Text
open Fauli.Kerberos.Encryption
open Fauli.Ntlm.Encoding

// ---------------------------------------------------------------------------
// Helpers: byte array concatenation
// ---------------------------------------------------------------------------

/// Concatenate two byte arrays.
let private concat2 (a : byte array) (b : byte array) : byte array =
    let result = Array.zeroCreate<byte> (a.Length + b.Length)
    Array.Copy(a, 0, result, 0, a.Length)
    Array.Copy(b, 0, result, a.Length, b.Length)
    result

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

// ---------------------------------------------------------------------------
// NT-Hash: MD4(UTF-16LE(password))
// ---------------------------------------------------------------------------

/// Compute the NT-Hash (also called the NT hash or NTHash).
/// This is the hash stored on Windows systems and used as the basis for all
/// NetNTLMv2 computations.
let internal computeNtHash (password : string) : byte array =
    md4 (Encoding.Unicode.GetBytes password)

// ---------------------------------------------------------------------------
// NTLMv2 response key: HMAC-MD5(NT-Hash, UTF-16LE(username) || UTF-16LE(domain))
// ---------------------------------------------------------------------------

/// Compute the NTLMv2 response key (also called the NTLMv2 hash).
/// This is derived from the NT-Hash and the user's identity.
let internal computeNtlmV2Hash (ntHash : byte array) (username : string) (domain : string) : byte array =
    // MS-NLMP: UNICODE(Uppercase(UserName)) || UNICODE(Domain) — domain case as given
    use hmac = new HMACMD5(ntHash)
    let identity =
        concat2
            (Encoding.Unicode.GetBytes (username.ToUpperInvariant()))
            (Encoding.Unicode.GetBytes domain)
    hmac.ComputeHash(identity)

// ---------------------------------------------------------------------------
// Client blob (NTLMv2_CLIENT_CHALLENGE)
// ---------------------------------------------------------------------------

/// Build NTLMv2_CLIENT_CHALLENGE per [MS-NLMP] §2.2.2.7:
/// RespType(1) HiRespType(1) Reserved1(2) Reserved2(4) TimeStamp(8)
/// ChallengeFromClient(8) Reserved3(4) AvPairs (server TargetInfo + MIC flag).
let private buildClientBlob (clientChallenge : byte array) (targetInfo : AvPair list) (serverTimestamp : DateTime option) : byte array =
    let sb = ResizeArray<byte>()
    sb.Add 0x01uy  // RespType
    sb.Add 0x01uy  // HiRespType
    [1..6] |> List.iter (fun _ -> sb.Add 0x00uy)  // Reserved1+2

    let timestamp =
        match serverTimestamp with
        | Some ts -> ts.ToFileTime()
        | None -> DateTime.UtcNow.ToFileTime()
    BitConverter.GetBytes(timestamp) |> Array.iter sb.Add
    clientChallenge |> Array.iter sb.Add
    [1..4] |> List.iter (fun _ -> sb.Add 0x00uy)  // Reserved3

    // Server TargetInfo with MsvAvFlags |= MIC_PROVIDED (0x2); drop existing Flags/EOL
    let micFlagValue = BitConverter.GetBytes(0x00000002u)  // LE
    let withoutFlags =
        targetInfo
        |> List.filter (fun p -> p.avId <> AvId.MsvAvEOL && p.avId <> AvId.MsvAvFlags)
    let withMic =
        withoutFlags @ [ { avId = AvId.MsvAvFlags; value = micFlagValue } ]
    encodeAvPairs withMic |> Array.iter sb.Add
    sb.ToArray()

// ---------------------------------------------------------------------------
// NTProofStr = HMAC-MD5(NTLMv2-Hash, ServerChallenge || ClientBlob)
// ---------------------------------------------------------------------------

/// Compute NTProofStr from the NTLMv2 hash, server challenge, and client blob.
let private computeNtProofStr (ntlmV2Hash : byte array) (serverChallenge : byte array) (clientBlob : byte array) : byte array =
    use hmac = new HMACMD5(ntlmV2Hash)
    hmac.ComputeHash(concat2 serverChallenge clientBlob)

// ---------------------------------------------------------------------------
// NTLMv2-Response = NTProofStr || ClientBlob
// ---------------------------------------------------------------------------

/// Compute the full NTLMv2 response: NTProofStr || ClientBlob.
let private computeNtV2Response (ntlmV2Hash : byte array) (serverChallenge : byte array) (clientBlob : byte array) : byte array =
    let ntProofStr = computeNtProofStr ntlmV2Hash serverChallenge clientBlob
    concat2 ntProofStr clientBlob

// ---------------------------------------------------------------------------
// LMv2-Response = HMAC-MD5(NTLMv2-Hash, ServerChallenge || ClientChallenge) || ClientChallenge
// ---------------------------------------------------------------------------

/// Compute the LMv2 response (used in the LmChallengeResponse field).
let private computeLmV2Response (ntlmV2Hash : byte array) (serverChallenge : byte array) (clientChallenge : byte array) : byte array =
    use hmac = new HMACMD5(ntlmV2Hash)
    let lmHash = hmac.ComputeHash(concat2 serverChallenge clientChallenge)
    concat2 lmHash clientChallenge

// ---------------------------------------------------------------------------
// ExportedSessionKey = HMAC-MD5(NTLMv2-Hash, NTProofStr)
// ---------------------------------------------------------------------------

/// Derive the exported session key from the NTLMv2 hash and NTProofStr.
let internal computeExportedSessionKey (ntlmV2Hash : byte array) (ntProofStr : byte array) : byte array = 
    use hmac = new HMACMD5(ntlmV2Hash)
    hmac.ComputeHash(ntProofStr)

// ---------------------------------------------------------------------------
// MIC = HMAC-MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)
// ---------------------------------------------------------------------------

/// Compute the Message Integrity Code (MIC).
/// The AUTHENTICATE_MESSAGE must have its MIC field zeroed out before hashing.
let internal computeMic (exportedSessionKey : byte array) (negotiateMessage : byte array) (challengeMessage : byte array) (authenticateMessage : byte array) : byte array =
    use hmac = new HMACMD5(exportedSessionKey)
    hmac.ComputeHash(concatMany [| negotiateMessage; challengeMessage; authenticateMessage |])

// ---------------------------------------------------------------------------
// Public: compute the full NetNTLMv2 challenge response
// ---------------------------------------------------------------------------

/// Result of computing the NetNTLMv2 response.
type NtlmV2Response =
    { lmResponse : byte array
      ntResponse : byte array
      /// Key used for SMB signing / sealing after auth (ExportedSessionKey).
      exportedSessionKey : byte array
      /// EncryptedRandomSessionKey payload (16 bytes when KEY_EXCH, else empty).
      encryptedRandomSessionKey : byte array }

/// RC4 encrypt/decrypt (same operation). Used for NTLM KEY_EXCH.
let private rc4 (key : byte array) (data : byte array) : byte array =
    let s = Array.init 256 id
    let mutable j = 0
    for i in 0..255 do
        j <- (j + s.[i] + int key.[i % key.Length]) &&& 0xFF
        let tmp = s.[i]
        s.[i] <- s.[j]
        s.[j] <- tmp
    let out = Array.zeroCreate<byte> data.Length
    let mutable i = 0
    j <- 0
    for n in 0 .. data.Length - 1 do
        i <- (i + 1) &&& 0xFF
        j <- (j + s.[i]) &&& 0xFF
        let tmp = s.[i]
        s.[i] <- s.[j]
        s.[j] <- tmp
        let k = s.[(s.[i] + s.[j]) &&& 0xFF]
        out.[n] <- data.[n] ^^^ byte k
    out

/// Compute the complete NetNTLMv2 response from password, username, domain,
/// and the server's CHALLENGE_MESSAGE. Honors NEGOTIATE_KEY_EXCH when set.
let internal computeNtlmV2Response (password : string) (username : string) (domain : string) (challenge : ChallengeMessage) : NtlmV2Response =
    let ntHash = computeNtHash password
    let ntlmV2Hash = computeNtlmV2Hash ntHash username domain

    let clientChallenge = Array.zeroCreate<byte> 8
    use rng = RandomNumberGenerator.Create()
    rng.GetBytes(clientChallenge)

    let clientBlob =
        buildClientBlob clientChallenge challenge.targetInfo
            (challenge.targetInfo |> extractTimestamp)

    let ntProofStr = computeNtProofStr ntlmV2Hash challenge.serverChallenge clientBlob
    let ntResponse = computeNtV2Response ntlmV2Hash challenge.serverChallenge clientBlob
    let lmResponse = computeLmV2Response ntlmV2Hash challenge.serverChallenge clientChallenge

    // SessionBaseKey / KeyExchangeKey for NTLMv2
    let keyExchangeKey = computeExportedSessionKey ntlmV2Hash ntProofStr

    let keyExch = (challenge.negotiateFlags &&& NtlmFlags.NegotiateKeyExch) <> 0u
    let exportedSessionKey, encryptedRandomSessionKey =
        match keyExch with
        | false -> keyExchangeKey, [||]
        | true ->
            // ExportedSessionKey = random NONCE(16); seal with RC4(KeyExchangeKey)
            let randomKey = Array.zeroCreate<byte> 16
            rng.GetBytes(randomKey)
            let enc = rc4 keyExchangeKey randomKey
            randomKey, enc

    { lmResponse = lmResponse
      ntResponse = ntResponse
      exportedSessionKey = exportedSessionKey
      encryptedRandomSessionKey = encryptedRandomSessionKey }
