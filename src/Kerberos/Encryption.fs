module internal Fauli.Kerberos.Encryption


open System
open System.Security.Cryptography
open System.Text

open Fauli.Constants


type public EncryptionType =
    | DES_CBC_CRC = 1
    | DES_CBC_MD4 = 2
    | DES_CBC_MD5 = 3
    | DES3_CBC_SHA1 = 16
    | AES128_CTS_HMAC_SHA1_96 = 17
    | AES256_CTS_HMAC_SHA1_96 = 18
    | ARCFOUR_HMAC_MD5 = 23


type public Key =
    { enctype : EncryptionType
      contents : byte array }


type CryptoError =
    | UnsupportedEncryptionType of EncryptionType
    | CiphertextTooShort
    | MacVerificationFailed
    | PrfNotImplemented of EncryptionType


type private Md4Reg =
    { a : uint32
      b : uint32
      c : uint32
      d : uint32 }


module public KeyUsage =
    let AsReqPaEncTs = 1
    let KdcRepTicket = 2
    let AsRepEncPart = 3
    let TgsReqAdSesskey = 4
    let TgsReqAdSubkey = 5
    let TgsReqAuthCksum = 6
    let TgsReqAuth = 7
    let TgsRepEncPartSesskey = 8
    let TgsRepEncPartSubkey = 9
    let ApReqAuthCksum = 10
    let ApReqAuth = 11
    let ApRepEncPart = 12


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


let private xorBytes (a : byte array) (b : byte array) : byte array =
    Array.init a.Length (fun i -> byte (int a.[i] ^^^ int b.[i]))


let private getRandomBytes (len : int) : byte array =
    let bytes = Array.zeroCreate<byte> len
    RandomNumberGenerator.Fill bytes 
    bytes


let private constantTimeCompare (a : byte array) (b : byte array) : bool =
    match a.Length <> b.Length with
    | true ->  false
    | false ->
        Array.fold2 (fun acc x y -> acc ||| int x ^^^ int y) 0 a b = 0


let private zeroPadToBlock (data : byte array) : byte array =
    let block = Aes.BlockSize
    let rem = data.Length % block
    match rem = 0 with
    | true -> data
    | false ->
        let padLen = block - rem
        let result = Array.zeroCreate<byte> (data.Length + padLen)
        Array.Copy(data, 0, result, 0, data.Length)
        result


let private transformAes (key : byte array) (mode : CipherMode) (encrypt : bool) (data : byte array) : byte array =
    use aes = Aes.Create()
    aes.Key <- key
    aes.Mode <- mode
    aes.Padding <- PaddingMode.None
    aes.IV <- Array.zeroCreate Aes.BlockSize
    use transform =
        match encrypt with
        | true -> aes.CreateEncryptor()
        | false -> aes.CreateDecryptor()
    transform.TransformFinalBlock(data, 0, data.Length)


let private cbcEncryptZerosIv (key : byte array) (data : byte array) : byte array =
    transformAes key CipherMode.CBC true data


let private cbcDecryptZerosIv (key : byte array) (data : byte array) : byte array =
    transformAes key CipherMode.CBC false data


let private ecbDecrypt (key : byte array) (data : byte array) : byte array =
    transformAes key CipherMode.ECB false data


///
/// Residual last-block length for ciphertext stealing (a full block when evenly divisible).
let private stolenByteCount (messageLength : int) : int =
    match messageLength % Aes.BlockSize with
    | 0 -> Aes.BlockSize
    | rem -> rem


///
/// CBC-CS3 steal: swap the last two ciphertext blocks and truncate Cn-1 ([RFC 3962]).
let private stealLastCiphertextBlocks (cbcCipher : byte array) (plainLength : int) : byte array =
    let lastTwoStart = cbcCipher.Length - 2 * Aes.BlockSize
    let prefix =
        match lastTwoStart > 0 with
        | true -> Array.sub cbcCipher 0 lastTwoStart
        | false -> [||]
    
    let cnMinus1 = Array.sub cbcCipher lastTwoStart Aes.BlockSize
    let cn = Array.sub cbcCipher (lastTwoStart + Aes.BlockSize) Aes.BlockSize
    
    Array.concat
        [ prefix
          cn
          Array.sub cnMinus1 0 (stolenByteCount plainLength) ]


let internal aesCtsEncrypt (key : byte array) (plaintext : byte array) : byte array =
    let cbcCipher = cbcEncryptZerosIv key (zeroPadToBlock plaintext)
    match plaintext.Length <= Aes.BlockSize with
    | true -> Array.sub cbcCipher 0 plaintext.Length
    | false -> stealLastCiphertextBlocks cbcCipher plaintext.Length


let private padPartialBlock (data : byte array) (offset : int) : byte array =
    let available = min Aes.BlockSize (data.Length - offset)
    let block = Array.zeroCreate Aes.BlockSize
    Array.Copy(data, offset, block, 0, available)
    
    block


let private ciphertextBlocks (ciphertext : byte array) : byte array array =
    let count = (ciphertext.Length + Aes.BlockSize - 1) / Aes.BlockSize
    Array.init count (fun i -> padPartialBlock ciphertext (i * Aes.BlockSize))


///
/// CBC-decrypt every full block except the stolen pair; return plaintext and the next CBC chain value.
let private decryptCtsPrefix (key : byte array) (blocks : byte array array) : byte array * byte array =
    let prefixCount = blocks.Length - 2
    match prefixCount > 0 with
    | false -> [||], Array.zeroCreate Aes.BlockSize
    | true ->
        let prefixCipher =
            blocks
            |> Array.take prefixCount
            |> Array.concat
        cbcDecryptZerosIv key prefixCipher, blocks.[prefixCount - 1]


///
/// Undo CS3 stealing on the last two ciphertext blocks.
let private recoverStolenPlaintext (key : byte array) (cn : byte array) (stolen : byte array) (cbcChain : byte array) (stolenLen : int) : byte array * byte array =
    let dn = ecbDecrypt key cn
    let pn = xorBytes (Array.sub dn 0 stolenLen) (Array.sub stolen 0 stolenLen)
    let restoredCnMinus1 =
        Array.concat
            [ Array.sub stolen 0 stolenLen
              Array.sub dn stolenLen (Aes.BlockSize - stolenLen) ]
    xorBytes (ecbDecrypt key restoredCnMinus1) cbcChain, pn


let internal aesCtsDecrypt (key : byte array) (ciphertext : byte array) : byte array =
    match ciphertext.Length <= Aes.BlockSize with
    | true -> ecbDecrypt key ciphertext
    | false ->
        let blocks = ciphertextBlocks ciphertext
        let prefixPlain, cbcChain = decryptCtsPrefix key blocks
        let pnMinus1, pn =
            recoverStolenPlaintext
                key
                blocks.[blocks.Length - 2]
                blocks.[blocks.Length - 1]
                cbcChain
                (stolenByteCount ciphertext.Length)
        Array.concat
            [ prefixPlain
              pnMinus1
              pn ]


let private aesStringToKey (keySize : int) (password : string) (salt : string) : byte array =
    let passwordBytes = Encoding.UTF8.GetBytes password
    use pbkdf2 =
        new Rfc2898DeriveBytes(passwordBytes, Encoding.UTF8.GetBytes salt, 4096, HashAlgorithmName.SHA1)
    pbkdf2.GetBytes keySize


let rec private gcd a b =
    match b with
    | 0 -> a
    | _ -> gcd b (a % b)


///
/// Rotate a big-endian bit string right by nbits.
let private rotateBytesRight (arr : byte array) (nbits : int) : byte array =
    let bitLength = arr.Length * 8
    let shift = nbits % bitLength
    match shift with
    | 0 -> Array.copy arr
    | _ ->
        let asLittleEndian = Numerics.BigInteger(Array.rev arr)
        let mask = (Numerics.BigInteger.One <<< bitLength) - Numerics.BigInteger.One
        let rotated = asLittleEndian >>> shift ||| (asLittleEndian <<< bitLength - shift &&& mask)
        let rotatedBytes = rotated.ToByteArray() |> Array.rev
        let output = Array.zeroCreate arr.Length
        let srcLen = min rotatedBytes.Length arr.Length
        Array.Copy(rotatedBytes, rotatedBytes.Length - srcLen, output, arr.Length - srcLen, srcLen)
        output


///
/// One's-complement (end-around carry) addition of two equal-length big-endian integers.
let private addOnesComplement (acc : byte array) (slice : byte array) : byte array =
    let rec addFromRight i carry =
        match i < 0 with
        | true -> carry
        | false ->
            let sum = int acc.[i] + int slice.[i] + carry
            acc.[i] <- byte (sum &&& 0xFF)
            addFromRight (i - 1) (sum >>> 8)
    let rec endAround i carry =
        match carry = 0 || i < 0 with
        | true -> ()
        | false ->
            let sum = int acc.[i] + carry
            acc.[i] <- byte (sum &&& 0xFF)
            endAround (i - 1) (sum >>> 8)
    endAround (acc.Length - 1) (addFromRight (acc.Length - 1) 0)
    acc


///
/// n-fold: fold an arbitrary bit string down to n bytes ([RFC 3961] §5.1).
let private nfold (input : byte array) (nbytes : int) : byte array =
    let stretchedLength = nbytes * input.Length / gcd nbytes input.Length
    let stretched =
        Array.init (stretchedLength / input.Length) (fun i -> rotateBytesRight input (13 * i))
        |> Array.concat
    Array.init (stretchedLength / nbytes) (fun i -> Array.sub stretched (i * nbytes) nbytes)
    |> Array.fold addOnesComplement (Array.zeroCreate nbytes)


///
/// DK(key, constant) = DR(key, n-fold(constant)) truncated to the key length ([RFC 3961] §5.1).
let internal aesDerive (key : byte array) (constant : byte array) : byte array =
    let rec expand (seed : byte array) (plaintext : byte array) : byte array =
        match seed.Length >= key.Length with
        | true -> Array.sub seed 0 key.Length
        | false ->
            let next = cbcEncryptZerosIv key plaintext
            expand (concat2 seed next) next
    expand Array.empty<byte> (nfold constant Aes.BlockSize)


let aesStringToKeyFull (keySize : int) (password : string) (salt : string) : byte array =
    aesDerive (aesStringToKey keySize password salt) (Encoding.ASCII.GetBytes "kerberos")


let internal buildUsageConstant (keyUsage : int) (marker : byte) : byte array =
    [| byte (keyUsage >>> 24 &&& 0xFF)
       byte (keyUsage >>> 16 &&& 0xFF)
       byte (keyUsage >>> 8 &&& 0xFF)
       byte (keyUsage &&& 0xFF)
       marker |]


let private aesEncrypt (key : byte array) (keyUsage : int) (plaintext : byte array) (confounder : byte array option) (keySize : int) : byte array =
    let blockSize = Aes.BlockSize
    let macSize = Aes.MacSize
    let ki = aesDerive key (buildUsageConstant keyUsage Aes.UsageMarkerEncrypt)
    let ke = aesDerive key (buildUsageConstant keyUsage Aes.UsageMarkerDecrypt)
    let conf = defaultArg confounder (getRandomBytes blockSize)
    let basicPlaintext = concat2 conf plaintext
    use hmac = new HMACSHA1(ki)
    let mac =
        hmac.ComputeHash(basicPlaintext : byte array)
        |> Array.truncate macSize
    let encrypted = aesCtsEncrypt ke basicPlaintext
    concat2 encrypted mac


let private finishAesDecrypt (key : byte array) (keyUsage : int) (ciphertext : byte array) (blockSize : int) (macSize : int) : Result<byte array, CryptoError> =
    let ki = aesDerive key (buildUsageConstant keyUsage Aes.UsageMarkerEncrypt)
    let ke = aesDerive key (buildUsageConstant keyUsage Aes.UsageMarkerDecrypt)
    let basicCiphertext = Array.sub ciphertext 0 (ciphertext.Length - macSize)
    let basicPlaintext = aesCtsDecrypt ke basicCiphertext
    use hmac = new HMACSHA1(ki)
    let expectedMac =
        hmac.ComputeHash basicPlaintext
        |> Array.truncate macSize
    let receivedMac = Array.sub ciphertext (ciphertext.Length - macSize) macSize
    match constantTimeCompare receivedMac expectedMac with
    | false -> MacVerificationFailed |> Error
    | true -> Array.sub basicPlaintext blockSize (basicPlaintext.Length - blockSize) |> Ok


let private aesDecrypt (key : byte array) (keyUsage : int) (ciphertext : byte array) (keySize : int) : Result<byte array, CryptoError> =
    let blockSize = Aes.BlockSize
    let macSize = Aes.MacSize
    match ciphertext.Length < blockSize + macSize with
    | true -> CiphertextTooShort |> Error
    | false -> finishAesDecrypt key keyUsage ciphertext blockSize macSize


///
/// Map RFC 4120 key usage to RFC 4757 T value.
/// Per RFC 4757 §3 and errata: usage 3 → T=8, usage 23 → T=13; all others pass through.
/// 
let private rc4MapUsage (keyUsage : int) : int =
    match keyUsage with
    | 3 -> 8
    | 23 -> 13
    | _ -> keyUsage


let private swapBytes (arr : byte array) (a : int) (b : int) : unit =
    let tmp = arr.[a]
    arr.[a] <- arr.[b]
    arr.[b] <- tmp


///
/// RC4 key-scheduling algorithm: identity permutation scrambled by the key.
let private rc4Ksa (keyBytes : byte array) : byte array =
    let state = Array.init Rc4.StateSize byte
    let rec scramble i j =
        match i < Rc4.StateSize with
        | false -> state
        | true ->
            let j' = j + int keyBytes.[i % keyBytes.Length] + int state.[i] &&& Rc4.Mask
            swapBytes state i j'
            scramble (i + 1) j'
    scramble 0 0


///
/// RC4 pseudo-random generation: keystream XOR of the input.
let private rc4Prga (state : byte array) (input : byte array) : byte array =
    let rec emit (idx : int) (i : int) (j : int) (output : byte array) : byte array =
        match idx >= input.Length with
        | true -> output
        | false ->
            let i' = i + 1 &&& Rc4.Mask
            let j' = j + int state.[i'] &&& Rc4.Mask
            swapBytes state i' j'
            let k = int state.[i'] + int state.[j'] &&& Rc4.Mask
            output.[idx] <- input.[idx] ^^^ state.[k]
            emit (idx + 1) i' j' output
    emit 0 0 0 (Array.zeroCreate<byte> input.Length)


let private rc4Crypt (keyBytes : byte array) (input : byte array) : byte array =
    let S = rc4Ksa keyBytes
    rc4Prga S input


let private rc4HmacMd5Encrypt (key : byte array) (keyUsage : int) (plaintext : byte array) (confounder : byte array option) : byte array =
    let usageBytes = BitConverter.GetBytes(rc4MapUsage keyUsage)  // little-endian per RFC 4757
    let conf = defaultArg confounder (getRandomBytes Rc4.ConfounderSize)
    
    use kiHmac = new HMACMD5(key)
    let ki = kiHmac.ComputeHash(usageBytes : byte array)
    
    use cksumHmac = new HMACMD5(ki)
    let data = concat2 conf plaintext
    let cksum = cksumHmac.ComputeHash(data : byte array)
    
    use keHmac = new HMACMD5(ki)
    let ke = keHmac.ComputeHash(cksum : byte array)
    let encrypted = rc4Crypt ke data
    
    concat2 cksum encrypted


let private stripRc4Confounder (basicPlaintext : byte array) : byte array =
    Array.sub basicPlaintext Rc4.ConfounderSize (basicPlaintext.Length - Rc4.ConfounderSize)


let private rc4MacMatches (key : byte array) (cksum : byte array) (basicPlaintext : byte array) : bool =
    use verifyHmac = new HMACMD5(key)
    constantTimeCompare cksum (verifyHmac.ComputeHash basicPlaintext)


let private tryRc4Usage9Fallback (key : byte array) (cksum : byte array) (basicPlaintext : byte array) : Result<byte array, CryptoError> =
    let usage8Bytes = BitConverter.GetBytes 9
    use kiHmac2 = new HMACMD5(key)
    let ki2 = kiHmac2.ComputeHash(usage8Bytes : byte array)
    match rc4MacMatches ki2 cksum basicPlaintext with
    | true -> stripRc4Confounder basicPlaintext |> Ok
    | false -> MacVerificationFailed |> Error


///
/// Try MAC verification with fallback usage 8 (RFC 4757 errata).
let private tryRc4MacVerification (key : byte array) (keyUsage : int) (cksum : byte array) (basicPlaintext : byte array) : Result<byte array, CryptoError> =
    match rc4MacMatches key cksum basicPlaintext with
    | true -> stripRc4Confounder basicPlaintext |> Ok
    | false when keyUsage = 9 -> tryRc4Usage9Fallback key cksum basicPlaintext
    | false -> MacVerificationFailed |> Error


let private rc4HmacMd5Decrypt (key : byte array) (keyUsage : int) (ciphertext : byte array) : Result<byte array, CryptoError> =
    let usageBytes = BitConverter.GetBytes(rc4MapUsage keyUsage)
    match ciphertext.Length < Rc4.Md5ChecksumSize + Rc4.ConfounderSize with
    | true -> CiphertextTooShort |> Error
    | false ->
        let cksum = Array.sub ciphertext 0 Rc4.Md5ChecksumSize
        let basicCtext = Array.sub ciphertext Rc4.Md5ChecksumSize (ciphertext.Length - Rc4.Md5ChecksumSize)
        use kiHmac = new HMACMD5(key)
        let ki = kiHmac.ComputeHash(usageBytes : byte array)
        use keHmac = new HMACMD5(ki)
        let ke = keHmac.ComputeHash(cksum : byte array)
        rc4Crypt ke basicCtext
        |> tryRc4MacVerification ki keyUsage cksum


let private leftRotate (x : uint32) (n : int) : uint32 =
    x <<< n ||| (x >>> 32 - n)


let private md4F u v w = u &&& v ||| (~~~u &&& w)


let private md4G u v w = u &&& v ||| (u &&& w) ||| (v &&& w)


let private md4H u v w = u ^^^ v ^^^ w


let private uint32FromLe (arr : byte array) (off : int) : uint32 =
    uint32 arr.[off] ||| (uint32 arr.[off + 1] <<< 8) ||| (uint32 arr.[off + 2] <<< 16) ||| (uint32 arr.[off + 3] <<< 24)


let private uint32ToLe (v : uint32) : byte array =
    [| byte (v &&& 0xFFu); byte (v >>> 8 &&& 0xFFu); byte (v >>> 16 &&& 0xFFu); byte (v >>> 24 &&& 0xFFu) |]


///
/// Round 1: sequential X, shifts 3/7/11/19.
let private md4Round1 =
    [| 0, 3; 1, 7; 2, 11; 3, 19
       4, 3; 5, 7; 6, 11; 7, 19
       8, 3; 9, 7; 10, 11; 11, 19
       12, 3; 13, 7; 14, 11; 15, 19 |]


///
/// Round 2: X stride 4, shifts 3/5/9/13.
let private md4Round2 =
    [| 0, 3; 4, 5; 8, 9; 12, 13
       1, 3; 5, 5; 9, 9; 13, 13
       2, 3; 6, 5; 10, 9; 14, 13
       3, 3; 7, 5; 11, 9; 15, 13 |]


///
/// Round 3: X 0/8/4/12 then odds, shifts 3/9/11/15.
let private md4Round3 =
    [| 0, 3; 8, 9; 4, 11; 12, 15
       2, 3; 10, 9; 6, 11; 14, 15
       1, 3; 9, 9; 5, 11; 13, 15
       3, 3; 11, 9; 7, 11; 15, 15 |]


///
/// One MD4 operation, then rotate so the next target sits in `a`.
let private md4Step (f : uint32 -> uint32 -> uint32 -> uint32) (k : uint32) (x : uint32 array) (s : Md4Reg) (xi : int, shift : int) : Md4Reg =
    let a' = leftRotate (s.a + f s.b s.c s.d + x.[xi] + k) shift
    { a = s.d
      b = a'
      c = s.b
      d = s.c }


let private md4Round (f : uint32 -> uint32 -> uint32 -> uint32) (k : uint32) (schedule : (int * int) array) (x : uint32 array) (state : Md4Reg) : Md4Reg =
    schedule |> Array.fold (md4Step f k x) state


let private md4Pad (input : byte array) : byte array =
    let bitLen = int64 input.Length * 8L
    let mod64 = input.Length % Md4.BlockBytes
    let padLen =
        match mod64 < 56 with
        | true -> 56 - mod64
        | false -> 120 - mod64
    let padded = Array.zeroCreate<byte> (input.Length + padLen + 8)
    Array.Copy(input, padded, input.Length)
    
    padded.[input.Length] <- 0x80uy
    let rec writeBitLen i =
        match i < 8 with
        | false -> ()
        | true ->
            padded.[input.Length + padLen + i] <- byte (int (bitLen >>> (i * 8) &&& 0xFFL))
            writeBitLen (i + 1)
    writeBitLen 0
    
    padded


let private loadBlock (padded : byte array) (blockStart : int) : uint32 array =
    Array.init 16 (fun i -> uint32FromLe padded (blockStart + i * 4))


let private processBlock (h : Md4Reg) (x : uint32 array) : Md4Reg =
    let after =
        h
        |> md4Round md4F 0u md4Round1 x
        |> md4Round md4G Md4.Round2Constant md4Round2 x
        |> md4Round md4H Md4.Round3Constant md4Round3 x
    
    { a = h.a + after.a
      b = h.b + after.b
      c = h.c + after.c
      d = h.d + after.d }


///
/// Compute the MD4 hash (RFC 1320). Used for RC4-HMAC-MD5 key derivation
/// (RFC 4757 §2) and NT-Hash computation in NetNTLMv2.
/// 
let internal md4 (input : byte array) : byte array =
    let padded = md4Pad input
    let rec processBlocks blockStart (h : Md4Reg) =
        match blockStart > padded.Length - Md4.BlockBytes with
        | true -> h
        | false -> processBlocks (blockStart + Md4.BlockBytes) (processBlock h (loadBlock padded blockStart))
    let h =
        processBlocks 0
            { a = 0x67452301u
              b = 0xEFCDAB89u
              c = 0x98BADCFEu
              d = 0x10325476u }
    Array.concat
        [ uint32ToLe h.a
          uint32ToLe h.b
          uint32ToLe h.c
          uint32ToLe h.d ]


let stringToKey (enctype : EncryptionType) (password : string) (salt : string) : Result<Key, CryptoError> =
    match enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96 ->
        { enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
          contents = aesStringToKeyFull 32 password salt } |> Ok
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        { enctype = EncryptionType.AES128_CTS_HMAC_SHA1_96
          contents = aesStringToKeyFull 16 password salt } |> Ok
    | EncryptionType.ARCFOUR_HMAC_MD5 ->
        { enctype = EncryptionType.ARCFOUR_HMAC_MD5
          contents = md4 (Encoding.Unicode.GetBytes password) } |> Ok
    | other -> UnsupportedEncryptionType other |> Error


///
/// Encrypt plaintext using the given key and Kerberos key usage number.
let internal encrypt (key : Key) (keyUsage : int) (plaintext : byte array) (confounder : byte array option) : Result<byte array, CryptoError> =
    match key.enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96 ->
        aesEncrypt key.contents keyUsage plaintext confounder 32 |> Ok
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        aesEncrypt key.contents keyUsage plaintext confounder 16 |> Ok
    | EncryptionType.ARCFOUR_HMAC_MD5 ->
        rc4HmacMd5Encrypt key.contents keyUsage plaintext confounder |> Ok
    | other -> UnsupportedEncryptionType other |> Error


///
/// Decrypt ciphertext using the given key and Kerberos key usage number.
/// Follows RFC 3961 §5: derives encryption/MAC keys, verifies the checksum
/// in constant time, then decrypts and strips the usage prefix.
/// 
let internal decrypt (key : Key) (keyUsage : int) (ciphertext : byte array) : Result<byte array, CryptoError> =
    match key.enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96 ->
        aesDecrypt key.contents keyUsage ciphertext 32
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        aesDecrypt key.contents keyUsage ciphertext 16
    | EncryptionType.ARCFOUR_HMAC_MD5 ->
        rc4HmacMd5Decrypt key.contents keyUsage ciphertext
    | other -> UnsupportedEncryptionType other |> Error


///
/// Kerberos pseudo-random function (PRF) per RFC 3962 §4 / RFC 8009.
/// Derives a key using the seed "prf", hashes the input, and encrypts
/// the truncated hash under the derived key. Used for key derivation in
/// password change and session key negotiation protocols.
/// 
let internal prf (key : Key) (input : byte array) : Result<byte array, CryptoError> =
    let aesPrfEncrypt (kp : byte array) (truncated : byte array) : byte array =
        use aes = Aes.Create()
        aes.Key <- kp
        aes.Mode <- CipherMode.ECB
        aes.Padding <- PaddingMode.None
        aes.IV <- Array.zeroCreate Aes.BlockSize
        
        use ec = aes.CreateEncryptor()
        ec.TransformFinalBlock(truncated, 0, 16)
    match key.enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        use sha1 = SHA1.Create()
        sha1.ComputeHash input
        |> Array.truncate Aes.BlockSize
        |> aesPrfEncrypt (aesDerive key.contents (Encoding.ASCII.GetBytes "prf"))
        |> Ok
    | other -> PrfNotImplemented other |> Error
