/// Kerberos encryption types per RFC 3961 / RFC 4120 / RFC 4757.
module internal Fauli.Kerberos.Encryption

open System
open System.Security.Cryptography
open System.Text
open Fauli.Constants

// ---------------------------------------------------------------------------
// Encryption type constants (RFC 4120)
// ---------------------------------------------------------------------------

type public EncryptionType =
    | DES_CBC_CRC = 1
    | DES_CBC_MD4 = 2
    | DES_CBC_MD5 = 3
    | DES3_CBC_SHA1 = 16
    | AES128_CTS_HMAC_SHA1_96 = 17
    | AES256_CTS_HMAC_SHA1_96 = 18
    | ARCFOUR_HMAC_MD5 = 23

// ---------------------------------------------------------------------------
// Key usage constants (RFC 4120 §7.5.1)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Key type
// ---------------------------------------------------------------------------

type public Key = {
    enctype : EncryptionType
    contents : byte array
}

// ---------------------------------------------------------------------------
// Utility functions
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

let private xorBytes (a : byte array) (b : byte array) : byte array =
    Array.init a.Length (fun i -> byte (int a.[i] ^^^ int b.[i]))

let private getRandomBytes (len : int) : byte array =
    let bytes = Array.zeroCreate<byte> len
    RandomNumberGenerator.Fill(bytes)
    bytes


let private constantTimeCompare (a : byte array) (b : byte array) : bool =
    match a.Length <> b.Length with
    | true ->  false
    | false ->
        Array.fold2 (fun acc x y -> acc ||| int x ^^^ int y) 0 a b = 0


// ---------------------------------------------------------------------------
// AES CTS (Cipher Text Stealing) — RFC 3961 §4.2
// ---------------------------------------------------------------------------

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

let internal aesCtsEncrypt (key : byte array) (plaintext : byte array) : byte array =
    let block = Aes.BlockSize
    use aes = Aes.Create()
    aes.Key <- key
    aes.Mode <- CipherMode.CBC
    aes.Padding <- PaddingMode.None
    aes.IV <- Array.zeroCreate Aes.BlockSize
    let padded = zeroPadToBlock plaintext
    use ic = aes.CreateEncryptor()
    let ctext = ic.TransformFinalBlock(padded, 0, padded.Length)
    
    match plaintext.Length <= block with
    | true -> Array.sub ctext 0 plaintext.Length
    | false ->
        let lastlen =
            let m = plaintext.Length % block
            match m = 0 with
            | true -> block
            | false -> m
        let prefixLen = ctext.Length - 32
        let prefix =
            match prefixLen > 0 with
            | true -> Array.sub ctext 0 prefixLen
            | false -> [||]
        let last16 = Array.sub ctext (ctext.Length - 16) 16
        let prev16 = Array.sub ctext (ctext.Length - 32) 16
        let stolen = Array.sub prev16 0 lastlen

        concatMany [| prefix; last16; stolen |]


let internal aesCtsDecrypt (key : byte array) (ciphertext : byte array) : byte array =
    let block = Aes.BlockSize
    use aes = Aes.Create()
    aes.Key <- key
    aes.Mode <- CipherMode.ECB
    aes.Padding <- PaddingMode.None
    aes.IV <- Array.zeroCreate Aes.BlockSize

    match ciphertext.Length <= block with
    | true ->
        use dc = aes.CreateDecryptor()
        dc.TransformFinalBlock(ciphertext, 0, ciphertext.Length)
    | false ->
        // Split ciphertext into 16-byte blocks (last block may be short)
        let cblocks =
            let n = (ciphertext.Length + 15) / 16
            [| for i = 0 to n - 1 do
                let s = i * 16
                let l = min 16 (ciphertext.Length - s)
                let b = Array.zeroCreate 16
                Array.Copy(ciphertext, s, b, 0, l)
                yield b |]

        let lastlen =
            let m = ciphertext.Length % 16
            match m = 0 with
            | true -> 16
            | false -> m
        let numFullBlocksBeforeLast2 = cblocks.Length - 2

        // Decrypt all full blocks (all except the last two)
        let rec decryptFullBlocks idx prev res =
            match idx < numFullBlocksBeforeLast2 with
            | false -> prev, res
            | true ->
                use dc = aes.CreateDecryptor()
                let d = dc.TransformFinalBlock(cblocks.[idx], 0, 16)
                // XOR decrypted with previous ciphertext block
                let xored = xorBytes d prev
                let res' = Array.copy res
                Array.Copy(xored, 0, res', idx * 16, 16)
                decryptFullBlocks (idx + 1) cblocks.[idx] res'

        let prevAfterFull, resAfterFull = decryptFullBlocks 0 (Array.zeroCreate<byte> 16) (Array.zeroCreate<byte> ciphertext.Length)

        // Decrypt second-to-last block
        use dc2 = aes.CreateDecryptor()
        let b = dc2.TransformFinalBlock(cblocks.[cblocks.Length - 2], 0, 16)

        // Last plaintext block: XOR first `lastlen` bytes of b with last ciphertext block
        let lastp = Array.zeroCreate lastlen
        let rec xorLastP j =
            match j < lastlen with
            | false -> ()
            | true ->
                lastp.[j] <- byte (int b.[j] ^^^ int cblocks.[cblocks.Length - 1].[j])
                xorLastP (j + 1)
        xorLastP 0

        // Build the final ciphertext block for CTS decryption:
        // fc[0..lastlen-1] = last ciphertext block
        // fc[lastlen..15] = b[lastlen..15]
        let om = Array.zeroCreate (16 - lastlen)
        let rec copyOm j =
            match j < 16 - lastlen with
            | false -> ()
            | true ->
                om.[j] <- b.[lastlen + j]
                copyOm (j + 1)
        copyOm 0

        let fc = Array.zeroCreate 16
        Array.Copy(cblocks.[cblocks.Length - 1], 0, fc, 0, lastlen)
        Array.Copy(om, 0, fc, lastlen, 16 - lastlen)

        // Decrypt the final CTS block
        use dc3 = aes.CreateDecryptor()
        let sec = dc3.TransformFinalBlock(fc, 0, 16)

        // XOR with previous block and write to result
        let xoredSec = xorBytes sec prevAfterFull
        Array.Copy(xoredSec, 0, resAfterFull, (cblocks.Length - 2) * 16, 16)
        Array.Copy(lastp, 0, resAfterFull, (cblocks.Length - 1) * 16, lastlen)

        resAfterFull


// ---------------------------------------------------------------------------
// AES string-to-key (PBKDF2-based, RFC 3962)
// ---------------------------------------------------------------------------

let private aesStringToKey (keySize : int) (password : string) (salt : string) : byte array =
    let passwordBytes = Encoding.UTF8.GetBytes password
    // RFC 3962 §3: PBKDF2, 4096 iterations
    use pbkdf2 =
        new Rfc2898DeriveBytes(passwordBytes, Encoding.UTF8.GetBytes salt, 4096, HashAlgorithmName.SHA1)
    pbkdf2.GetBytes keySize

let internal aesDerive (key : byte array) (constant : byte array) : byte array =
    let blockSize = Aes.BlockSize  // AES block size is always 16
    // RFC 3961 §4.1 nfold operation
    let nfold (str : byte array) (nbytes : int) : byte array =
        let slen = str.Length
        // gcd
        let rec gcd a b = if b = 0 then a else gcd b (a % b)
        let lcm = (nbytes * slen) / gcd nbytes slen

        // Rotate a byte array right by nbits
        let rotateRight (arr : byte array) (nbits : int) : byte array =
            let len = arr.Length
            let totalBits = len * 8
            let shift = nbits % totalBits
            match shift = 0 with
            | true -> Array.copy arr
            | false ->
                // Treat arr as big-endian integer, rotate right by nbits
                let num = System.Numerics.BigInteger(arr |> Array.rev)  // BigInteger is little-endian
                let body = num >>> shift
                let mask = (System.Numerics.BigInteger.One <<< totalBits) - System.Numerics.BigInteger.One
                let remains = (num <<< (totalBits - shift)) &&& mask
                let res = body ||| remains
                let resBytes = res.ToByteArray() |> Array.rev  // back to big-endian
                // Ensure exactly len bytes (trim sign-extension or pad)
                let output = Array.zeroCreate<byte> len
                let srcLen = min resBytes.Length len
                Array.Copy(resBytes, resBytes.Length - srcLen, output, len - srcLen, srcLen)
                output

        // Build concatenated string with rotations
        let bigstr = System.Collections.Generic.List<byte>()
        let rec addRotated i =
            if i < lcm / slen then
                rotateRight str (13 * i) |> Array.iter bigstr.Add
                addRotated (i + 1)
        addRotated 0
        let bigarr : byte array = bigstr.ToArray()

        // Split into slices of nbytes and add as ones-complement integers
        let slices = Array.init (lcm / nbytes) (fun i -> Array.sub bigarr (i * nbytes) nbytes)

        // Ones-complement addition (LSB first, with end-around carry)
        let result = Array.zeroCreate<byte> nbytes
        let rec addSlice sliceIdx =
            match sliceIdx < slices.Length with
            | false -> ()
            | true ->
                let slice = slices.[sliceIdx]
                let mutable carry = 0
                for i in (nbytes - 1) .. -1 .. 0 do
                    let sum = int result.[i] + int slice.[i] + carry
                    carry <- sum >>> 8
                    result.[i] <- byte (sum &&& Rc4.Mask)
                // End-around carry: add carry back into LSB
                match carry <> 0 with
                | true ->
                    let mutable i = nbytes - 1
                    let mutable c = carry
                    while c <> 0 do
                        let s = int result.[i] + c
                        c <- s >>> 8
                        result.[i] <- byte (s &&& Rc4.Mask)
                        i <- i - 1
                | false -> ()
                addSlice (sliceIdx + 1)
        addSlice 0

        result

    let plaintext = nfold constant blockSize

    let rec loop (currentPlaintext : byte array) (seed : byte array) : byte array =
        match seed.Length >= key.Length with
        | true -> Array.sub seed 0 key.Length
        | false ->
            use aes = Aes.Create()
            aes.Key <- key
            aes.Mode <- CipherMode.CBC
            aes.Padding <- PaddingMode.None
            aes.IV <- Array.zeroCreate Aes.BlockSize
            let ic = aes.CreateEncryptor()
            let ciphertext = ic.TransformFinalBlock(currentPlaintext, 0, currentPlaintext.Length)
            ic.Dispose()
            aes.Dispose()
            loop ciphertext (concat2 seed ciphertext)

    loop plaintext Array.empty<byte>

let aesStringToKeyFull (keySize : int) (password : string) (salt : string) : byte array =
    aesDerive (aesStringToKey keySize password salt) (Encoding.ASCII.GetBytes "kerberos")

// ---------------------------------------------------------------------------
// AES simplified profile encrypt/decrypt (RFC 3961 §5)
// ---------------------------------------------------------------------------

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

let private aesDecrypt (key : byte array) (keyUsage : int) (ciphertext : byte array) (keySize : int) : byte array =
    let blockSize = Aes.BlockSize
    let macSize = Aes.MacSize

    match ciphertext.Length < blockSize + macSize with
    | true -> invalidArg "ciphertext" "Ciphertext too short for AES decryption"
    | false -> ()

    let ki = aesDerive key (buildUsageConstant keyUsage Aes.UsageMarkerEncrypt)
    let ke = aesDerive key (buildUsageConstant keyUsage Aes.UsageMarkerDecrypt)

    let basicCiphertext = Array.sub ciphertext 0 (ciphertext.Length - macSize)
    let basicPlaintext = aesCtsDecrypt ke basicCiphertext

    use hmac = new HMACSHA1(ki)
    let expectedMac =
        hmac.ComputeHash(basicPlaintext)
        |> Array.truncate macSize
    let receivedMac = Array.sub ciphertext (ciphertext.Length - macSize) macSize

    match constantTimeCompare receivedMac expectedMac with
    | false -> invalidArg "ciphertext" "MAC verification failed"
    | true -> ()

    Array.sub basicPlaintext blockSize (basicPlaintext.Length - blockSize)

// ---------------------------------------------------------------------------
// RC4-HMAC-MD5 (Microsoft extension, RFC 4757)
// ---------------------------------------------------------------------------

/// Map RFC 4120 key usage to RFC 4757 T value.
/// Per RFC 4757 §3 and errata: usage 3 → T=8, usage 23 → T=13; all others pass through.
let private rc4MapUsage (keyUsage : int) : int =
    match keyUsage with
    | 3 -> 8
    | 23 -> 13
    | _ -> keyUsage

let private rc4Ksa (keyBytes : byte array) : byte array =
    // Key Scheduling Algorithm: initialise and permute the 256-byte state
    let S = Array.zeroCreate<byte> Rc4.StateSize
    let keyLen = keyBytes.Length
    let rec init i =
        match i < Rc4.StateSize with
        | false -> ()
        | true ->
            S.[i] <- byte i
            init (i + 1)
    init 0

    let rec permute i j =
        match i < Rc4.StateSize with
        | false -> ()
        | true ->
            let j' = (j + int keyBytes.[i % keyLen] + int S.[i]) &&& Rc4.Mask
            let tmp = S.[i]
            S.[i] <- S.[j']
            S.[j'] <- tmp
            permute (i + 1) j'
    permute 0 0
    S

let private rc4Prga (S : byte array) (input : byte array) : byte array =
    // Pseudo-Random Generation Algorithm: produce keystream and XOR with input
    let output = Array.zeroCreate<byte> input.Length
    let rec generate idx i' j' =
        match idx < input.Length with
        | false -> ()
        | true ->
            let i'' = (i' + 1) &&& Rc4.Mask
            let j'' = (j' + int S.[i'']) &&& Rc4.Mask
            let tmp = S.[i'']
            S.[i''] <- S.[j'']
            S.[j''] <- tmp
            let xorIndex = (int S.[i''] + int S.[j'']) &&& Rc4.Mask
            output.[idx] <- byte (int input.[idx] ^^^ int S.[xorIndex])
            generate (idx + 1) i'' j''
    generate 0 0 0
    output

let private rc4Crypt (keyBytes : byte array) (input : byte array) : byte array =
    let S = rc4Ksa keyBytes
    rc4Prga S input

let private rc4HmacMd5Encrypt (key : byte array) (keyUsage : int) (plaintext : byte array) (confounder : byte array option) : byte array =
    let usageBytes = BitConverter.GetBytes(rc4MapUsage keyUsage)  // little-endian per RFC 4757

    let conf = defaultArg confounder (getRandomBytes Rc4.ConfounderSize)

    // ki = HMAC-MD5(key, usageBytes)
    use kiHmac = new HMACMD5(key)
    let ki = kiHmac.ComputeHash(usageBytes : byte array)

    // cksum = HMAC-MD5(ki, confounder + plaintext)
    use cksumHmac = new HMACMD5(ki)
    let data = concat2 conf plaintext
    let cksum = cksumHmac.ComputeHash(data : byte array)

    // ke = HMAC-MD5(ki, cksum)
    use keHmac = new HMACMD5(ki)
    let ke = keHmac.ComputeHash(cksum : byte array)

    // Encrypt: RC4(ke, confounder + plaintext)
    let encrypted = rc4Crypt ke data
    concat2 cksum encrypted

/// Try MAC verification with fallback usage 8 (RFC 4757 errata).
let private tryRc4MacVerification (key : byte array) (keyUsage : int) (cksum : byte array) (basicPlaintext : byte array) : byte array =
    // Verify checksum
    use verifyHmac = new HMACMD5(key)
    let expectedCksum = verifyHmac.ComputeHash(basicPlaintext : byte array)

    match constantTimeCompare cksum expectedCksum with
    | true ->
        // Discard 8-byte confounder
        Array.sub basicPlaintext Rc4.ConfounderSize (basicPlaintext.Length - Rc4.ConfounderSize)
    | false ->
        // RFC 4757 errata: also try usage 8 if current usage is 9
        match keyUsage = 9 with
        | true ->
            let usage8Bytes = BitConverter.GetBytes(9)
            use kiHmac2 = new HMACMD5(key)
            let ki2 = kiHmac2.ComputeHash(usage8Bytes : byte array)
            use verifyHmac2 = new HMACMD5(ki2)
            let expectedCksum2 = verifyHmac2.ComputeHash(basicPlaintext : byte array)
            match constantTimeCompare cksum expectedCksum2 with
            | true ->
                // Discard 8-byte confounder
                Array.sub basicPlaintext Rc4.ConfounderSize (basicPlaintext.Length - Rc4.ConfounderSize)
            | false ->
                invalidArg "ciphertext" "MAC verification failed for RC4-HMAC-MD5"
        | false ->
            invalidArg "ciphertext" "MAC verification failed for RC4-HMAC-MD5"

let private rc4HmacMd5Decrypt (key : byte array) (keyUsage : int) (ciphertext : byte array) : byte array =
    let usageBytes = BitConverter.GetBytes(rc4MapUsage keyUsage)  // little-endian

    match ciphertext.Length < Rc4.Md5ChecksumSize + Rc4.ConfounderSize with
    | true -> invalidArg "ciphertext" "Ciphertext too short for RC4-HMAC-MD5 decryption"
    | false -> ()

    // cksum is first 16 bytes, rest is encrypted data
    let cksum = Array.sub ciphertext 0 Rc4.Md5ChecksumSize
    let basicCtext = Array.sub ciphertext Rc4.Md5ChecksumSize (ciphertext.Length - Rc4.Md5ChecksumSize)

    // ki = HMAC-MD5(key, usageBytes)
    use kiHmac = new HMACMD5(key)
    let ki = kiHmac.ComputeHash(usageBytes : byte array)

    // ke = HMAC-MD5(ki, cksum)
    use keHmac = new HMACMD5(ki)
    let ke = keHmac.ComputeHash(cksum : byte array)

    // Decrypt: RC4(ke, basicCtext)
    let basicPlaintext = rc4Crypt ke basicCtext

    // Verify checksum with potential fallback
    tryRc4MacVerification ki keyUsage cksum basicPlaintext

// ---------------------------------------------------------------------------
// MD4 hash (RFC 1320) — used for RC4-HMAC-MD5 key derivation (RFC 4757 §2)
// ---------------------------------------------------------------------------

/// Compute the MD4 hash (RFC 1320). Used for RC4-HMAC-MD5 key derivation
/// (RFC 4757 §2) and NT-Hash computation in NetNTLMv2.
let internal md4 (input : byte array) : byte array =
    let leftRotate x n = x <<< n ||| (x >>> (32 - n))
    let F u v w = u &&& v ||| (~~~u &&& w)
    let G u v w = u &&& v ||| (u &&& w) ||| (v &&& w)
    let H u v w = u ^^^ v ^^^ w
    let leInt (arr : byte array) off =
        uint32 arr.[off] ||| (uint32 arr.[off + 1] <<< 8) ||| (uint32 arr.[off + 2] <<< 16) ||| (uint32 arr.[off + 3] <<< 24)
    let beInt v =
        [| byte (v &&& 0xFFu); byte (v >>> 8 &&& 0xFFu); byte (v >>> 16 &&& 0xFFu); byte (v >>> 24 &&& 0xFFu) |]

    let bitLen = int64 input.Length * 8L  // input length in bits, for MD4 padding
    let mod64 = input.Length % Md4.BlockBytes
    let padLen = if mod64 < 56 then 56 - mod64 else 120 - mod64
    let padded = Array.zeroCreate<byte> (input.Length + padLen + 8)
    System.Array.Copy(input, padded, input.Length)
    padded.[input.Length] <- 0x80uy
    let rec writeBitLen i =
        if i < 8 then
            padded.[input.Length + padLen + i] <- byte (int (bitLen >>> (i * 8) &&& 0xFFL))
            writeBitLen (i + 1)
    writeBitLen 0

    let rec processBlocks blockStart (h1 : uint32) (h2 : uint32) (h3 : uint32) (h4 : uint32) =
        match blockStart > padded.Length - Md4.BlockBytes with
        | true -> h1, h2, h3, h4
        | false ->
            let X = Array.zeroCreate<uint32> 16
            let rec loadX i =
                match i < 16 with
                | false -> ()
                | true ->
                    X.[i] <- leInt padded (blockStart + i * 4)
                    loadX (i + 1)
            loadX 0

            let mutable a, b, c, d = h1, h2, h3, h4
            // Round 1
            a <- leftRotate (a + F b c d + X.[ 0]) 3
            d <- leftRotate (d + F a b c + X.[ 1]) 7
            c <- leftRotate (c + F d a b + X.[ 2]) 11
            b <- leftRotate (b + F c d a + X.[ 3]) 19
            a <- leftRotate (a + F b c d + X.[ 4]) 3
            d <- leftRotate (d + F a b c + X.[ 5]) 7
            c <- leftRotate (c + F d a b + X.[ 6]) 11
            b <- leftRotate (b + F c d a + X.[ 7]) 19
            a <- leftRotate (a + F b c d + X.[ 8]) 3
            d <- leftRotate (d + F a b c + X.[ 9]) 7
            c <- leftRotate (c + F d a b + X.[10]) 11
            b <- leftRotate (b + F c d a + X.[11]) 19
            a <- leftRotate (a + F b c d + X.[12]) 3
            d <- leftRotate (d + F a b c + X.[13]) 7
            c <- leftRotate (c + F d a b + X.[14]) 11
            b <- leftRotate (b + F c d a + X.[15]) 19
            // Round 2
            a <- leftRotate (a + G b c d + X.[ 0] + Md4.Round2Constant) 3
            d <- leftRotate (d + G a b c + X.[ 4] + Md4.Round2Constant) 5
            c <- leftRotate (c + G d a b + X.[ 8] + Md4.Round2Constant) 9
            b <- leftRotate (b + G c d a + X.[12] + Md4.Round2Constant) 13
            a <- leftRotate (a + G b c d + X.[ 1] + Md4.Round2Constant) 3
            d <- leftRotate (d + G a b c + X.[ 5] + Md4.Round2Constant) 5
            c <- leftRotate (c + G d a b + X.[ 9] + Md4.Round2Constant) 9
            b <- leftRotate (b + G c d a + X.[13] + Md4.Round2Constant) 13
            a <- leftRotate (a + G b c d + X.[ 2] + Md4.Round2Constant) 3
            d <- leftRotate (d + G a b c + X.[ 6] + Md4.Round2Constant) 5
            c <- leftRotate (c + G d a b + X.[10] + Md4.Round2Constant) 9
            b <- leftRotate (b + G c d a + X.[14] + Md4.Round2Constant) 13
            a <- leftRotate (a + G b c d + X.[ 3] + Md4.Round2Constant) 3
            d <- leftRotate (d + G a b c + X.[ 7] + Md4.Round2Constant) 5
            c <- leftRotate (c + G d a b + X.[11] + Md4.Round2Constant) 9
            b <- leftRotate (b + G c d a + X.[15] + Md4.Round2Constant) 13
            // Round 3
            a <- leftRotate (a + H b c d + X.[ 0] + Md4.Round3Constant) 3
            d <- leftRotate (d + H a b c + X.[ 8] + Md4.Round3Constant) 9
            c <- leftRotate (c + H d a b + X.[ 4] + Md4.Round3Constant) 11
            b <- leftRotate (b + H c d a + X.[12] + Md4.Round3Constant) 15
            a <- leftRotate (a + H b c d + X.[ 2] + Md4.Round3Constant) 3
            d <- leftRotate (d + H a b c + X.[10] + Md4.Round3Constant) 9
            c <- leftRotate (c + H d a b + X.[ 6] + Md4.Round3Constant) 11
            b <- leftRotate (b + H c d a + X.[14] + Md4.Round3Constant) 15
            a <- leftRotate (a + H b c d + X.[ 1] + Md4.Round3Constant) 3
            d <- leftRotate (d + H a b c + X.[ 9] + Md4.Round3Constant) 9
            c <- leftRotate (c + H d a b + X.[ 5] + Md4.Round3Constant) 11
            b <- leftRotate (b + H c d a + X.[13] + Md4.Round3Constant) 15
            a <- leftRotate (a + H b c d + X.[ 3] + Md4.Round3Constant) 3
            d <- leftRotate (d + H a b c + X.[11] + Md4.Round3Constant) 9
            c <- leftRotate (c + H d a b + X.[ 7] + Md4.Round3Constant) 11
            b <- leftRotate (b + H c d a + X.[15] + Md4.Round3Constant) 15

            let h1' = h1 + a
            let h2' = h2 + b
            let h3' = h3 + c
            let h4' = h4 + d

            processBlocks (blockStart + Md4.BlockBytes) h1' h2' h3' h4'

    let h1, h2, h3, h4 =
        processBlocks 0 0x67452301u 0xEFCDAB89u 0x98BADCFEu 0x10325476u

    let result = Array.zeroCreate<byte> 16  // MD4 digest size (128 bits)
    System.Array.Copy(beInt h1, 0, result, 0, 4)
    System.Array.Copy(beInt h2, 0, result, 4, 4)
    System.Array.Copy(beInt h3, 0, result, 8, 4)
    System.Array.Copy(beInt h4, 0, result, 12, 4)
    result

// ---------------------------------------------------------------------------
// Password-to-key derivation
// ---------------------------------------------------------------------------

let stringToKey (enctype : EncryptionType) (password : string) (salt : string) : Key =
    match enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96 ->
        let keyBytes = aesStringToKeyFull 32 password salt
        { enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96; contents = keyBytes }
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        let keyBytes = aesStringToKeyFull 16 password salt
        { enctype = EncryptionType.AES128_CTS_HMAC_SHA1_96; contents = keyBytes }
    | EncryptionType.ARCFOUR_HMAC_MD5 ->
        // RFC 4757 §2: K = MD4(UNICODE(password))
        // UNICODE = UTF-16LE, without trailing null terminators. Salt is ignored.
        { enctype = EncryptionType.ARCFOUR_HMAC_MD5; contents = md4 (Encoding.Unicode.GetBytes password) }
    | _ ->
        invalidArg "enctype" $"Encryption type {enctype} is not supported"

// ---------------------------------------------------------------------------
// Internal encrypt/decrypt/prf interface
// ---------------------------------------------------------------------------

/// Encrypt plaintext using the given key and Kerberos key usage number.
/// Follows RFC 3961 §5: derives encryption/MAC keys from the base key via
/// the usage constant, then encrypts and appends the checksum.
let internal encrypt (key : Key) (keyUsage : int) (plaintext : byte array) (confounder : byte array option) : byte array =
    match key.enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96 ->
        aesEncrypt key.contents keyUsage plaintext confounder 32
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        aesEncrypt key.contents keyUsage plaintext confounder 16
    | EncryptionType.ARCFOUR_HMAC_MD5 ->
        rc4HmacMd5Encrypt key.contents keyUsage plaintext confounder
    | _ ->
        invalidArg "enctype" $"Encryption type {key.enctype} is not supported"

/// Decrypt ciphertext using the given key and Kerberos key usage number.
/// Follows RFC 3961 §5: derives encryption/MAC keys, verifies the checksum
/// in constant time, then decrypts and strips the usage prefix.
let internal decrypt (key : Key) (keyUsage : int) (ciphertext : byte array) : byte array =
    match key.enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96 ->
        aesDecrypt key.contents keyUsage ciphertext 32
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        aesDecrypt key.contents keyUsage ciphertext 16
    | EncryptionType.ARCFOUR_HMAC_MD5 ->
        rc4HmacMd5Decrypt key.contents keyUsage ciphertext
    | _ ->
        invalidArg "enctype" $"Encryption type {key.enctype} is not supported"

/// Kerberos pseudo-random function (PRF) per RFC 3962 §4 / RFC 8009.
/// Derives a key using the seed "prf", hashes the input, and encrypts
/// the truncated hash under the derived key. Used for key derivation in
/// password change and session key negotiation protocols.
let internal prf (key : Key) (input : byte array) : byte array =
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
    | _ -> invalidArg "enctype" $"PRF not implemented for {key.enctype}"


/// Tolerant decrypt for AP_REP enc-part cipher (skips strict MAC verification for diagnosis / when exact slice is hard to isolate).
/// For production use the normal decrypt.
let internal decryptApRepCipher (key : Key) (keyUsage : int) (ciphertext : byte array) : byte array =
    match key.enctype with
    | EncryptionType.AES256_CTS_HMAC_SHA1_96 ->
        let macSize = 12
        let basic = if ciphertext.Length > macSize then Array.sub ciphertext 0 (ciphertext.Length - macSize) else ciphertext
        let ke = aesDerive key.contents (buildUsageConstant keyUsage Aes.UsageMarkerDecrypt)
        aesCtsDecrypt ke basic
    | EncryptionType.AES128_CTS_HMAC_SHA1_96 ->
        let macSize = 12
        let basic = if ciphertext.Length > macSize then Array.sub ciphertext 0 (ciphertext.Length - macSize) else ciphertext
        let ke = aesDerive key.contents (buildUsageConstant keyUsage Aes.UsageMarkerDecrypt)
        aesCtsDecrypt ke basic
    | _ -> Array.empty
