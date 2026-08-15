module internal Fauli.Constants

// ---------------------------------------------------------------------------
// Kerberos protocol constants (RFC 4120)
// ---------------------------------------------------------------------------

module Kerberos =

    /// PrincipalName name-type: simple string (e.g. "Administrator").
    let NamePrincipal = 1

    /// PrincipalName name-type: service instance (e.g. "cifs/server.domain.com").
    let NameSrvInst = 2

    /// KDC_ERR_PREAUTH_FAILED (24) — pre-authentication data was invalid.
    let KrbPreauthFailed = 0x18

    /// PA-PAC-REQUEST padata type (128) — request a Privilege Attribute Certificate.
    let PaPacRequest = 128

// ---------------------------------------------------------------------------
// AES CTS / simplified profile constants (RFC 3961 / RFC 3962)
// ---------------------------------------------------------------------------

module Aes =

    /// AES block size in bytes.
    let BlockSize = 16

    /// Truncated HMAC-SHA1 size for the simplified profile (96 bits).
    let MacSize = 12

    /// Usage constant marker byte for the encryption key derivation (0xAA).
    let UsageMarkerEncrypt = 0x55uy

    /// Usage constant marker byte for the decryption key derivation (0x55).
    let UsageMarkerDecrypt = 0xAAuy

// ---------------------------------------------------------------------------
// RC4-HMAC-MD5 constants (RFC 4757)
// ---------------------------------------------------------------------------

module Rc4 =

    /// Size of the RC4 S-box state array.
    let StateSize = 256

    /// MD5 checksum length in bytes (prepended to ciphertext).
    let Md5ChecksumSize = 16

    /// Confounder length in bytes (random, prepended to plaintext).
    let ConfounderSize = 8

    /// Byte mask for RC4 index arithmetic.
    let Mask = 0xFF

// ---------------------------------------------------------------------------
// MD4 constants (RFC 1320)
// ---------------------------------------------------------------------------

module Md4 =

    /// MD4 block size in bytes.
    let BlockBytes = 64

    /// Round 2 additive constant (0x5A827999).
    let Round2Constant = 0x5A827999u

    /// Round 3 additive constant (0x6ED9EBA1).
    let Round3Constant = 0x6ED9EBA1u

// ---------------------------------------------------------------------------
// GSS-API / SPNEGO mechanism OIDs (RFC 4178 / RFC 4121 / MS extensions)
// ---------------------------------------------------------------------------
/// Kerberos mechanism OID: 1.2.840.113554.1.2.2
let krb5MechOid = "1.2.840.113554.1.2.2"

/// MS Kerberos 5 OID (SPNEGO mechTypes extension): 1.2.840.113554.1.2.2.1
let msKrb5MechOid = "1.2.840.113554.1.2.2.1"

/// SPNEGO mechanism OID: 1.3.6.1.5.5.2
let snegoMechOid = "1.3.6.1.5.5.2"

/// NTLMSSP mechanism OID: 1.3.6.1.4.1.311.2.2.10
let ntlmsspMechOid = "1.3.6.1.4.1.311.2.2.10"

// ---------------------------------------------------------------------------
// ASN.1 BER tag bytes (used across GssApi, Kerberos, LDAP)
// ---------------------------------------------------------------------------
/// BER SEQUENCE tag (0x30).
let berSequence : byte = 0x30uy

/// BER OCTET STRING tag (0x04).
let berOctetString : byte = 0x04uy

/// BER INTEGER tag (0x02).
let berInteger : byte = 0x02uy

// ---------------------------------------------------------------------------
// NTLMSSP wire signature (8 bytes)
// ---------------------------------------------------------------------------
/// NTLMSSP magic bytes: "NTLMSSP\0".
let ntlmsspSignature : byte array = [| 0x4Euy; 0x54uy; 0x4Cuy; 0x4Duy; 0x53uy; 0x53uy; 0x50uy; 0x00uy |]

// ---------------------------------------------------------------------------
// SMB protocol constants (MS-SMB2)
// ---------------------------------------------------------------------------
/// SMB2 dialect code: 2.0.2.
let smbDialect202 : uint16 = 0x0202us

/// SMB2 dialect code: 2.1.
let smbDialect21 : uint16 = 0x0210us

/// SMB2 dialect code: 3.0.
let smbDialect30 : uint16 = 0x0300us

/// SMB2 dialect code: 3.0.2.
let smbDialect302 : uint16 = 0x0302us

/// SMB2 dialect code: 3.1.1.
let smbDialect311 : uint16 = 0x0311us

/// SMB2 NEGOTIATE_SIGNING_ENABLED (bit 0).
let smbNegotiateSigningEnabled : uint16 = 0x0001us

/// SMB2 protocol identifier: 0xFE + "SMB" (NetBIOS session).
let smb2ProtocolId : byte array = [| 0xFEuy; 0x53uy; 0x4Duy; 0x42uy |]

/// SMB3 transform header magic: 0xFD + "SMB".
let smbTransformHeaderMagic : byte array = [| 0xFDuy; 0x53uy; 0x4Duy; 0x42uy |]
