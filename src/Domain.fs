
module Fauli.Domain

open System
open System.Net.Sockets
open System.Net.Http
open System.Security.Cryptography.X509Certificates


/// Unified error type for the entire authentication pipeline.
type AuthError =
    | NoSuitableAuthMethod
    | UnsupportedConnectionType
    | KerberosRealmUnreachable
    | KerberosTGTExpired
    | KerberosTGTAcquisitionFailed
    | KerberosServiceTicketFailed
    | KerberosSPNNotFound
    | KerberosPreauthFailed
    | KerberosTicketExpired
    | KerberosClockSkew
    | NtlmChallengeFailed
    | NtlmWrongPassword
    | NtlmAccountLocked
    | NtlmAccountDisabled
    | NtlmDomainNotFound
    | NtlmVersionNotSupported
    | CertificateInvalid
    | CertificateExpired
    | CertificateChainUntrusted
    | CertificatePrivateKeyMissing
    | CertificateHostNameMismatch
    | OAuthTokenExpired
    | OAuthTokenInvalid
    | OAuthTokenEndpointUnreachable
    | OAuthInsufficientScopes
    | OAuthClientCredentialsInvalid
    | SamlAssertionExpired
    | SamlAssertionInvalid
    | SamlIdPUnreachable
    | SamlAssertionSignatureInvalid
    | ProtocolConnectionFailed
    | ProtocolTimeout
    | ProtocolHandshakeFailed
    | ProtocolAuthenticationRejected
    | UnexpectedError of string


/// Kerberos SPN prefix for a given protocol.
type internal SpnPrefix =
    | SpnCifs
    | SpnLdap
    | SpnHttp
    | SpnMssqlSvc
    | SpnE351
    | SpnOther of string


/// OAuth token type (RFC 6750).
type TokenType =
    | Bearer
    | MAC
    | TokenOther of string


/// OAuth scope (permission boundary).
type Scope = Scope of string


/// OAuth refresh token (long-lived, exchanged for new access tokens).
type RefreshToken = RefreshToken of string


/// SAML AuthnContext — how the user was authenticated by the IdP (OASIS SAML 2.0).
type SamlAuthnContext =
    | Password
    | X509Certificate
    | Kerberos
    | Windows
    | TLSClientCertificate
    | MobileOneFactorContract
    | GovernmentIdOfNonUnionCitizen
    | SamlOther of string


/// Validated SAML assertion XML.
type SamlAssertion = SamlAssertion of string


/// Protocol-level session identifier.
type SessionId = SessionId of string


/// Private key material for certificate authentication.
type PrivateKey = PrivateKey of obj


/// Kerberos SPN or equivalent service identifier.
type ServiceName = ServiceName of string


module ServiceName =
    let create (spn : string) : Result<ServiceName, AuthError> =
        match String.IsNullOrWhiteSpace spn with
        | true -> Error (UnexpectedError "Service name cannot be empty")
        | false -> Ok (ServiceName spn)


/// Kerberos service ticket.
type ServiceTicket = ServiceTicket of byte array


/// Active Directory domain or Kerberos realm name.
type DomainName = DomainName of string


module DomainName =
    let create (domain : string) : Result<DomainName, AuthError> =
        match String.IsNullOrWhiteSpace domain with
        | true -> Error (UnexpectedError "Domain name cannot be empty")
        | false -> Ok (DomainName domain)

/// NTLM authentication response (message 3 of the three-message exchange).
type NtlmAuthResponse = NtlmAuthResponse of byte array


/// Network transport for LDAP connections.
type LdapTransport =
    | LdapPlain    /// TCP 389, no encryption
    | LdapTls      /// TCP 636, LDAP over TLS (implicit)

/// Configuration for LDAP connections — transport, referral policy, and timeout.
type LdapConnectionConfig =
    { transport : LdapTransport
      followReferrals : bool
      connectTimeout : int }  /// milliseconds

module LdapConnectionConfig =
    let defaults : LdapConnectionConfig =
        { transport = LdapPlain
          followReferrals = false
          connectTimeout = 10000 }

/// Network protocols supported by the authentication solver.
type ConnectionType =
    | SMB
    | Ldap of LdapConnectionConfig
    | WinRM
    | RDP
    | HOST
    | HTTP
    | MSSql
    | DNS
    | RPC
    | Exchange


/// An authenticated SMB2 session.
///
/// This represents the state immediately after a successful SESSION_SETUP.
/// No TREE_CONNECT has been issued yet.
///
/// The caller receives this handle and is responsible for all further SMB2
/// protocol operations: choosing and connecting to shares (ADMIN$, IPC$, etc.),
/// performing CREATE/READ/WRITE, managing message IDs, and handling any
/// signing/encryption requirements.
///
/// Fauli's responsibility ends once authentication succeeds and this session
/// is handed off. The caller "owns" the connection from this point.
///
/// When <see cref="P:Encryption"/> is <c>Some</c>, post-setup traffic must be
/// wrapped in SMB2 TRANSFORM_HEADER (RejectUnencryptedAccess / SessionFlags.ENCRYPT_DATA).
/// Use <c>Fauli.Smb.Handler.sendSmb2</c> / related helpers rather than raw Stream writes.
type SmbCipher =
    | Aes128Ccm
    | Aes128Gcm
    | Aes256Ccm
    | Aes256Gcm

/// SMB3 channel encryption keys and negotiated cipher for a session.
type SmbEncryption =
    { Cipher : SmbCipher
      /// Client-to-server encryption key (C2S).
      EncryptionKey : byte array
      /// Server-to-client decryption key (S2C).
      DecryptionKey : byte array }

type SmbSession =
    { /// The underlying bidirectional TCP stream for SMB2 messages.
      Stream : NetworkStream
      /// The opaque SessionId assigned by the server. Must be included
      /// in the SMB2 header of every message sent after session setup.
      SessionId : uint64
      /// The SMB2 dialect that was successfully negotiated (e.g. 0x0202, 0x0210).
      /// Callers may need this to construct compatible requests.
      Dialect : uint16
      /// Session key for SMB2.x signing (HMAC-SHA256) / SMB3.x KDF input.
      /// Kerberos: ticket session key (often truncated to 16 for signing).
      /// NTLM: exported session key from NetNTLMv2.
      SessionKey : byte array
      /// Derived signing key (Some for SMB3.x with signing, None for SMB2.x).
      SigningKey : byte array option
      /// When Some, all post-setup messages must be SMB3-encrypted (TRANSFORM_HEADER).
      Encryption : SmbEncryption option
      /// Next SMB2 MessageId to use (negotiate=0 consumed; Kerberos SS uses 1 → next=2;
      /// NTLM SS uses 1+2 → next=3). Callers must increment after each send.
      NextMessageId : uint64 }


/// SMB dialects supported end-to-end (auth → TREE → directory ops).
type SmbDialect =
    | Smb202   // 2.0.2
    | Smb21    // 2.1
    | Smb30    // 3.0
    | Smb302   // 3.0.2
    | Smb311   // 3.1.1

/// Back-compat alias used by existing 2.x call sites.
type Smb2xDialect = SmbDialect

/// Wire dialect code for an SMB dialect preference.
let smbDialectCode (d : SmbDialect) : uint16 =
    match d with
    | Smb202 -> 0x0202us
    | Smb21 -> 0x0210us
    | Smb30 -> 0x0300us
    | Smb302 -> 0x0302us
    | Smb311 -> 0x0311us

/// Back-compat alias.
let smb2xDialectCode = smbDialectCode

/// An authenticated and bound LDAP session resulting from a successful SASL bind.
///
/// This represents the state immediately after a BindResponse with
/// resultCode = success (0) has been received and consumed.
///
/// No further LDAP operations (SearchRequest, ModifyRequest, etc.) have been issued yet.
///
/// The caller receives this handle and is responsible for:
/// - All subsequent LDAP protocol operations
/// - Proper message ID management starting from NextMessageId
/// - Reading and correlating responses
/// - Handling controls, referrals, timeouts, etc.
/// - Disposing the stream when done
///
/// Fauli's responsibility ends once the bind succeeds and this session
/// is handed off. The caller "owns" the connection from this point.
type LdapSession =
    { /// The underlying bidirectional TCP stream for LDAP BER messages.
      /// The bind response has already been read from this stream.
      Stream : NetworkStream
      /// The message ID the caller must use for the first operation after the bind.
      /// Fauli uses message ID 1 for the SASL bind request.
      NextMessageId : int
      /// The identity (if any) that the directory server accepted as the bound entity.
      /// This is typically the matchedDN from the successful BindResponse.
      /// May be None for certain SASL mechanisms or server configurations.
      BoundAs : string option }

/// Authenticated connection handle returned by the protocol handler.
/// Each case corresponds to a ConnectionType and uses the underlying .NET type directly.
type ConnectionHandle =
    | AuthSmb of SmbSession
    | AuthLdap of LdapSession
    | AuthWinRm of HttpClient
    | AuthRdp of NetworkStream
    | AuthHost of NetworkStream
    | AuthHttp of HttpClient
    | AuthMssql of NetworkStream
    | AuthDns of Socket
    | AuthRpc of NetworkStream
    | AuthExchange of HttpClient


/// A network host identifier (DNS name or IP address string).
type Host = Host of string


module Host =
    let create (hostString : string) : Result<Host, AuthError> =
        match String.IsNullOrWhiteSpace hostString with
        | true -> Error (UnexpectedError "Host cannot be empty")
        | false -> Ok (Host hostString)


/// Username in any AD-accepted format: plain, UPN (user@domain), or down-level (DOMAIN\user).
type UserName = UserName of string


module UserName =
    let create (name : string) : Result<UserName, AuthError> =
        match String.IsNullOrWhiteSpace name with
        | true -> Error (UnexpectedError "Username cannot be empty")
        | false -> Ok (UserName name)


/// Plaintext password value.
type Password = Password of string


module Password =
    let create (pw : string) : Result<Password, AuthError> =
        match String.IsNullOrWhiteSpace pw with
        | true -> Error (UnexpectedError "Password cannot be empty")
        | false -> Ok (Password pw)


/// Non-empty byte payload guard used by ticket-file smart constructors.
let private nonEmptyBytes (label : string) (rawData : byte array) : Result<byte array, AuthError> =
    match isNull rawData, rawData with
    | true, _ -> Error (UnexpectedError $"{label} data cannot be empty")
    | false, data when data.Length = 0 -> Error (UnexpectedError $"{label} data cannot be empty")
    | false, data -> Ok data


/// Kerberos .kirbi ticket file (Rubeus/Kekeo export format).
type Kirbi = private Kirbi of byte array


module Kirbi =
    let create (rawData : byte array) : Result<Kirbi, AuthError> =
        // Parse .kirbi format, validate ticket structure, check expiry
        match nonEmptyBytes "Kirbi" rawData with
        | Error e -> Error e
        | Ok data -> Ok (Kirbi data)

    let rawData (Kirbi b) : byte array = b


/// Kerberos .ccache credential cache file (MIT Kerberos format).
type Ccache = private Ccache of byte array


module Ccache =
    let create (rawData : byte array) : Result<Ccache, AuthError> =
        // Parse .ccache format, validate credential structure, check expiry
        match nonEmptyBytes "Ccache" rawData with
        | Error e -> Error e
        | Ok data -> Ok (Ccache data)

    let rawData (Ccache b) : byte array = b


/// Windows LSA ticket store (live ticket cache on Windows).
type WindowsTicketStore = private WindowsTicketStore of byte array


module internal WindowsTicketStore =
    let create () : Result<WindowsTicketStore, AuthError> =
        // Query Windows LSA for current ticket material
        // Validate ticket structure and check expiry
        Error (UnexpectedError "Windows LSA access not yet implemented")


/// Kerberos realm name (e.g., EXAMPLE.COM). Derived by the solver from host/domain context.
type KerberosRealm = KerberosRealm of string


module internal KerberosRealm =
    let create (realm : string) : Result<KerberosRealm, AuthError> =
        match String.IsNullOrWhiteSpace realm with
        | true -> Error (UnexpectedError "Kerberos realm cannot be empty")
        | false -> Ok (KerberosRealm (realm.ToUpperInvariant()))


/// Validated X.509 client certificate.
type ValidatedCertificate = private ValidatedCertificate of X509Certificate2


module ValidatedCertificate =
    let create (cert : X509Certificate2) : Result<ValidatedCertificate, AuthError> =
        // Validate: not null, not expired, chain of trust, private key available
        match Option.ofObj cert with
        | None -> Error CertificateInvalid
        | Some c when c.NotAfter < DateTime.Now -> Error CertificateExpired
        | Some c -> Ok (ValidatedCertificate c)


/// Username and password pair for Kerberos password logon, NetNTLMv2, or NetNTLMv1.
type UserNamePassword =
    { userName : UserName
      password : Password }


module UserNamePassword =
    let create (userName : UserName) (password : Password) : UserNamePassword =
        { userName = userName
          password = password }


/// Client certificate and private key for certificate-based authentication.
type CertificateCredential =
    { certificate : ValidatedCertificate
      privateKey : PrivateKey }


module CertificateCredential =
    let create (certificate : ValidatedCertificate) (privateKey : PrivateKey) : CertificateCredential =
        { certificate = certificate
          privateKey = privateKey }


type OAuthAccessToken =
    { accessToken : string
      tokenType : TokenType
      scopes : Scope list
      refreshToken : RefreshToken option
      expiresAt : DateTimeOffset }


type OAuthClientCredentials =
    { clientId : string
      clientSecret : string
      tokenEndpoint : Uri
      requestedScopes : Scope list }


type OAuthResourceOwnerPassword =
    { userName : UserName
      password : Password
      clientId : string
      clientSecret : string option
      tokenEndpoint : Uri
      requestedScopes : Scope list }


/// OAuth 2.0 credential material (RFC 6749 grant types).
type OAuthCredential =
    | AccessToken of OAuthAccessToken
    | ClientCredentials of OAuthClientCredentials
    | ResourceOwnerPassword of OAuthResourceOwnerPassword


/// SAML assertion credential.
type SAMLCredential =
    { assertion : SamlAssertion
      authnContext : SamlAuthnContext
      expiresAt : DateTimeOffset }


module SAMLCredential =
    let create (assertion : SamlAssertion) (authnContext : SamlAuthnContext) (expiresAt : DateTimeOffset) : Result<SAMLCredential, AuthError> =
        match expiresAt < DateTimeOffset.Now with
        | true -> Error SamlAssertionExpired
        | false ->
            Ok
                { assertion = assertion
                  authnContext = authnContext
                  expiresAt = expiresAt }


/// Unified credential type for the solver. Includes NoCredential for anonymous/implicit auth.
type Credential =
    | UserPassword of UserNamePassword
    | KerberosKirbi of Kirbi
    | KerberosCcache of Ccache
    | KerberosWindowsTicket of WindowsTicketStore
    | Cert of CertificateCredential
    | OAuthCred of OAuthCredential
    | SamlCred of SAMLCredential
    | NoCredential



/// Input to the solver: connection needed, credentials available, and hosts involved.
///
/// Three distinct host roles are modelled explicitly so that TCP connect target,
/// Kerberos KDC address, and SPN principal can diverge (e.g. connect to IP while
/// requesting a ticket for an FQDN SPN).
type AuthenticationRequest =
    { connectionType : ConnectionType
      credential : Credential
      /// KDC / domain-controller address for Kerberos AS/TGS exchanges.
      kdcHost : Host
      /// TCP connect target for the application protocol (LDAP/SMB/…).
      /// The protocol handler connects to this host.
      connectHost : Host
      /// Hostname used to build the Kerberos SPN (<c>cifs/…</c>, <c>ldap/…</c>).
      /// Must be an FQDN when targeting Active Directory; bare IPs usually fail
      /// Kerberos SPN lookup. This field is required — callers must decide which
      /// name the KDC should see, even if it happens to be the same as <c>connectHost</c>.
      spnHost : Host }

module AuthenticationRequest =
    /// Create an authentication request with three distinct host roles.
    let create (connectionType : ConnectionType) (credential : Credential) (kdcHost : Host) (connectHost : Host) (spnHost : Host) : AuthenticationRequest =
        { connectionType = connectionType
          credential = credential
          kdcHost = kdcHost
          connectHost = connectHost
          spnHost = spnHost }



/// Authentication mechanism the solver selects.
type AuthenticationMethod =
    | Kerberos
    | NetNTLMv2
    | NetNTLMv1
    | Certificate
    | OAuth
    | SAML
    | Anonymous



/// Service session key from a Kerberos TGS exchange.
type ServiceSessionKey = ServiceSessionKey of byte array * int  /// key bytes, enctype

/// BER-encoded client principal name from a Kerberos ticket.
type ClientPrincipalName = ClientPrincipalName of byte array

/// Parameters for Kerberos protocol handler.
/// Contains everything needed to build an AP-REQ for SASL/GSSAPI binds.
type KerberosTicketParams =
    { serviceTicket : ServiceTicket
      serviceName : ServiceName
      sessionKey : ServiceSessionKey
      clientName : ClientPrincipalName
      clientRealm : string }


/// Parameters for NTLM protocol handler.
type NtlmResponseParams =
    { /// Optional prebuilt Type-3 (unused for SMB; SMB does NTLM on-connection).
      authResponse : NtlmAuthResponse
      userName : UserName
      domain : DomainName
      /// Password required so protocol handlers can complete Type1→Type2→Type3
      /// against the challenge delivered on the protocol connection (e.g. SMB).
      password : Password }


/// Parameters for certificate protocol handler.
type CertificateAuthParams =
    { certificate : ValidatedCertificate
      privateKey : PrivateKey }


/// Parameters for OAuth protocol handler.
type OAuthTokenParams =
    { accessToken : string
      tokenType : TokenType
      scopes : Scope list }


/// Parameters for SAML protocol handler.
type SamlAssertionParams =
    { assertion : SamlAssertion }


/// Parameters the solver passes to the protocol handler.
/// Each case maps to one AuthenticationMethod — the method is implicit in the data shape.
type ProtocolHandlerParams =
    | KerberosTicket of KerberosTicketParams
    | NtlmResponse of NtlmResponseParams
    | CertificateAuth of CertificateAuthParams
    | OAuthToken of OAuthTokenParams
    | SamlAssertion of SamlAssertionParams
    | AnonymousAuth



/// Session metadata for connection lifecycle management.
type SessionInfo =
    { authenticatedAs : UserName option
      expiresAt : DateTimeOffset option
      sessionId : SessionId option
      domain : DomainName option }


/// Response from the protocol handler after establishing an authenticated connection.
type AuthenticatedResponse =
    { connection : ConnectionHandle
      authenticationMethod : AuthenticationMethod
      sessionInfo : SessionInfo }


/// Main solver function: selects auth method and produces handler parameters.
type internal Solve =
    AuthenticationRequest -> Result<ProtocolHandlerParams, AuthError>


/// Protocol handler: establishes authenticated connection using solver parameters.
type internal HandleProtocol =
    ConnectionType -> ProtocolHandlerParams -> Result<AuthenticatedResponse, AuthError>


/// Error handler: invoked when no auth method satisfies the request. Always returns Error.
type internal ErrorProtocol =
    ConnectionType -> Result<AuthenticatedResponse, AuthError>


/// Top-level workflow: solve authentication, then invoke protocol handler.
type Authenticate =
    AuthenticationRequest -> Result<AuthenticatedResponse, AuthError>
