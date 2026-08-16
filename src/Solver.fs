module Fauli.Solver


open Fauli.Domain
open Fauli.MethodSelection
open Fauli.ServiceDiscovery
open Fauli.Kerberos.Auth
open Fauli.Kerberos.TicketIngestion
open Fauli.Smb.Handler
open Fauli.Ldap.Handler


///
/// Extract viable authentication methods from the request.
let private selectViableMethods (request : AuthenticationRequest) : AuthenticationMethod list =
    selectMethods request.connectionType request.credential


///
/// Username carried by a UserPassword credential, if any.
let private userNameFromCredential (credential : Credential) : UserName option =
    match credential with
    | UserPassword creds -> Some creds.userName
    | _ -> None


///
/// Client principal bytes from an optional cname BER value.
let private clientNameBytesFromCname (cname : Fauli.Kerberos.Parsing.BerValue option) : byte array =
    match cname with
    | Some cn -> berEncodeValue cn
    | None -> [||]


///
/// Build KerberosTicketParams from a service ticket result.
let private buildKerberosTicketParams (spn : ServiceName) (svcTicket : ServiceTicketResult) : ProtocolHandlerParams =
    let sessionKey = ServiceSessionKey (svcTicket.sessionKey.contents, int svcTicket.sessionKey.enctype)
    KerberosTicket
        { serviceTicket = ServiceTicket svcTicket.ticketBytes
          serviceName = spn
          sessionKey = sessionKey
          clientName = ClientPrincipalName (clientNameBytesFromCname svcTicket.cname)
          clientRealm = defaultArg svcTicket.crealm "" }


///
/// Map a service-ticket Result into ProtocolHandlerParams.
let private mapServiceTicketToParams (spn : ServiceName) (svcTicketResult : Result<ServiceTicketResult, AuthError>) : Result<ProtocolHandlerParams, AuthError> =
    match svcTicketResult with
    | Error e -> e |> Error
    | Ok svcTicket -> buildKerberosTicketParams spn svcTicket |> Ok


///
/// TGS exchange: TGT + SPN + realm → ProtocolHandlerParams.
let private acquireServiceTicketParams (kdcHost : string) (spn : ServiceName) (realmStr : string) (tgt : TgtResult) : Result<ProtocolHandlerParams, AuthError> =
    let (ServiceName spnStr) = spn
    getServiceTicket kdcHost tgt spnStr realmStr
    |> mapServiceTicketToParams spn


///
/// Password material required for AS-REQ, or NoSuitableAuthMethod.
let private passwordCredentialFromRequest (request : AuthenticationRequest) : Result<UserNamePassword, AuthError> =
    match request.credential with
    | UserPassword creds -> creds |> Ok
    | _ -> NoSuitableAuthMethod |> Error


///
/// Acquire TGT then service ticket for a password credential and resolved realm.
let private passwordKerberosWithRealm (request : AuthenticationRequest) (creds : UserNamePassword) (realm : KerberosRealm) : Result<ProtocolHandlerParams, AuthError> =
    let (Host kdcHost) = request.kdcHost
    let (KerberosRealm realmStr) = realm
    let (Password password) = creds.password
    let spn = serviceNameFor request.connectionType request.spnHost realm
    let principal = principalNameFromUserName creds.userName
    
    match getTgt kdcHost principal password realmStr with
    | Error e -> e |> Error
    | Ok tgt -> acquireServiceTicketParams kdcHost spn realmStr tgt


///
/// Password Kerberos: short principal + realm → TGT → service ticket.
let private tryKerberosPassword (request : AuthenticationRequest) (realm : KerberosRealm) : Result<ProtocolHandlerParams, AuthError> =
    match passwordCredentialFromRequest request with
    | Error e -> e |> Error
    | Ok creds -> passwordKerberosWithRealm request creds realm


///
/// Continue password Kerberos after realm resolution.
let private continuePasswordKerberos (request : AuthenticationRequest) (realmResult : Result<KerberosRealm, AuthError>) : Result<ProtocolHandlerParams, AuthError> =
    match realmResult with
    | Error e -> e |> Error
    | Ok realm -> tryKerberosPassword request realm


///
/// Derive realm (credential-first) then run password Kerberos.
let private tryKerberos (request : AuthenticationRequest) : Result<ProtocolHandlerParams, AuthError> =
    resolveRealm (userNameFromCredential request.credential) request.kdcHost
    |> continuePasswordKerberos request


///
/// After a TGT is in hand, resolve realm from the ticket, build SPN, acquire service ticket.
let private continueWithTgt (request : AuthenticationRequest) (tgt : TgtResult) : Result<ProtocolHandlerParams, AuthError> =
    match resolveRealmFromTgtCrealm tgt.crealm request.kdcHost with
    | Error e -> e |> Error
    | Ok realm ->
        let (Host kdcHost) = request.kdcHost
        let (KerberosRealm realmStr) = realm
        let spn = serviceNameFor request.connectionType request.spnHost realm
        acquireServiceTicketParams kdcHost spn realmStr tgt


///
/// Continue after TGT extraction from ticket material.
let private continueAfterTgtExtraction (request : AuthenticationRequest) (tgtResult : Result<TgtResult, AuthError>) : Result<ProtocolHandlerParams, AuthError> =
    match tgtResult with
    | Error e -> e |> Error
    | Ok tgt -> continueWithTgt request tgt


///
/// Authenticate using a .kirbi Kerberos ticket file.
/// Realm is harvested from the TGT crealm when present — host FQDN is only a fallback.
/// 
let private tryKerberosKirbi (request : AuthenticationRequest) (kirbi : Kirbi) : Result<ProtocolHandlerParams, AuthError> =
    Kirbi.rawData kirbi
    |> extractTgtFromKirbi
    |> continueAfterTgtExtraction request


///
/// Authenticate using a .ccache credential cache file.
/// Realm is harvested from the TGT crealm when present — host FQDN is only a fallback.
/// 
let private tryKerberosCcache (request : AuthenticationRequest) (ccache : Ccache) : Result<ProtocolHandlerParams, AuthError> =
    Ccache.rawData ccache
    |> extractTgtFromCcache
    |> continueAfterTgtExtraction request


///
/// Package resolved NTLM identity material for protocol handlers.
let private packageNtlmParams (creds : UserNamePassword) (domain : DomainName) : ProtocolHandlerParams =
    let shortName = principalNameFromUserName creds.userName
    NtlmResponse
        { authResponse = NtlmAuthResponse [||]
          userName = UserName shortName
          domain = domain
          password = creds.password }


///
/// Continue NetNTLMv2 after domain resolution.
let private continueNtlmAfterDomain (creds : UserNamePassword) (domainResult : Result<DomainName, AuthError>) : Result<ProtocolHandlerParams, AuthError> =
    match domainResult with
    | Error e -> e |> Error
    | Ok domain -> packageNtlmParams creds domain |> Ok


///
/// Package NTLM credentials for protocol handlers.
/// SMB (and similar) perform Type1→Type2→Type3 on the protocol connection using the password;
/// a separate raw-TCP NTLM exchange cannot supply the correct server challenge.
/// 
let private tryNetNtlmV2 (request : AuthenticationRequest) : Result<ProtocolHandlerParams, AuthError> =
    match request.credential with
    | UserPassword creds ->
        resolveDomain (Some creds.userName) request.kdcHost
        |> continueNtlmAfterDomain creds
    | _ -> NoSuitableAuthMethod |> Error


///
/// NetNTLMv1 is not yet supported; always returns an error.
let private tryNetNtlmV1 (_ : AuthenticationRequest) : Result<ProtocolHandlerParams, AuthError> =
    NtlmVersionNotSupported |> Error


///
/// Kerberos dispatch: ticket material vs password path.
let private attemptKerberos (request : AuthenticationRequest) : Result<ProtocolHandlerParams, AuthError> =
    match request.credential with
    | KerberosKirbi kirbi -> tryKerberosKirbi request kirbi
    | KerberosCcache ccache -> tryKerberosCcache request ccache
    | _ -> tryKerberos request


///
/// Dispatch an AuthenticationMethod to its solver function.
let private attemptMethod (method : AuthenticationMethod) (request : AuthenticationRequest) : Result<ProtocolHandlerParams, AuthError> =
    match method with
    | Kerberos -> attemptKerberos request
    | NetNTLMv2 -> tryNetNtlmV2 request
    | NetNTLMv1 -> tryNetNtlmV1 request
    | _ -> NoSuitableAuthMethod |> Error


///
/// Collapse the sequential attempt outcome when the method list is exhausted.
let private finalizeMethodAttempts (lastError : AuthError option) : Result<ProtocolHandlerParams, AuthError> =
    match lastError with
    | Some e -> e |> Error
    | None -> NoSuitableAuthMethod |> Error


///
/// Try a list of authentication methods sequentially.
/// Returns the first success, or the last error encountered.
/// 
let private tryMethodsSequentially (request : AuthenticationRequest) (methods : AuthenticationMethod list) : Result<ProtocolHandlerParams, AuthError> =
    let rec loop (remaining : AuthenticationMethod list) (lastError : AuthError option) : Result<ProtocolHandlerParams, AuthError> =
        match remaining with
        | [] -> finalizeMethodAttempts lastError
        | method :: rest ->
            match attemptMethod method request with
            | Ok result -> result |> Ok
            | Error e -> loop rest (Some e)
    loop methods None


///
/// Named step: select viable methods and try each in order.
/// All monadic logic lives inside this function and its callees.
/// 
let private produceProtocolHandlerParams (request : AuthenticationRequest) : Result<ProtocolHandlerParams, AuthError> =
    request
    |> selectViableMethods
    |> tryMethodsSequentially request


///
/// Named step: given a request and params, dispatch to the concrete handler
/// for the connection type. This completes the authentication and returns
/// the live connection handle.
/// 
let private executeAuthenticatedConnection (request : AuthenticationRequest) (authParams : ProtocolHandlerParams) : Result<AuthenticatedResponse, AuthError> =
    match request.connectionType with
    | SMB -> handleSmb request.connectHost authParams
    | Ldap config -> handleLdap request.connectHost config authParams
    | _ -> UnsupportedConnectionType |> Error


///
/// Named step that bridges the Result from param production into execution.
/// All Result handling is encapsulated here.
/// 
let private continueAfterParams (request : AuthenticationRequest) (paramsResult : Result<ProtocolHandlerParams, AuthError>) : Result<AuthenticatedResponse, AuthError> =
    match paramsResult with
    | Ok p -> executeAuthenticatedConnection request p
    | Error e -> e |> Error


///
/// <summary>
/// Public entry point for Fauli. Given an <see cref="T:Fauli.Domain.AuthenticationRequest"/>,
/// selects a viable authentication method, obtains the necessary auth material, opens an
/// authenticated connection to the target service, and returns an
/// <see cref="T:Fauli.Domain.AuthenticatedResponse"/> (or an <see cref="T:Fauli.Domain.AuthError"/>).
/// </summary>
///
/// <remarks>
/// <para><b>Pipeline</b></para>
/// <list type="number">
///   <item>Intersect credential methods with protocol methods (priority order).</item>
///   <item>Try each method until one produces handler params (first success wins).</item>
///   <item>Dispatch to the protocol handler for <c>connectionType</c> using <c>connectHost</c>.</item>
/// </list>
///
/// <para><b>Request fields</b></para>
/// <list type="table">
///   <listheader><term>Field</term><description>Role</description></listheader>
///   <item>
///     <term><c>connectionType</c></term>
///     <description>
///       Target protocol. Currently supported: <c>SMB</c>, <c>LDAP/S</c>.
///       All other cases return <c>UnsupportedConnectionType</c>.
///     </description>
///   </item>
///   <item>
///     <term><c>credential</c></term>
///     <description>
///       Auth material. Determines which methods are viable and where realm/domain come from.
///     </description>
///   </item>
///   <item>
///     <term><c>kdcHost</c></term>
///     <description>
///       KDC / domain controller address used for Kerberos AS/TGS and as the host used when
///       deriving realm/domain from FQDN. May be a bare IP when realm is supplied by the credential.
///     </description>
///   </item>
///   <item>
///     <term><c>connectHost</c></term>
///     <description>
///       TCP connect target for the application protocol (SMB :445, LDAP :389/:636).
///       This is the address the protocol handler will connect to.
///     </description>
///   </item>
///   <item>
///     <term><c>spnHost</c></term>
///     <description>
///       Hostname used to build the Kerberos SPN (<c>cifs/…</c>, <c>ldap/…</c>).
///       Must be an FQDN when targeting Active Directory; bare IPs usually fail
///       Kerberos SPN lookup and cause fallthrough to NTLM. This field is required
///       — callers must explicitly decide which name the KDC sees, even if it is
///       the same as <c>connectHost</c>.
///     </description>
///   </item>
/// </list>
///
/// <para><b>Method selection (credential × protocol)</b></para>
/// Viable methods are the intersection of what the credential can do and what the protocol accepts,
/// in credential priority order. For password creds against SMB/LDAP that is typically
/// <c>Kerberos</c> then <c>NetNTLMv2</c>. Empty intersection → <c>NoSuitableAuthMethod</c>
/// (e.g. <c>NoCredential</c> on SMB when Anonymous is filtered out by selection rules).
///
/// <para><b>Realm and domain resolution</b></para>
/// Kerberos realm and NTLM domain are resolved credential-first:
/// <list type="number">
///   <item>Username UPN (<c>user@AD-LAB.LOCAL</c>) or down-level (<c>DOMAIN\user</c>).</item>
///   <item>For kirbi/ccache: TGT <c>crealm</c> embedded in the ticket.</item>
///   <item>Else DNS domain from <c>kdcHost</c> FQDN (labels after the first).</item>
/// </list>
/// Bare IP with a plain username (no <c>@</c> / <c>\</c> domain) cannot supply realm or domain:
/// Kerberos fails with <c>KerberosRealmUnreachable</c>, NTLM with <c>NtlmDomainNotFound</c>.
/// UPN/down-level names are stripped to the short principal before AS-REQ / NTLM Type3
/// (<c>Administrator@AD-LAB.LOCAL</c> → principal <c>Administrator</c>, realm/domain from the suffix).
///
/// <para><b>Behavior by credential</b></para>
/// <list type="table">
///   <listheader><term>Credential</term><description>Behavior</description></listheader>
///   <item>
///     <term><c>UserPassword</c></term>
///     <description>
///       Tries Kerberos (TGT via password, then TGS for the protocol SPN), then NetNTLMv2
///       (handler completes Type1→Type2→Type3 on the protocol connection). Requires a resolvable
///       realm/domain as above.
///     </description>
///   </item>
///   <item>
///     <term><c>KerberosKirbi</c> / <c>KerberosCcache</c></term>
///     <description>
///       Kerberos only. Parses the ticket file, harvests realm from TGT <c>crealm</c> when present,
///       requests a service ticket from the KDC at <c>kdcHost</c>, then binds/sessions
///       on <c>connectHost</c>. Expired TGTs → <c>KerberosTGTExpired</c>.
///     </description>
///   </item>
///   <item>
///     <term><c>KerberosWindowsTicket</c></term>
///     <description>Not implemented; Kerberos attempt fails (<c>KerberosTGTAcquisitionFailed</c>).</description>
///   </item>
///   <item>
///     <term><c>Cert</c> / <c>OAuthCred</c> / <c>SamlCred</c></term>
///     <description>
///       May appear in method selection for some protocols, but solver/handler paths are not
///       implemented yet → effectively <c>NoSuitableAuthMethod</c> after failed attempts.
///     </description>
///   </item>
///   <item>
///     <term><c>NoCredential</c></term>
///     <description>No viable method for SMB/LDAP in practice → <c>NoSuitableAuthMethod</c>.</description>
///   </item>
/// </list>
///
/// <para><b>Behavior by connection type</b></para>
/// <list type="table">
///   <listheader><term>ConnectionType</term><description>On success</description></listheader>
///   <item>
///     <term><c>SMB</c></term>
///     <description>
///       TCP to <c>connectHost:445</c>, dialect negotiate + SESSION_SETUP (Kerberos SPNEGO or NTLM).
///       Returns <c>AuthSmb</c> with stream, SessionId, dialect, session/signing keys, NextMessageId.
///       No TREE_CONNECT — caller owns further SMB ops.
///     </description>
///   </item>
///   <item>
///     <term><c>Ldap config</c></term>
///     <description>
///       TCP to <c>connectHost</c> port 389 (<c>LdapPlain</c>) or 636 (<c>LdapTls</c>; implicit TLS
///       via <c>SslStream</c>, server certificate always accepted). SASL bind with mechanism
///       <c>GSS-SPNEGO</c> (Kerberos single-shot or NTLM two-leg), carried over the transport
///       stream. Returns <c>AuthLdap</c> with stream, NextMessageId, optional BoundAs.
///       No Search/Modify — caller owns further LDAP ops.
///     </description>
///   </item>
///   <item>
///     <term>Other</term>
///     <description><c>Error UnsupportedConnectionType</c>.</description>
///   </item>
/// </list>
///
///
/// </remarks>
///
/// <param name="request">Fully populated authentication request (protocol, credential, hosts).</param>
/// <returns>
/// <c>Ok AuthenticatedResponse</c> with a live protocol session, or <c>Error AuthError</c>.
/// </returns>
/// 
let authenticate (request : AuthenticationRequest) : Result<AuthenticatedResponse, AuthError> =
    request
    |> produceProtocolHandlerParams
    |> continueAfterParams request
