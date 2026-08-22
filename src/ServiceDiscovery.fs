module internal Fauli.ServiceDiscovery


open System

open Fauli.Domain


///
/// Map ConnectionType to its Kerberos SPN prefix.
let spnPrefixFor (connectionType : ConnectionType) : SpnPrefix =
    match connectionType with
    | SMB -> SpnCifs
    | Ldap _ -> SpnLdap
    | WinRM -> SpnHttp
    | HTTP -> SpnHttp
    | MSSql -> SpnMssqlSvc
    | RPC -> SpnHost
    | _ -> SpnOther ""


///
/// Wire string for an SPN prefix.
let private prefixToString (prefix : SpnPrefix) : string =
    match prefix with
    | SpnCifs -> "cifs"
    | SpnLdap -> "ldap"
    | SpnHttp -> "http"
    | SpnMssqlSvc -> "MSSQLSvc"
    | SpnHost -> "HOST"
    | SpnOther s -> s


///
/// True when the host string parses as an IP address.
let private hostLooksLikeIp (hostStr : string) : bool =
    match System.Net.IPAddress.TryParse hostStr with
    | true, _ -> true
    | false, _ -> false


///
/// Expand host to FQDN when needed; bare IPs are left unchanged.
let private expandHostToFqdn (hostStr : string) (realmStr : string) : string =
    match hostLooksLikeIp hostStr with
    | true -> hostStr
    | false ->
        match hostStr.EndsWith($".{realmStr}", StringComparison.OrdinalIgnoreCase) with
        | true -> hostStr
        | false -> $"{hostStr}.{realmStr}"


///
/// Build a Kerberos SPN string from prefix, host, and realm.
/// Format: <prefix>/<hostname>.<realm>[:<port>]
/// If host is already FQDN and ends with the realm, use it as-is.
/// Bare IP addresses are left unchanged (callers should prefer FQDN session hosts for Kerberos).
/// 
let buildSpn (prefix : SpnPrefix) (host : Host) (realm : KerberosRealm) : string =
    let (Host hostStr) = host
    let (KerberosRealm realmStr) = realm
    let fqdn = expandHostToFqdn hostStr realmStr
    $"{prefixToString prefix}/{fqdn}"


///
/// Construct a ServiceName from ConnectionType, Host, and KerberosRealm.
let serviceNameFor (connectionType : ConnectionType) (host : Host) (realm : KerberosRealm) : ServiceName =
    buildSpn (spnPrefixFor connectionType) host realm |> ServiceName


///
/// Try to extract the domain from a UPN-style username (user@domain).
let tryExtractFromUpn (userName : UserName) : DomainName option =
    let (UserName name) = userName
    match name.Split('@') with
    | [| _; domain |] when not (String.IsNullOrWhiteSpace domain) ->
        Some (DomainName domain)
    | _ -> None


///
/// Try to extract the domain from a down-level logon name (DOMAIN\user).
let tryExtractFromDownLevel (userName : UserName) : DomainName option =
    let (UserName name) = userName
    match name.Split('\\') with
    | [| domain; user |] when not (String.IsNullOrWhiteSpace domain) && not (String.IsNullOrWhiteSpace user) ->
        Some (DomainName domain)
    | _ -> None


///
/// Extract domain material embedded in the username, if any.
/// Priority: UPN (user@domain) then down-level (DOMAIN\user).
/// 
let tryExtractDomainFromUserName (userName : UserName) : DomainName option =
    match tryExtractFromUpn userName with
    | Some d -> Some d
    | None -> tryExtractFromDownLevel userName


///
/// Domain from optional username material (no monadic operators at call sites).
let private domainFromUserNameOption (userName : UserName option) : DomainName option =
    match userName with
    | None -> None
    | Some name -> tryExtractDomainFromUserName name


///
/// Kerberos/NTLM principal short name: strip UPN or down-level domain qualifiers.
///   Administrator@AD-LAB.LOCAL → Administrator
///   AD-LAB\Administrator       → Administrator
///   Administrator              → Administrator
/// 
let principalNameFromUserName (userName : UserName) : string =
    let (UserName name) = userName
    match name.Split('@'), name.Split('\\') with
    | [| user; _ |], _ when not (String.IsNullOrWhiteSpace user) -> user
    | _, [| _; user |] when not (String.IsNullOrWhiteSpace user) -> user
    | _ -> name


///
/// Domain labels after the first hostname label, when present and non-empty.
let private domainFromFqdnParts (parts : string array) : DomainName option =
    match parts.Length >= 2 with
    | false -> None
    | true ->
        match String.Join(".", parts.[1..]) with
        | domain when String.IsNullOrWhiteSpace domain -> None
        | domain -> Some (DomainName domain)


///
/// Try to extract the domain from a fully-qualified hostname.
/// Handles both 2-part (host.domain) and 3+ part (host.sub.domain.tld) FQDNs.
/// Bare IPs are rejected (not domains).
/// 
let tryExtractFromFqdn (host : Host) : DomainName option =
    let (Host hostStr) = host
    match hostLooksLikeIp hostStr with
    | true -> None
    | false -> domainFromFqdnParts (hostStr.Split('.'))


///
/// Resolve a DomainName from the authentication request context.
/// Tries credential-borne domain first (UPN / down-level), then host FQDN.
/// 
let resolveDomain (userName : UserName option) (host : Host) : Result<DomainName, AuthError> =
    match domainFromUserNameOption userName, tryExtractFromFqdn host with
    | Some domain, _ -> domain |> Ok
    | None, Some domain -> domain |> Ok
    | None, None -> NtlmDomainNotFound |> Error


///
/// Convert a DomainName into a KerberosRealm (uppercased AD DNS domain).
let private realmFromDomainName (DomainName domain) : Result<KerberosRealm, AuthError> =
    KerberosRealm.create domain


///
/// Single-label non-IP host as a realm candidate (lab short names).
let private realmFromSingleLabelHost (hostStr : string) : Result<KerberosRealm, AuthError> =
    match hostLooksLikeIp hostStr with
    | false when not (String.IsNullOrWhiteSpace hostStr) && not (hostStr.Contains('.')) ->
        KerberosRealm.create hostStr
    | _ -> KerberosRealmUnreachable |> Error


///
/// Derive a Kerberos realm from the authenticating host FQDN only.
/// In AD environments, the realm is the DNS domain name (uppercase).
/// Bare IPs and single-label hosts without a domain suffix fail.
/// 
let deriveRealm (host : Host) : Result<KerberosRealm, AuthError> =
    match tryExtractFromFqdn host with
    | Some domain -> realmFromDomainName domain
    | None ->
        let (Host hostStr) = host
        realmFromSingleLabelHost hostStr


///
/// Resolve Kerberos realm with credential-first priority:
///   1. Domain embedded in the username (UPN or DOMAIN\user)
///   2. Domain derived from the authenticating host FQDN
/// This is the path for password-based Kerberos when the KDC may be addressed by IP.
/// 
let resolveRealm (userName : UserName option) (host : Host) : Result<KerberosRealm, AuthError> =
    match domainFromUserNameOption userName with
    | Some domain -> realmFromDomainName domain
    | None -> deriveRealm host


///
/// Resolve Kerberos realm from a TGT's client realm, falling back to the host FQDN.
/// Ticket material is authoritative when present — kirbi/ccache already carry crealm.
/// 
let resolveRealmFromTgtCrealm (crealm : string option) (host : Host) : Result<KerberosRealm, AuthError> =
    match crealm with
    | Some realm when not (String.IsNullOrWhiteSpace realm) ->
        KerberosRealm.create realm
    | _ -> deriveRealm host
