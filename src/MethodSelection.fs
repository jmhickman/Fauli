module internal Fauli.MethodSelection


open Fauli.Domain


///
/// Authentication methods supported by each credential type.
let credentialMethods (credential : Credential) : AuthenticationMethod list =
    match credential with
    | UserPassword _ ->
        [ Kerberos
          NetNTLMv2
          NetNTLMv1
          OAuth
          SAML ]
    | KerberosKirbi _ ->
        [ Kerberos ]
    | KerberosCcache _ ->
        [ Kerberos ]
    | KerberosWindowsTicket _ ->
        [ Kerberos ]
    | Cert _ ->
        [ Certificate
          Kerberos ] // PKINIT
    | OAuthCred _ ->
        [ OAuth ]
    | SamlCred _ ->
        [ SAML ]
    | NoCredential ->
        [ Anonymous ]


///
/// Authentication methods supported by each protocol (ConnectionType).
let protocolMethods (connectionType : ConnectionType) : AuthenticationMethod list =
    match connectionType with
    | SMB ->
        [ Kerberos
          NetNTLMv2
          Anonymous ]
    | Ldap _ ->
        [ Kerberos
          NetNTLMv2
          Certificate
          Anonymous ]
    | WinRM ->
        [ Kerberos
          NetNTLMv2
          Certificate ]
    | RDP ->
        [ Kerberos
          NetNTLMv2
          Certificate ]
    | HOST ->
        [ Kerberos
          NetNTLMv2
          Certificate
          Anonymous ]
    | HTTP ->
        [ Kerberos
          NetNTLMv2
          Certificate
          OAuth
          SAML
          Anonymous ]
    | MSSql ->
        [ Kerberos
          NetNTLMv2
          Certificate
          OAuth
          Anonymous ]
    | DNS ->
        [ Kerberos
          Anonymous ]
    | RPC ->
        [ Kerberos
          NetNTLMv2
          Anonymous ]
    | Exchange ->
        [ Kerberos
          NetNTLMv2
          Certificate
          OAuth
          Anonymous ]


///
/// True when the method is accepted by the protocol.
let private isSupportedByProtocol (protocolSupported : Set<AuthenticationMethod>) (method : AuthenticationMethod) : bool =
    protocolSupported |> Set.contains method


///
/// Select viable authentication methods for a given connection type and credential.
/// Returns methods in priority order (most preferred first).
/// 
let selectMethods (connectionType : ConnectionType) (credential : Credential) : AuthenticationMethod list =
    let protocolSupported =
        connectionType
        |> protocolMethods
        |> Set.ofList
    credential
    |> credentialMethods
    |> List.filter (isSupportedByProtocol protocolSupported)
