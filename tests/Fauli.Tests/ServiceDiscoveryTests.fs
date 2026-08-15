/// Pure unit tests for SPN construction, realm/domain harvest, and principal stripping.
/// No network I/O — locks the credential-first realm rules and SPN shape.
module Fauli.Tests.ServiceDiscoveryTests

open System
open Xunit
open Fauli.Domain
open Fauli.ServiceDiscovery

// ===========================================================================
// SPN construction
// ===========================================================================

[<Fact>]
let ``serviceNameFor SMB builds cifs SPN from FQDN host`` () =
    match KerberosRealm.create "AD-LAB.LOCAL" with
    | Error e -> Assert.Fail(sprintf "%A" e)
    | Ok realm ->
        let spn = serviceNameFor SMB (Host "fileserver") realm
        let (ServiceName s) = spn
        Assert.Equal("cifs/fileserver.AD-LAB.LOCAL", s)

[<Fact>]
let ``serviceNameFor LDAP builds ldap SPN and preserves host already ending in realm`` () =
    match KerberosRealm.create "ad-lab.local" with
    | Error e -> Assert.Fail(sprintf "%A" e)
    | Ok realm ->
        let (ServiceName s) =
            serviceNameFor (Ldap LdapConnectionConfig.defaults) (Host "AD-Server-01.ad-lab.local") realm
        // Realm is uppercased by KerberosRealm.create
        Assert.Equal("ldap/AD-Server-01.ad-lab.local", s)

[<Fact>]
let ``buildSpn leaves bare IP host unchanged (does not append realm)`` () =
    match KerberosRealm.create "AD-LAB.LOCAL" with
    | Error e -> Assert.Fail(sprintf "%A" e)
    | Ok realm ->
        let s = buildSpn SpnCifs (Host "192.168.10.38") realm
        Assert.Equal("cifs/192.168.10.38", s)

[<Fact>]
let ``spnPrefixFor maps connection types`` () =
    Assert.Equal(SpnCifs, spnPrefixFor SMB)
    Assert.Equal(SpnLdap, spnPrefixFor (Ldap LdapConnectionConfig.defaults))
    Assert.Equal(SpnHttp, spnPrefixFor WinRM)
    Assert.Equal(SpnHttp, spnPrefixFor HTTP)
    Assert.Equal(SpnMssqlSvc, spnPrefixFor MSSql)

// ===========================================================================
// Principal / domain extraction
// ===========================================================================

[<Fact>]
let ``principalNameFromUserName strips UPN and down-level`` () =
    Assert.Equal("Administrator", principalNameFromUserName (UserName "Administrator@AD-LAB.LOCAL"))
    Assert.Equal("Administrator", principalNameFromUserName (UserName "AD-LAB\\Administrator"))
    Assert.Equal("bob", principalNameFromUserName (UserName "bob"))
    Assert.Equal("jdoe", principalNameFromUserName (UserName "CORP\\jdoe"))

[<Fact>]
let ``tryExtractDomainFromUserName prefers UPN then down-level`` () =
    match tryExtractDomainFromUserName (UserName "a@corp.example") with
    | Some (DomainName d) -> Assert.Equal("corp.example", d)
    | None -> Assert.Fail "UPN domain expected"

    match tryExtractDomainFromUserName (UserName "CORP\\a") with
    | Some (DomainName d) -> Assert.Equal("CORP", d)
    | None -> Assert.Fail "down-level domain expected"

    Assert.True((tryExtractDomainFromUserName (UserName "plain")).IsNone)

[<Fact>]
let ``tryExtractFromFqdn rejects bare IP and single label`` () =
    Assert.True((tryExtractFromFqdn (Host "10.0.0.1")).IsNone)
    Assert.True((tryExtractFromFqdn (Host "localhost")).IsNone)
    match tryExtractFromFqdn (Host "dc.ad-lab.local") with
    | Some (DomainName d) -> Assert.Equal("ad-lab.local", d)
    | None -> Assert.Fail "FQDN domain expected"

// ===========================================================================
// Realm resolution (credential-first)
// ===========================================================================

[<Fact>]
let ``resolveRealm prefers UPN over bare IP host`` () =
    match resolveRealm (Some (UserName "Administrator@AD-LAB.LOCAL")) (Host "192.168.10.38") with
    | Ok (KerberosRealm r) -> Assert.Equal("AD-LAB.LOCAL", r)
    | Error e -> Assert.Fail(sprintf "Expected realm from UPN, got %A" e)

[<Fact>]
let ``resolveRealm prefers down-level DOMAIN\\user over bare IP host`` () =
    match resolveRealm (Some (UserName "AD-LAB\\Administrator")) (Host "192.168.10.38") with
    | Ok (KerberosRealm r) -> Assert.Equal("AD-LAB", r)
    | Error e -> Assert.Fail(sprintf "Expected realm from down-level name, got %A" e)

[<Fact>]
let ``resolveRealm falls back to host FQDN when username has no domain`` () =
    match resolveRealm (Some (UserName "Administrator")) (Host "dc.ad-lab.local") with
    | Ok (KerberosRealm r) -> Assert.Equal("AD-LAB.LOCAL", r)
    | Error e -> Assert.Fail(sprintf "Expected realm from FQDN, got %A" e)

[<Fact>]
let ``resolveRealm fails for plain user + bare IP`` () =
    match resolveRealm (Some (UserName "Administrator")) (Host "192.168.10.38") with
    | Error KerberosRealmUnreachable -> ()
    | other -> Assert.Fail(sprintf "Expected KerberosRealmUnreachable, got %A" other)

[<Fact>]
let ``resolveRealmFromTgtCrealm harvests ticket crealm before host`` () =
    match resolveRealmFromTgtCrealm (Some "AD-LAB.LOCAL") (Host "192.168.10.38") with
    | Ok (KerberosRealm r) -> Assert.Equal("AD-LAB.LOCAL", r)
    | Error e -> Assert.Fail(sprintf "Expected crealm, got %A" e)

[<Fact>]
let ``resolveRealmFromTgtCrealm falls back to host when crealm missing`` () =
    match resolveRealmFromTgtCrealm None (Host "kdc.example.com") with
    | Ok (KerberosRealm r) -> Assert.Equal("EXAMPLE.COM", r)
    | Error e -> Assert.Fail(sprintf "%A" e)

    match resolveRealmFromTgtCrealm (Some "   ") (Host "192.168.1.1") with
    | Error KerberosRealmUnreachable -> ()
    | other -> Assert.Fail(sprintf "blank crealm + IP should fail, got %A" other)

// ===========================================================================
// NTLM domain resolution
// ===========================================================================

[<Fact>]
let ``resolveDomain prefers UPN and rejects bare IP without domain`` () =
    match resolveDomain (Some (UserName "user@corp.local")) (Host "10.0.0.1") with
    | Ok (DomainName d) -> Assert.Equal("corp.local", d)
    | Error e -> Assert.Fail(sprintf "Expected domain from UPN, got %A" e)

    match resolveDomain (Some (UserName "user")) (Host "10.0.0.1") with
    | Error NtlmDomainNotFound -> ()
    | other -> Assert.Fail(sprintf "Expected NtlmDomainNotFound for bare IP, got %A" other)

[<Fact>]
let ``resolveDomain accepts down-level DOMAIN\\user`` () =
    match resolveDomain (Some (UserName "CORP\\alice")) (Host "10.0.0.1") with
    | Ok (DomainName d) -> Assert.Equal("CORP", d)
    | Error e -> Assert.Fail(sprintf "%A" e)

[<Fact>]
let ``KerberosRealm.create uppercases realm`` () =
    match KerberosRealm.create "ad-lab.local" with
    | Ok (KerberosRealm r) -> Assert.Equal("AD-LAB.LOCAL", r)
    | Error e -> Assert.Fail(sprintf "%A" e)
