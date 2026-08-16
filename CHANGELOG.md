# Changelog

### 2026.8.16

- **LDAPS (implicit TLS) support** — `LdapTls` now performs an implicit-TLS
  handshake on port 636 via `SslStream`.
  The SASL bind (Kerberos or NetNTLMv2) is carried over the encrypted stream.
- `LdapSession.Stream` widened from `NetworkStream` to `System.IO.Stream` so the
  session handle is transport-agnostic.
- LDAPS server certificate is always accepted, validation is out of scope.

### 2026.8.15

Initial release for public repo.