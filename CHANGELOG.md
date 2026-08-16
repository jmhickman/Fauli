# Changelog

### 2026.8.16

- **LDAPS (implicit TLS) support** — `LdapTls` now performs a real implicit-TLS
  handshake on port 636 via `SslStream`, instead of opening a cleartext socket.
  The SASL bind (Kerberos or NetNTLMv2) is carried over the encrypted stream.
- `LdapSession.Stream` widened from `NetworkStream` to `System.IO.Stream` so the
  session handle is transport-agnostic (plain or TLS). Public, widening change.
- LDAPS server certificate is always accepted (no identity validation), matching
  Fauli's pentesting scope against self-signed / internal AD certificates.

### 2026.8.15

Initial release for public repo.