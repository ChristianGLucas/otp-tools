# christiangeorgelucas/otp-tools

Composable [Axiom](https://axiomide.com) nodes for RFC 6238 TOTP and RFC 4226 HOTP
one-time passwords — the codes used by authenticator apps (Google
Authenticator, Authy, 1Password, Steam Guard, ...) for two-factor
authentication. Built for the Axiom marketplace.

Wraps [`github.com/pquerna/otp`](https://github.com/pquerna/otp)
(Apache-2.0), the de-facto reference Go implementation of both RFCs, used by
production systems including HashiCorp Vault. Every node is stateless and
deterministic: the caller supplies the secret, timestamp/counter, and every
parameter; nothing is stored server-side and the wall clock is never read.

## Nodes

- **GenerateTotpCode** — compute an RFC 6238 TOTP code for a secret at a
  caller-supplied point in time.
- **GenerateHotpCode** — compute an RFC 4226 HOTP code for a secret at a
  caller-supplied counter value.
- **ValidateTotpCode** — verify a submitted TOTP code, tolerating a
  configurable window of clock drift (skew) on either side.
- **ValidateHotpCode** — verify a submitted HOTP code, tolerating a
  configurable look-ahead window on the counter.
- **GenerateRandomSecret** — generate a fresh random (CSPRNG) base32 shared
  secret, or a deterministic one from caller-supplied entropy.
- **BuildProvisioningUri** — build an `otpauth://totp/...` or
  `otpauth://hotp/...` Key URI (the payload authenticator apps scan from a
  QR code) per the
  [Key-Uri-Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
  spec.
- **ParseProvisioningUri** — parse a Key URI back into its components.

## Shared secret encoding

Every node that consumes a secret takes an `OtpSecret{value, encoding}` pair.
`encoding` defaults to `"base32"` (the RFC 4226/6238 and authenticator-app
convention) and also accepts `"hex"`, `"base64"`, `"base64url"`, and `"utf8"`
— the same vocabulary as `christiangeorgelucas/hash-tools` and
`christiangeorgelucas/crypto-tools`, so key material derived elsewhere (e.g.
hash-tools' `Hkdf`, hex/base64 output) plugs in directly without a
conversion step.

## Verification

Every generate/validate node is tested against the RFC 4226 Appendix D and
RFC 6238 Appendix B authors' own published test vectors (independent of this
package and of the wrapped library). `BuildProvisioningUri` and
`ParseProvisioningUri` are tested against Google's own published
Key-Uri-Format wiki examples. `GenerateRandomSecret`'s deterministic path is
tested against the RFC 4648 §10 base32 test vectors.

## Security note

Every `OtpSecret.value` is caller-supplied **data** — a shared secret the
caller already possesses, not a platform credential — and is never logged.

## License

MIT. See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for the licenses
of the wrapped open-source libraries (all permissive: Apache-2.0, MIT,
BSD-3-Clause).
