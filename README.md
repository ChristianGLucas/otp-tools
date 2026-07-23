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

## Use it from your agent or app

Every node in this package is a **live, auto-scaling API endpoint** on the
[Axiom](https://axiomide.com) marketplace — call it from an AI agent or your own
code, with nothing to self-host.

**📦 See it on the marketplace:**
https://dev.axiomide.com/marketplace/christiangeorgelucas/otp-tools@0.1.0

**Hook it up to an AI agent (MCP).** Add Axiom's hosted MCP server to any MCP
client and every node becomes a typed tool your agent can call — search the
catalog, inspect a schema, and invoke it directly.

```bash
# Claude Code
claude mcp add --transport http axiom https://api.axiomide.com/mcp \
  --header "Authorization: Bearer $AXIOM_API_KEY"
```

Claude Desktop, Cursor, or any config-based client:

```json
{
  "mcpServers": {
    "axiom": {
      "type": "http",
      "url": "https://api.axiomide.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_AXIOM_API_KEY" }
    }
  }
}
```

**Call it from the CLI.**

```bash
axiom invoke christiangeorgelucas/otp-tools/GenerateTotpCode --input '{ ... }'
```

**Call it over HTTP.**

```bash
curl -X POST https://api.axiomide.com/invocations/v1/nodes/christiangeorgelucas/otp-tools/0.1.0/GenerateTotpCode \
  -H "Authorization: Bearer $AXIOM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{ ... }'
```

> Input/output schema for each node is on the marketplace page above, or via
> `axiom inspect node christiangeorgelucas/otp-tools/GenerateTotpCode`.

### Get started free

Install the CLI:

```bash
# macOS / Linux — Homebrew
brew install axiomide/tap/axiom

# macOS / Linux — install script
curl -fsSL https://raw.githubusercontent.com/AxiomIDE/axiom-releases/main/install.sh | sh
```

**Windows:** download the `windows/amd64` `.zip` from the
[releases page](https://github.com/AxiomIDE/axiom-releases/releases), unzip it,
and put `axiom.exe` on your `PATH`.

Then `axiom version` to verify, `axiom login` (GitHub or Google) to authenticate,
and create an API key under **Console → API Keys**. Docs and sign-up at
**[axiomide.com](https://axiomide.com)**.

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
