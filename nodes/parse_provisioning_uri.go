package nodes

import (
	"context"
	"fmt"

	"christiangeorgelucas/otp-tools/axiom"
	gen "christiangeorgelucas/otp-tools/gen"
)

// Parses an "otpauth://..." Key URI (from a scanned QR code, or a URI a
// caller already has) back into its components — the inverse of
// BuildProvisioningUri. Applies the same issuer/account-label precedence and
// field defaults (algorithm SHA1, digits 6, period 30s) the Key-Uri-Format
// spec defines. Bounded to 8 KiB; malformed input (not a URI, wrong scheme,
// unrecognized host) returns a structured error rather than a crash.
func ParseProvisioningUri(ctx context.Context, ax axiom.Context, input *gen.ParseProvisioningUriInput) (*gen.ProvisioningUriRecord, error) {
	uri := input.GetUri()
	if uri == "" {
		return &gen.ProvisioningUriRecord{Error: "uri is required"}, nil
	}
	if len(uri) > maxUriBytes {
		return &gen.ProvisioningUriRecord{Error: fmt.Sprintf("uri exceeds the maximum of %d bytes", maxUriBytes)}, nil
	}

	p, err := parseKeyURI(uri)
	if err != nil {
		return &gen.ProvisioningUriRecord{Error: "failed to parse uri: " + err.Error()}, nil
	}

	return &gen.ProvisioningUriRecord{
		Type:          p.typ,
		Issuer:        p.issuer,
		AccountName:   p.account,
		SecretBase32:  p.secretB32,
		Algorithm:     p.algorithm,
		Digits:        p.digits,
		PeriodSeconds: p.period,
		Counter:       p.counter,
		HasCounter:    p.hasCounter,
	}, nil
}
