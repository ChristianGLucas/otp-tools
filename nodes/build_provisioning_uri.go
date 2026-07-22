package nodes

import (
	"context"
	"strings"

	"christiangeorgelucas/otp-tools/axiom"
	gen "christiangeorgelucas/otp-tools/gen"
)

// Builds an "otpauth://totp/..." or "otpauth://hotp/..." Key URI — the
// payload most authenticator apps (Google Authenticator, Authy, 1Password,
// ...) scan from a QR code to enroll a new credential, per the
// Key-Uri-Format spec pquerna/otp's own Key type implements. issuer and
// account_name are required and must not contain a colon (the label
// delimiter). algorithm/digits/period follow the same defaults as the
// generate/validate nodes (SHA1, 6, 30s) when left unset.
func BuildProvisioningUri(ctx context.Context, ax axiom.Context, input *gen.BuildProvisioningUriInput) (*gen.ProvisioningUriResult, error) {
	typ := strings.ToLower(strings.TrimSpace(input.GetType()))
	if typ != "totp" && typ != "hotp" {
		return &gen.ProvisioningUriResult{Error: `type must be "totp" or "hotp"`}, nil
	}
	issuer := input.GetIssuer()
	if issuer == "" {
		return &gen.ProvisioningUriResult{Error: "issuer is required"}, nil
	}
	if strings.Contains(issuer, ":") {
		return &gen.ProvisioningUriResult{Error: "issuer must not contain a colon"}, nil
	}
	account := input.GetAccountName()
	if account == "" {
		return &gen.ProvisioningUriResult{Error: "account_name is required"}, nil
	}
	if strings.Contains(account, ":") {
		return &gen.ProvisioningUriResult{Error: "account_name must not contain a colon"}, nil
	}

	raw, err := decodeSecret(input.GetSecret())
	if err != nil {
		return &gen.ProvisioningUriResult{Error: err.Error()}, nil
	}
	digits, err := parseDigits(input.GetDigits())
	if err != nil {
		return &gen.ProvisioningUriResult{Error: err.Error()}, nil
	}
	algorithm, err := parseAlgorithm(input.GetAlgorithm())
	if err != nil {
		return &gen.ProvisioningUriResult{Error: err.Error()}, nil
	}
	period := input.GetPeriodSeconds()
	if period == 0 {
		period = 30
	}

	uri := buildKeyURI(typ, issuer, account, secretToBase32(raw), algorithm.String(), int32(digits.Length()), period, input.GetCounter(), typ == "hotp")
	return &gen.ProvisioningUriResult{Uri: uri}, nil
}
