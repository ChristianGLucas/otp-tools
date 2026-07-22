package nodes_test

import (
	"context"
	"testing"

	"christiangeorgelucas/otp-tools/nodes"

	gen "christiangeorgelucas/otp-tools/gen"
)

// Independent-oracle test: the exact issuer/account/secret from Google's own
// Key-Uri-Format wiki page example (github.com/google/google-authenticator/
// wiki/Key-Uri-Format), which also appears verbatim in pquerna/otp's own
// source comments. Field order in the query string is our own choice
// (alphabetical, deterministic) since the spec does not mandate an order.
func TestBuildProvisioningUri_TotpMatchesGoogleWikiExample(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.BuildProvisioningUri(ctx, ax, &gen.BuildProvisioningUriInput{
		Type:        "totp",
		Issuer:      "Example",
		AccountName: "alice@google.com",
		Secret:      &gen.OtpSecret{Value: "JBSWY3DPEHPK3PXP", Encoding: "base32"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Error != "" {
		t.Fatalf("node error: %s", got.Error)
	}
	want := "otpauth://totp/Example:alice@google.com?algorithm=SHA1&digits=6&issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP"
	if got.Uri != want {
		t.Errorf("uri=%q, want %q", got.Uri, want)
	}
}

func TestBuildProvisioningUri_HotpIncludesCounter(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.BuildProvisioningUri(ctx, ax, &gen.BuildProvisioningUriInput{
		Type:        "hotp",
		Issuer:      "Example",
		AccountName: "alice@google.com",
		Secret:      &gen.OtpSecret{Value: "JBSWY3DPEHPK3PXP", Encoding: "base32"},
		Counter:     5,
	})
	if err != nil || got.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got.Error)
	}
	want := "otpauth://hotp/Example:alice@google.com?algorithm=SHA1&counter=5&digits=6&issuer=Example&secret=JBSWY3DPEHPK3PXP"
	if got.Uri != want {
		t.Errorf("uri=%q, want %q", got.Uri, want)
	}
}

func TestBuildProvisioningUri_RoundTripsThroughParse(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	built, err := nodes.BuildProvisioningUri(ctx, ax, &gen.BuildProvisioningUriInput{
		Type:        "totp",
		Issuer:      "ACME Co",
		AccountName: "john.doe@email.com",
		Secret:      &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"},
		Digits:      8,
		Algorithm:   "SHA256",
	})
	if err != nil || built.Error != "" {
		t.Fatalf("build: err=%v nodeErr=%s", err, built.Error)
	}

	parsed, err := nodes.ParseProvisioningUri(ctx, ax, &gen.ParseProvisioningUriInput{Uri: built.Uri})
	if err != nil || parsed.Error != "" {
		t.Fatalf("parse: err=%v nodeErr=%s", err, parsed.Error)
	}
	if parsed.Issuer != "ACME Co" || parsed.AccountName != "john.doe@email.com" {
		t.Errorf("issuer=%q account=%q, want %q / %q", parsed.Issuer, parsed.AccountName, "ACME Co", "john.doe@email.com")
	}
	if parsed.Digits != 8 || parsed.Algorithm != "SHA256" {
		t.Errorf("digits=%d algorithm=%q, want 8 / SHA256", parsed.Digits, parsed.Algorithm)
	}

	// The round-tripped secret must generate the same code as the original.
	code1, err := nodes.GenerateTotpCode(ctx, ax, &gen.GenerateTotpCodeInput{
		Secret: &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}, TimestampUnix: 100, Digits: 8, Algorithm: "SHA256",
	})
	if err != nil || code1.Error != "" {
		t.Fatalf("code1: err=%v nodeErr=%s", err, code1.Error)
	}
	code2, err := nodes.GenerateTotpCode(ctx, ax, &gen.GenerateTotpCodeInput{
		Secret: &gen.OtpSecret{Value: parsed.SecretBase32, Encoding: "base32"}, TimestampUnix: 100, Digits: 8, Algorithm: "SHA256",
	})
	if err != nil || code2.Error != "" {
		t.Fatalf("code2: err=%v nodeErr=%s", err, code2.Error)
	}
	if code1.Code != code2.Code {
		t.Errorf("code from original secret=%q != code from round-tripped secret=%q", code1.Code, code2.Code)
	}
}

func TestBuildProvisioningUri_RejectsColonInIssuer(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.BuildProvisioningUri(ctx, ax, &gen.BuildProvisioningUriInput{
		Type: "totp", Issuer: "Ex:ample", AccountName: "a@b.com",
		Secret: &gen.OtpSecret{Value: "JBSWY3DPEHPK3PXP", Encoding: "base32"},
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Error == "" {
		t.Errorf("want a structured error for a colon in issuer, got none")
	}
}
