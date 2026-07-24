package nodes_test

import (
	"context"
	"testing"

	"christiangeorgelucas/otp-tools/nodes"

	gen "christiangeorgelucas/otp-tools/gen"
)

// Independent-oracle test: the EXACT example URI published on Google's own
// Key-Uri-Format wiki page (github.com/google/google-authenticator/wiki/
// Key-Uri-Format#example), authored independently of this package.
func TestParseProvisioningUri_GoogleWikiExample(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	const uri = "otpauth://totp/ACME%20Co:john.doe@email.com?" +
		"secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"

	got, err := nodes.ParseProvisioningUri(ctx, ax, &gen.ParseProvisioningUriInput{Uri: uri})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Error != "" {
		t.Fatalf("node error: %s", got.Error)
	}
	if got.Type != "totp" {
		t.Errorf("type=%q, want totp", got.Type)
	}
	if got.Issuer != "ACME Co" {
		t.Errorf("issuer=%q, want %q", got.Issuer, "ACME Co")
	}
	if got.AccountName != "john.doe@email.com" {
		t.Errorf("account_name=%q, want %q", got.AccountName, "john.doe@email.com")
	}
	if got.SecretBase32 != "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ" {
		t.Errorf("secret_base32=%q, want %q", got.SecretBase32, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
	}
	if got.Algorithm != "SHA1" || got.Digits != 6 || got.PeriodSeconds != 30 {
		t.Errorf("algorithm=%q digits=%d period=%d, want SHA1/6/30", got.Algorithm, got.Digits, got.PeriodSeconds)
	}
}

func TestParseProvisioningUri_DefaultsWhenParamsOmitted(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseProvisioningUri(ctx, ax, &gen.ParseProvisioningUriInput{
		Uri: "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
	})
	if err != nil || got.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got.Error)
	}
	if got.Algorithm != "SHA1" {
		t.Errorf("algorithm=%q, want default SHA1", got.Algorithm)
	}
	if got.Digits != 6 {
		t.Errorf("digits=%d, want default 6", got.Digits)
	}
	if got.PeriodSeconds != 30 {
		t.Errorf("period_seconds=%d, want default 30", got.PeriodSeconds)
	}
	if got.HasCounter {
		t.Errorf("has_counter=true for a TOTP uri with no counter param, want false")
	}
}

func TestParseProvisioningUri_HotpCounter(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseProvisioningUri(ctx, ax, &gen.ParseProvisioningUriInput{
		Uri: "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=42",
	})
	if err != nil || got.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got.Error)
	}
	if got.Type != "hotp" {
		t.Errorf("type=%q, want hotp", got.Type)
	}
	if !got.HasCounter || got.Counter != 42 {
		t.Errorf("has_counter=%v counter=%d, want true / 42", got.HasCounter, got.Counter)
	}
}

func TestParseProvisioningUri_WrongSchemeIsRejected(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseProvisioningUri(ctx, ax, &gen.ParseProvisioningUriInput{
		Uri: "https://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP",
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Error == "" {
		t.Errorf("want a structured error for a non-otpauth scheme, got none")
	}
}

// Payload size is the platform's job, not the node's (ADR: node = pure
// input->output function). This exercises a URI far larger than the
// package's old, now-removed 8 KiB cap and asserts only that the node
// handles it without crashing — a well-formed large URI parses fine, and a
// malformed one still comes back as a structured error, never a panic.
func TestParseProvisioningUri_LargeUriDoesNotCrash(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	big := make([]byte, 200000)
	for i := range big {
		big[i] = 'a'
	}
	got, err := nodes.ParseProvisioningUri(ctx, ax, &gen.ParseProvisioningUriInput{
		Uri: "otpauth://totp/" + string(big),
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got == nil {
		t.Fatalf("want a non-nil result for a large uri, got nil")
	}
	if got.Error != "" {
		t.Errorf("large-but-well-formed uri should parse, got structured error: %s", got.Error)
	}
	if got.AccountName != string(big) {
		t.Errorf("account name mismatch on large input: got %d bytes, want %d", len(got.AccountName), len(big))
	}
}
