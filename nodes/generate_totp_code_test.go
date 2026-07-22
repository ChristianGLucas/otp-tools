package nodes_test

import (
	"context"
	"testing"

	"christiangeorgelucas/otp-tools/nodes"

	gen "christiangeorgelucas/otp-tools/gen"
)

// Independent-oracle test: the RFC 6238 Appendix B test vectors, published
// by the RFC's own authors, hand-computed independently of this package and
// of the wrapped library — across all three algorithms it defines, 8 digits,
// 30s period, T0=0.
func TestGenerateTotpCode_RFC6238Vectors(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	sha1Secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}
	sha256Secret := &gen.OtpSecret{Value: "12345678901234567890123456789012", Encoding: "utf8"}
	sha512Secret := &gen.OtpSecret{Value: "1234567890123456789012345678901234567890123456789012345678901234", Encoding: "utf8"}

	cases := []struct {
		name      string
		secret    *gen.OtpSecret
		algorithm string
		time      int64
		want      string
	}{
		{"SHA1@59", sha1Secret, "SHA1", 59, "94287082"},
		{"SHA1@1111111109", sha1Secret, "SHA1", 1111111109, "07081804"},
		{"SHA1@1111111111", sha1Secret, "SHA1", 1111111111, "14050471"},
		{"SHA1@2000000000", sha1Secret, "SHA1", 2000000000, "69279037"},
		{"SHA256@59", sha256Secret, "SHA256", 59, "46119246"},
		{"SHA256@1111111109", sha256Secret, "SHA256", 1111111109, "68084774"},
		{"SHA512@59", sha512Secret, "SHA512", 59, "90693936"},
		{"SHA512@2000000000", sha512Secret, "SHA512", 2000000000, "38618901"},
	}
	for _, c := range cases {
		got, err := nodes.GenerateTotpCode(ctx, ax, &gen.GenerateTotpCodeInput{
			Secret:        c.secret,
			TimestampUnix: c.time,
			PeriodSeconds: 30,
			Digits:        8,
			Algorithm:     c.algorithm,
		})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, err)
		}
		if got.Error != "" {
			t.Fatalf("%s: node error: %s", c.name, got.Error)
		}
		if got.Code != c.want {
			t.Errorf("%s: code=%q, want %q (RFC 6238 Appendix B)", c.name, got.Code, c.want)
		}
	}
}

func TestGenerateTotpCode_DefaultsTo6Digits(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	got, err := nodes.GenerateTotpCode(ctx, ax, &gen.GenerateTotpCodeInput{Secret: secret, TimestampUnix: 59})
	if err != nil || got.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got.Error)
	}
	if len(got.Code) != 6 {
		t.Errorf("code=%q has length %d, want 6 (default digits)", got.Code, len(got.Code))
	}
}

func TestGenerateTotpCode_SteamEncoder(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	// pquerna/otp's Steam encoder uses the request's digit count as the
	// output length (there is no separate "5" Digits value — the library
	// only defines 6 and 8) — so with digits left at its default (6), the
	// Steam-alphabet code is 6 characters, not the 5 a real Steam Guard
	// client shows on screen. This is a genuine property of the wrapped
	// library, documented on the field, not an implementation bug here.
	got, err := nodes.GenerateTotpCode(ctx, ax, &gen.GenerateTotpCodeInput{
		Secret: secret, TimestampUnix: 59, Encoder: "steam",
	})
	if err != nil || got.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got.Error)
	}
	if len(got.Code) != 6 {
		t.Errorf("steam code=%q has length %d, want 6 (default digits)", got.Code, len(got.Code))
	}
	const steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"
	for _, r := range got.Code {
		if !containsRune(steamAlphabet, r) {
			t.Errorf("steam code=%q contains %q, not in the Steam Guard alphabet", got.Code, r)
		}
	}
}

func TestGenerateTotpCode_BadEncoding(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.GenerateTotpCode(ctx, ax, &gen.GenerateTotpCodeInput{
		Secret:        &gen.OtpSecret{Value: "zzz", Encoding: "hex"},
		TimestampUnix: 59,
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Code != "" || got.Error == "" {
		t.Errorf("got code=%q error=%q, want empty code and a structured error", got.Code, got.Error)
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
