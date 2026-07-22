package nodes_test

import (
	"context"
	"testing"

	"christiangeorgelucas/otp-tools/nodes"

	gen "christiangeorgelucas/otp-tools/gen"
)

// Independent-oracle test: the RFC 4226 Appendix D test vectors, published
// by the RFC's own authors, hand-computed independently of this package and
// of the wrapped library. Secret is the RFC's own ASCII test secret
// "12345678901234567890" (20 bytes), SHA1, 6 digits.
func TestGenerateHotpCode_RFC4226Vectors(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	cases := []struct {
		counter uint64
		want    string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{5, "254676"},
		{9, "520489"},
	}
	for _, c := range cases {
		got, err := nodes.GenerateHotpCode(ctx, ax, &gen.GenerateHotpCodeInput{Secret: secret, Counter: c.counter})
		if err != nil {
			t.Fatalf("counter=%d: unexpected error: %v", c.counter, err)
		}
		if got.Error != "" {
			t.Fatalf("counter=%d: node error: %s", c.counter, got.Error)
		}
		if got.Code != c.want {
			t.Errorf("counter=%d: code=%q, want %q (RFC 4226 Appendix D)", c.counter, got.Code, c.want)
		}
	}
}

func TestGenerateHotpCode_MalformedSecret(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.GenerateHotpCode(ctx, ax, &gen.GenerateHotpCodeInput{
		Secret: &gen.OtpSecret{Value: "not valid base32!!", Encoding: "base32"},
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Code != "" || got.Error == "" {
		t.Errorf("got code=%q error=%q, want empty code and a structured error", got.Code, got.Error)
	}
}

func TestGenerateHotpCode_InvalidAlgorithm(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.GenerateHotpCode(ctx, ax, &gen.GenerateHotpCodeInput{
		Secret:    &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"},
		Algorithm: "MD5",
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Error == "" {
		t.Errorf("want a structured error for unsupported algorithm MD5, got none")
	}
}
