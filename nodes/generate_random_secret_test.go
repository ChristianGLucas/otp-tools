package nodes_test

import (
	"context"
	"testing"

	"christiangeorgelucas/otp-tools/nodes"

	gen "christiangeorgelucas/otp-tools/gen"
)

// Independent-oracle test: RFC 4648 §10's own base32 test vector
// ("fooba" -> "MZXW6YTB"), hand-published by the encoding's own spec,
// exercised here via the deterministic entropy path.
func TestGenerateRandomSecret_RFC4648Vector(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.GenerateRandomSecret(ctx, ax, &gen.GenerateRandomSecretInput{
		ByteLength: 5,
		Entropy:    []byte("fooba"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Error != "" {
		t.Fatalf("node error: %s", got.Error)
	}
	if got.SecretBase32 != "MZXW6YTB" {
		t.Errorf("secret_base32=%q, want %q (RFC 4648 §10)", got.SecretBase32, "MZXW6YTB")
	}
	if got.ByteLength != 5 {
		t.Errorf("byte_length=%d, want 5", got.ByteLength)
	}
}

func TestGenerateRandomSecret_DefaultsTo20BytesAndIsRandom(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got1, err := nodes.GenerateRandomSecret(ctx, ax, &gen.GenerateRandomSecretInput{})
	if err != nil || got1.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got1.Error)
	}
	if got1.ByteLength != 20 {
		t.Errorf("byte_length=%d, want 20 (default)", got1.ByteLength)
	}
	if got1.SecretBase32 == "" {
		t.Fatalf("secret_base32 is empty")
	}

	got2, err := nodes.GenerateRandomSecret(ctx, ax, &gen.GenerateRandomSecretInput{})
	if err != nil || got2.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got2.Error)
	}
	if got1.SecretBase32 == got2.SecretBase32 {
		t.Errorf("two CSPRNG-backed calls returned the same secret — randomness is broken")
	}
}

func TestGenerateRandomSecret_ByteLengthAboveMaxIsRejected(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.GenerateRandomSecret(ctx, ax, &gen.GenerateRandomSecretInput{ByteLength: 257})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Error == "" {
		t.Errorf("want a structured error for byte_length=257 (above the 256 cap), got none")
	}
}

func TestGenerateRandomSecret_EntropyLengthMismatchIsRejected(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.GenerateRandomSecret(ctx, ax, &gen.GenerateRandomSecretInput{
		ByteLength: 10,
		Entropy:    []byte("tooshort"),
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Error == "" {
		t.Errorf("want a structured error for entropy length != byte_length, got none")
	}
}
