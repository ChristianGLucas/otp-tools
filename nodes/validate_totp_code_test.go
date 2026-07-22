package nodes_test

import (
	"context"
	"testing"

	"christiangeorgelucas/otp-tools/nodes"

	gen "christiangeorgelucas/otp-tools/gen"
)

// Independent-oracle test: RFC 6238 Appendix B's own vector (code "94287082"
// at Unix time 59, SHA1, 8 digits, 30s period) must validate exactly at that
// time.
func TestValidateTotpCode_RFC6238VectorMatchesExactly(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	got, err := nodes.ValidateTotpCode(ctx, ax, &gen.ValidateTotpCodeInput{
		Code:          "94287082",
		Secret:        secret,
		TimestampUnix: 59,
		PeriodSeconds: 30,
		Digits:        8,
		Algorithm:     "SHA1",
		Skew:          u32(0),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Valid || got.Error != "" {
		t.Fatalf("valid=%v error=%q, want valid=true", got.Valid, got.Error)
	}
	if got.MatchedSkew != 0 {
		t.Errorf("matched_skew=%d, want 0 for an exact match", got.MatchedSkew)
	}
}

func TestValidateTotpCode_SkewToleratesClockDrift(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	// RFC 6238's code "94287082" is for time-step counter floor(59/30)=1.
	// "Now" = 75 falls in counter floor(75/30)=2, exactly one 30s step
	// later — so the code should validate only with skew>=1, at offset -1.
	got, err := nodes.ValidateTotpCode(ctx, ax, &gen.ValidateTotpCodeInput{
		Code:          "94287082",
		Secret:        secret,
		TimestampUnix: 75,
		PeriodSeconds: 30,
		Digits:        8,
		Algorithm:     "SHA1",
		Skew:          u32(1),
	})
	if err != nil || got.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got.Error)
	}
	if !got.Valid {
		t.Fatalf("valid=false, want the drifted code to validate within skew=1")
	}
	if got.MatchedSkew != -1 {
		t.Errorf("matched_skew=%d, want -1 (the code is from one period in the past)", got.MatchedSkew)
	}

	// With skew=0, the same drifted code must NOT validate.
	got2, err := nodes.ValidateTotpCode(ctx, ax, &gen.ValidateTotpCodeInput{
		Code:          "94287082",
		Secret:        secret,
		TimestampUnix: 75,
		PeriodSeconds: 30,
		Digits:        8,
		Algorithm:     "SHA1",
		Skew:          u32(0),
	})
	if err != nil || got2.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got2.Error)
	}
	if got2.Valid {
		t.Errorf("valid=true with skew=0, want false for a code one period stale")
	}
}

func TestValidateTotpCode_WrongCodeIsNormalMismatch(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	got, err := nodes.ValidateTotpCode(ctx, ax, &gen.ValidateTotpCodeInput{
		Code:          "00000000",
		Secret:        secret,
		TimestampUnix: 59,
		PeriodSeconds: 30,
		Digits:        8,
		Algorithm:     "SHA1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Valid {
		t.Errorf("valid=true for a wrong code, want false")
	}
	if got.Error != "" {
		t.Errorf("error=%q for a well-formed-but-wrong code, want empty (mismatch is not an error)", got.Error)
	}
}

func TestValidateTotpCode_SkewAboveMaxIsRejected(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	got, err := nodes.ValidateTotpCode(ctx, ax, &gen.ValidateTotpCodeInput{
		Code: "94287082", Secret: secret, TimestampUnix: 59, Skew: u32(101),
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Error == "" {
		t.Errorf("want a structured error for skew=101 (above the 100 cap), got none")
	}
}
