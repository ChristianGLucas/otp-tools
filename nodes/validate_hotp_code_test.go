package nodes_test

import (
	"context"
	"testing"

	"christiangeorgelucas/otp-tools/nodes"

	gen "christiangeorgelucas/otp-tools/gen"
)

// Independent-oracle test: RFC 4226 Appendix D's counter=2 code "359152",
// checked against a stored counter of 0 with a look-ahead window wide enough
// to reach it — the standard HOTP resynchronization case.
func TestValidateHotpCode_RFC4226VectorWithinWindow(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	got, err := nodes.ValidateHotpCode(ctx, ax, &gen.ValidateHotpCodeInput{
		Code: "359152", Secret: secret, Counter: 0, LookAheadWindow: u32(5),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Valid || got.Error != "" {
		t.Fatalf("valid=%v error=%q, want valid=true", got.Valid, got.Error)
	}
	if got.MatchedCounter != 2 {
		t.Errorf("matched_counter=%d, want 2", got.MatchedCounter)
	}
	if got.Offset != 2 {
		t.Errorf("offset=%d, want 2", got.Offset)
	}
}

func TestValidateHotpCode_OutsideWindowFails(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	// Same RFC vector as above, but the window is too narrow to reach
	// counter=2 from a stored counter of 0.
	got, err := nodes.ValidateHotpCode(ctx, ax, &gen.ValidateHotpCodeInput{
		Code: "359152", Secret: secret, Counter: 0, LookAheadWindow: u32(1),
	})
	if err != nil || got.Error != "" {
		t.Fatalf("err=%v nodeErr=%s", err, got.Error)
	}
	if got.Valid {
		t.Errorf("valid=true with a window too narrow to reach the matching counter, want false")
	}
}

func TestValidateHotpCode_WindowAboveMaxIsRejected(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	secret := &gen.OtpSecret{Value: "12345678901234567890", Encoding: "utf8"}

	got, err := nodes.ValidateHotpCode(ctx, ax, &gen.ValidateHotpCodeInput{
		Code: "359152", Secret: secret, Counter: 0, LookAheadWindow: u32(1001),
	})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if got.Error == "" {
		t.Errorf("want a structured error for look_ahead_window=1001 (above the 1000 cap), got none")
	}
}
