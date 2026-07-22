package nodes

import (
	"context"
	"time"

	"github.com/pquerna/otp/totp"

	"christiangeorgelucas/otp-tools/axiom"
	gen "christiangeorgelucas/otp-tools/gen"
)

// Computes an RFC 6238 TOTP code for a shared secret at one caller-supplied
// point in time. Deterministic: this node never reads the wall clock, so the
// same secret, timestamp, period, digits, algorithm, and encoder always
// produce the same code. Malformed input (a secret that fails to decode, or
// an unsupported digits/algorithm/encoder) returns a structured error in the
// output rather than a Go error or a crash.
func GenerateTotpCode(ctx context.Context, ax axiom.Context, input *gen.GenerateTotpCodeInput) (*gen.OtpCode, error) {
	raw, err := decodeSecret(input.GetSecret())
	if err != nil {
		return &gen.OtpCode{Error: err.Error()}, nil
	}
	digits, err := parseDigits(input.GetDigits())
	if err != nil {
		return &gen.OtpCode{Error: err.Error()}, nil
	}
	algorithm, err := parseAlgorithm(input.GetAlgorithm())
	if err != nil {
		return &gen.OtpCode{Error: err.Error()}, nil
	}
	encoder, err := parseEncoder(input.GetEncoder())
	if err != nil {
		return &gen.OtpCode{Error: err.Error()}, nil
	}
	period := input.GetPeriodSeconds()
	if period == 0 {
		period = 30
	}

	code, err := totp.GenerateCodeCustom(secretToBase32(raw), time.Unix(input.GetTimestampUnix(), 0).UTC(), totp.ValidateOpts{
		Period:    uint(period),
		Digits:    digits,
		Algorithm: algorithm,
		Encoder:   encoder,
	})
	if err != nil {
		return &gen.OtpCode{Error: "failed to generate code: " + err.Error()}, nil
	}
	return &gen.OtpCode{Code: code}, nil
}
