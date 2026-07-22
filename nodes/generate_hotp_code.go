package nodes

import (
	"context"

	"github.com/pquerna/otp/hotp"

	"christiangeorgelucas/otp-tools/axiom"
	gen "christiangeorgelucas/otp-tools/gen"
)

// Computes an RFC 4226 HOTP code for a shared secret at one caller-supplied
// counter value. Deterministic: the same secret, counter, digits, algorithm,
// and encoder always produce the same code. Malformed input (a secret that
// fails to decode, or an unsupported digits/algorithm/encoder) returns a
// structured error in the output rather than a Go error or a crash.
func GenerateHotpCode(ctx context.Context, ax axiom.Context, input *gen.GenerateHotpCodeInput) (*gen.OtpCode, error) {
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

	code, err := hotp.GenerateCodeCustom(secretToBase32(raw), input.GetCounter(), hotp.ValidateOpts{
		Digits:    digits,
		Algorithm: algorithm,
		Encoder:   encoder,
	})
	if err != nil {
		return &gen.OtpCode{Error: "failed to generate code: " + err.Error()}, nil
	}
	return &gen.OtpCode{Code: code}, nil
}
