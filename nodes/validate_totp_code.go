package nodes

import (
	"context"
	"math"

	"github.com/pquerna/otp/hotp"

	"christiangeorgelucas/otp-tools/axiom"
	gen "christiangeorgelucas/otp-tools/gen"
)

// maxTotpSkew bounds the drift window before anything runs — each step of
// skew costs one more HMAC computation, so an unbounded caller-supplied skew
// is an input->cost dimension worth capping even though the per-step cost is
// tiny.
const maxTotpSkew = 100

// Verifies a caller-submitted TOTP code against a shared secret at a
// caller-supplied "now", tolerating up to `skew` time-steps of clock drift
// on either side (the standard TOTP verification pattern — see RFC 6238
// §5.2). Checks the exact time-step first, then alternates ±1, ±2, ... out
// to `skew`, and reports the offset that matched so a caller can detect a
// client whose clock is persistently ahead or behind. A well-formed code
// that simply does not match is a normal result (valid=false, error empty);
// error is reserved for malformed input.
func ValidateTotpCode(ctx context.Context, ax axiom.Context, input *gen.ValidateTotpCodeInput) (*gen.TotpValidationResult, error) {
	raw, err := decodeSecret(input.GetSecret())
	if err != nil {
		return &gen.TotpValidationResult{Error: err.Error()}, nil
	}
	digits, err := parseDigits(input.GetDigits())
	if err != nil {
		return &gen.TotpValidationResult{Error: err.Error()}, nil
	}
	algorithm, err := parseAlgorithm(input.GetAlgorithm())
	if err != nil {
		return &gen.TotpValidationResult{Error: err.Error()}, nil
	}
	encoder, err := parseEncoder(input.GetEncoder())
	if err != nil {
		return &gen.TotpValidationResult{Error: err.Error()}, nil
	}
	period := input.GetPeriodSeconds()
	if period == 0 {
		period = 30
	}
	skew := uint32(1)
	if input.Skew != nil {
		skew = input.GetSkew()
	}
	if skew > maxTotpSkew {
		return &gen.TotpValidationResult{Error: "skew exceeds the maximum of 100"}, nil
	}

	secretB32 := secretToBase32(raw)
	opts := hotp.ValidateOpts{Digits: digits, Algorithm: algorithm, Encoder: encoder}
	baseCounter := int64(math.Floor(float64(input.GetTimestampUnix()) / float64(period)))

	// Exact step first, then alternate outward — mirrors the order
	// totp.ValidateCustom itself checks in, so the reported offset matches
	// what the reference implementation would have accepted.
	offsets := make([]int32, 0, 2*int(skew)+1)
	offsets = append(offsets, 0)
	for i := int32(1); i <= int32(skew); i++ {
		offsets = append(offsets, i, -i)
	}

	for _, off := range offsets {
		counter := baseCounter + int64(off)
		if counter < 0 {
			continue
		}
		ok, err := hotp.ValidateCustom(input.GetCode(), uint64(counter), secretB32, opts)
		if err != nil {
			return &gen.TotpValidationResult{Error: "failed to validate code: " + err.Error()}, nil
		}
		if ok {
			return &gen.TotpValidationResult{Valid: true, MatchedSkew: off}, nil
		}
	}
	return &gen.TotpValidationResult{Valid: false}, nil
}
