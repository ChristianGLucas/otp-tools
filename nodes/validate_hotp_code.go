package nodes

import (
	"context"
	"math"

	"github.com/pquerna/otp/hotp"

	"christiangeorgelucas/otp-tools/axiom"
	gen "christiangeorgelucas/otp-tools/gen"
)

// maxHotpWindow bounds the look-ahead window before anything runs — each
// step costs one HMAC computation, so an unbounded caller-supplied window is
// an input->cost dimension worth capping even though the per-step cost is
// tiny.
const maxHotpWindow = 1000

// Verifies a caller-submitted HOTP code against a shared secret and a
// stored counter, tolerating the token having been used up to
// `look_ahead_window` times ahead of what the caller has recorded (RFC 4226
// §7.4's resynchronization guidance). A well-formed code that matches
// nothing in the window is a normal result (valid=false, error empty); error
// is reserved for malformed input. On a match, the caller MUST advance its
// stored counter to matched_counter+1 to prevent the same code being
// replayed.
func ValidateHotpCode(ctx context.Context, ax axiom.Context, input *gen.ValidateHotpCodeInput) (*gen.HotpValidationResult, error) {
	raw, err := decodeSecret(input.GetSecret())
	if err != nil {
		return &gen.HotpValidationResult{Error: err.Error()}, nil
	}
	digits, err := parseDigits(input.GetDigits())
	if err != nil {
		return &gen.HotpValidationResult{Error: err.Error()}, nil
	}
	algorithm, err := parseAlgorithm(input.GetAlgorithm())
	if err != nil {
		return &gen.HotpValidationResult{Error: err.Error()}, nil
	}
	encoder, err := parseEncoder(input.GetEncoder())
	if err != nil {
		return &gen.HotpValidationResult{Error: err.Error()}, nil
	}
	window := uint32(10)
	if input.LookAheadWindow != nil {
		window = input.GetLookAheadWindow()
	}
	if window > maxHotpWindow {
		return &gen.HotpValidationResult{Error: "look_ahead_window exceeds the maximum of 1000"}, nil
	}
	if input.GetCounter() > math.MaxUint64-uint64(window) {
		return &gen.HotpValidationResult{Error: "counter + look_ahead_window overflows"}, nil
	}

	secretB32 := secretToBase32(raw)
	opts := hotp.ValidateOpts{Digits: digits, Algorithm: algorithm, Encoder: encoder}

	for off := uint32(0); off <= window; off++ {
		counter := input.GetCounter() + uint64(off)
		ok, err := hotp.ValidateCustom(input.GetCode(), counter, secretB32, opts)
		if err != nil {
			return &gen.HotpValidationResult{Error: "failed to validate code: " + err.Error()}, nil
		}
		if ok {
			return &gen.HotpValidationResult{Valid: true, MatchedCounter: counter, Offset: off}, nil
		}
	}
	return &gen.HotpValidationResult{Valid: false}, nil
}
