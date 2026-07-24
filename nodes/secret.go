// Package-shared helpers for decoding an OtpSecret, mapping the
// algorithm/digits/encoder vocabulary onto github.com/pquerna/otp's types,
// and re-encoding bytes to base32 for otpauth:// URIs and generated
// secrets. Kept in one file so every node applies the exact same rules.
package nodes

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/pquerna/otp"

	gen "christiangeorgelucas/otp-tools/gen"
)

// b32NoPad is the padding-free base32 alphabet used throughout — the same
// convention pquerna/otp itself uses when it mints a secret, and what
// otpauth:// URIs and authenticator apps expect.
var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// decodeSecret turns a caller-supplied OtpSecret into raw key bytes,
// honoring `encoding` (default "base32" when empty). Returns a plain error
// with a short, non-sensitive message — callers must never echo the raw
// secret value back into an error string.
func decodeSecret(s *gen.OtpSecret) ([]byte, error) {
	if s == nil || s.GetValue() == "" {
		return nil, errors.New("secret.value is required")
	}
	enc := strings.ToLower(strings.TrimSpace(s.GetEncoding()))
	if enc == "" {
		enc = "base32"
	}
	v := s.GetValue()

	var out []byte
	var err error
	switch enc {
	case "base32":
		out, err = decodeBase32Tolerant(v)
	case "hex":
		out, err = hex.DecodeString(strings.TrimSpace(v))
	case "base64":
		out, err = base64.StdEncoding.DecodeString(v)
		if err != nil {
			out, err = base64.RawStdEncoding.DecodeString(v)
		}
	case "base64url":
		out, err = base64.URLEncoding.DecodeString(v)
		if err != nil {
			out, err = base64.RawURLEncoding.DecodeString(v)
		}
	case "utf8":
		out, err = []byte(v), nil
	default:
		return nil, fmt.Errorf("unsupported secret encoding %q (want base32, hex, base64, base64url, or utf8)", enc)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid secret.value for encoding %q", enc)
	}
	if len(out) == 0 {
		return nil, errors.New("secret decodes to zero bytes")
	}
	return out, nil
}

// decodeBase32Tolerant mirrors pquerna/otp's own leniency (trim whitespace,
// re-pad to a multiple of 8, upper-case) so a secret copied from an
// authenticator app or another OtpSecret's base32 output decodes the same
// way here as it would inside GenerateCodeCustom.
func decodeBase32Tolerant(v string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimSpace(v))
	if n := len(s) % 8; n != 0 {
		s = s + strings.Repeat("=", 8-n)
	}
	return base32.StdEncoding.DecodeString(s)
}

// secretToBase32 re-encodes raw bytes as padding-free base32 for embedding
// in an otpauth:// URI or returning as a freshly generated secret.
func secretToBase32(b []byte) string {
	return b32NoPad.EncodeToString(b)
}

// parseAlgorithm maps the package's string vocabulary onto otp.Algorithm.
// Defaults to SHA1 (RFC 6238/4226's own default, and required for Google
// Authenticator compatibility) when empty. MD5 is deliberately not exposed —
// pquerna/otp supports it internally but it is not part of RFC 6238/4226 and
// no mainstream authenticator app accepts it.
func parseAlgorithm(a string) (otp.Algorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(a)) {
	case "", "SHA1":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q (want SHA1, SHA256, or SHA512)", a)
	}
}

// parseDigits maps 0 (unset) to 6, and otherwise requires 6 or 8 — the only
// two values pquerna/otp's Digits type defines.
func parseDigits(d int32) (otp.Digits, error) {
	switch d {
	case 0, 6:
		return otp.DigitsSix, nil
	case 8:
		return otp.DigitsEight, nil
	default:
		return 0, fmt.Errorf("unsupported digits %d (want 6 or 8)", d)
	}
}

// parseEncoder maps the package's string vocabulary onto otp.Encoder.
func parseEncoder(e string) (otp.Encoder, error) {
	switch strings.ToLower(strings.TrimSpace(e)) {
	case "", "standard", "default":
		return otp.EncoderDefault, nil
	case "steam":
		return otp.EncoderSteam, nil
	default:
		return otp.EncoderDefault, fmt.Errorf("unsupported encoder %q (want standard or steam)", e)
	}
}
