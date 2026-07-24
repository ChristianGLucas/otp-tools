package nodes

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"christiangeorgelucas/otp-tools/axiom"
	gen "christiangeorgelucas/otp-tools/gen"
)

// Generates a fresh shared secret, base32-encoded and ready to hand to any
// other node's OtpSecret or embed via BuildProvisioningUri. With `entropy`
// left empty (the normal, intended use — actually provisioning a new 2FA
// credential), the bytes come from crypto/rand, a CSPRNG, exactly as
// github.com/pquerna/otp's own totp.Generate/hotp.Generate do internally —
// this node never uses math/rand or any predictable seed. Supplying
// `entropy` explicitly (exactly byte_length bytes) instead makes generation
// a pure, deterministic function of the input, for tests and reproducible
// fixtures — it is never appropriate for a real credential.
func GenerateRandomSecret(ctx context.Context, ax axiom.Context, input *gen.GenerateRandomSecretInput) (*gen.RandomSecretResult, error) {
	length := input.GetByteLength()
	if length == 0 {
		length = 20
	}

	var secret []byte
	if entropy := input.GetEntropy(); len(entropy) > 0 {
		if uint32(len(entropy)) != length {
			return &gen.RandomSecretResult{Error: fmt.Sprintf("entropy is %d bytes, want exactly byte_length=%d", len(entropy), length)}, nil
		}
		secret = entropy
	} else {
		secret = make([]byte, length)
		if _, err := io.ReadFull(rand.Reader, secret); err != nil {
			return &gen.RandomSecretResult{Error: "failed to read random bytes: " + err.Error()}, nil
		}
	}

	return &gen.RandomSecretResult{
		SecretBase32: secretToBase32(secret),
		ByteLength:   length,
	}, nil
}
