package entropy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// Size represents the size of the entropy in bits, i.e. Entropy128 is equal to 128 bits (or 16 bytes) of entrop.
type Size int

// Directly set the sizes according to NIST recommendations for entropy
// defined here: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
const (
	Size112 Size = 112 / 8 // 14 bytes
	Size128 Size = 128 / 8 // 16 bytes
	Size192 Size = 192 / 8 // 24 bytes
	Size256 Size = 256 / 8 // 32 bytes
)

// Generate generates a random byte array of size n bytes.
func Generate(n Size) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("entropy byte size must be > 0")
	}

	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// GenerateNonce generates a hex-encoded nonce by calling GenerateEntropy with a size of 16 bytes (128 bits).
func GenerateNonce(n Size) (string, error) {
	bytes, err := Generate(n)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
