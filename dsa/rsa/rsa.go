package rsa

import (
	"errors"
	"fmt"

	"github.com/mistermoe/jose/jwk"
)

const (
	KeyType = "RSA"
)

var algorithmIDs = map[string]bool{
	RS256AlgorithmID: true,
}

// GeneratePrivateKey generates an RSA private key for the given algorithm.
func GeneratePrivateKey(algorithmID string) (jwk.JWK, error) {
	switch algorithmID {
	case RS256AlgorithmID:
		return RS256GeneratePrivateKey()
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
}

// GetPublicKey builds an RSA public key from the given RSA private key.
func GetPublicKey(privateKey jwk.JWK) jwk.JWK {
	return jwk.JWK{
		KTY: privateKey.KTY,
		N:   privateKey.N,
		E:   privateKey.E,
	}
}

// Sign generates a cryptographic signature for the given payload with the given private key
//
// # Note
//
// The function will automatically detect the RSA algorithm from the given private key.
func Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	if privateKey.D == "" {
		return nil, errors.New("d must be set")
	}

	// For RS256, we can determine the algorithm from the key material
	// In the future, we might need to store ALG in the JWK or determine it another way
	return RS256Sign(payload, privateKey)
}

// Verify verifies the given signature over a given payload by the given public key
//
// # Note
//
// The function will automatically detect the RSA algorithm from the given public key.
func Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	// For now, we only support RS256, so we'll use that
	// In the future, we might need to determine the algorithm from the key or context
	return RS256Verify(payload, signature, publicKey)
}

// GetJWA returns the [JWA] for the given RSA key
//
// [JWA]: https://datatracker.ietf.org/doc/html/rfc7518
func GetJWA(jwk jwk.JWK) (string, error) {
	// For now, we only support RS256
	// In the future, we might determine this from key size or store it in the JWK
	return RS256JWA, nil
}

// BytesToPublicKey deserializes the given byte array into a jwk.JWK for the given cryptographic algorithm.
func BytesToPublicKey(algorithmID string, input []byte) (jwk.JWK, error) {
	switch algorithmID {
	case RS256AlgorithmID:
		return RS256BytesToPublicKey(input)
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
}

// PublicKeyToBytes serializes the given public key into a byte array.
func PublicKeyToBytes(publicKey jwk.JWK) ([]byte, error) {
	// For now, we only support RS256
	return RS256PublicKeyToBytes(publicKey)
}

// SupportsAlgorithmID informs as to whether or not the given algorithm ID is supported by this package.
func SupportsAlgorithmID(id string) bool {
	return algorithmIDs[id]
}

// AlgorithmID returns the algorithm ID for the given jwk.JWK.
func AlgorithmID(jwk *jwk.JWK) (string, error) {
	// For now, we only support RS256
	// In the future, we might determine this from key size or other factors
	return RS256AlgorithmID, nil
}
