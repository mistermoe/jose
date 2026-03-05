package dsa

import (
	_ecdsa "crypto/ecdsa"
	_ed25519 "crypto/ed25519"
	_rsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/mistermoe/jose/dsa/ecdsa"
	"github.com/mistermoe/jose/dsa/eddsa"
	"github.com/mistermoe/jose/dsa/rsa"
	"github.com/mistermoe/jose/jwk"
)

const (
	AlgorithmIDSECP256K1 = ecdsa.SECP256K1AlgorithmID
	AlgorithmIDSECP384R1 = ecdsa.SECP384R1AlgorithmID
	AlgorithmIDED25519   = eddsa.ED25519AlgorithmID
	AlgorithmIDRS256     = rsa.RS256AlgorithmID
)

// GeneratePrivateKey generates a private key using the algorithm specified by algorithmID.
func GeneratePrivateKey(algorithmID string) (jwk.JWK, error) {
	switch {
	case ecdsa.SupportsAlgorithmID(algorithmID):
		return ecdsa.GeneratePrivateKey(algorithmID)
	case eddsa.SupportsAlgorithmID(algorithmID):
		return eddsa.GeneratePrivateKey(algorithmID)
	case rsa.SupportsAlgorithmID(algorithmID):
		return rsa.GeneratePrivateKey(algorithmID)
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
}

// GetPublicKey returns the public key corresponding to the given private key.
func GetPublicKey(privateKey jwk.JWK) jwk.JWK {
	switch privateKey.KTY {
	case ecdsa.KeyType:
		return ecdsa.GetPublicKey(privateKey)
	case eddsa.KeyType:
		return eddsa.GetPublicKey(privateKey)
	case rsa.KeyType:
		return rsa.GetPublicKey(privateKey)
	default:
		return jwk.JWK{}
	}
}

// Sign signs the payload using the given private key.
func Sign(payload []byte, jwk jwk.JWK) ([]byte, error) {
	switch jwk.KTY {
	case ecdsa.KeyType:
		return ecdsa.Sign(payload, jwk)
	case eddsa.KeyType:
		return eddsa.Sign(payload, jwk)
	case rsa.KeyType:
		return rsa.Sign(payload, jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}

// Verify verifies the signature of the payload using the given public key.
func Verify(payload []byte, signature []byte, jwk jwk.JWK) (bool, error) {
	switch jwk.KTY {
	case ecdsa.KeyType:
		return ecdsa.Verify(payload, signature, jwk)
	case eddsa.KeyType:
		return eddsa.Verify(payload, signature, jwk)
	case rsa.KeyType:
		return rsa.Verify(payload, signature, jwk)
	default:
		return false, fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}

// GetJWA returns the JWA (JSON Web Algorithm) algorithm corresponding to the given key.
func GetJWA(jwk jwk.JWK) (string, error) {
	switch jwk.KTY {
	case ecdsa.KeyType:
		return ecdsa.GetJWA(jwk)
	case eddsa.KeyType:
		return eddsa.GetJWA(jwk)
	case rsa.KeyType:
		return rsa.GetJWA(jwk)
	default:
		return "", fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}

// BytesToPublicKey converts the given bytes to a public key based on the algorithm specified by algorithmID.
func BytesToPublicKey(algorithmID string, input []byte) (jwk.JWK, error) {
	switch {
	case ecdsa.SupportsAlgorithmID(algorithmID):
		return ecdsa.BytesToPublicKey(algorithmID, input)
	case eddsa.SupportsAlgorithmID(algorithmID):
		return eddsa.BytesToPublicKey(algorithmID, input)
	case rsa.SupportsAlgorithmID(algorithmID):
		return rsa.BytesToPublicKey(algorithmID, input)
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
}

// PublicKeyToBytes converts the provided public key to bytes.
func PublicKeyToBytes(publicKey jwk.JWK) ([]byte, error) {
	switch publicKey.KTY {
	case ecdsa.KeyType:
		return ecdsa.PublicKeyToBytes(publicKey)
	case eddsa.KeyType:
		return eddsa.PublicKeyToBytes(publicKey)
	case rsa.KeyType:
		return rsa.PublicKeyToBytes(publicKey)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", publicKey.KTY)
	}
}

// PrivateKeyFromPEM parses a PEM-encoded private key and converts it to a jwk.JWK.
// Supports PKCS#8 (all key types), SEC 1 (EC), and PKCS#1 (RSA) encodings.
func PrivateKeyFromPEM(pemBytes []byte) (jwk.JWK, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return jwk.JWK{}, errors.New("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to format-specific parsers
		if ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			key = ecKey
		} else if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
			key = rsaKey
		} else {
			return jwk.JWK{}, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	switch k := key.(type) {
	case *_ecdsa.PrivateKey:
		return ecdsa.PrivateJwkFromKey(k)
	case _ed25519.PrivateKey:
		return eddsa.PrivateJwkFromKey(k)
	case *_rsa.PrivateKey:
		return rsa.PrivateJwkFromKey(k)
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// PublicKeyFromPEM parses a PEM-encoded public key and converts it to a jwk.JWK.
func PublicKeyFromPEM(pemBytes []byte) (jwk.JWK, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return jwk.JWK{}, errors.New("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch k := key.(type) {
	case *_ecdsa.PublicKey:
		return ecdsa.PublicJwkFromKey(k)
	case _ed25519.PublicKey:
		return eddsa.PublicJwkFromKey(k)
	case *_rsa.PublicKey:
		return rsa.PublicJwkFromKey(k)
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported public key type: %T", key)
	}
}

// AlgorithmID returns the algorithm ID for the given jwk.JWK.
func AlgorithmID(jwk *jwk.JWK) (string, error) {
	switch jwk.KTY {
	case ecdsa.KeyType:
		return ecdsa.AlgorithmID(jwk)
	case eddsa.KeyType:
		return eddsa.AlgorithmID(jwk)
	case rsa.KeyType:
		return rsa.AlgorithmID(jwk)
	default:
		return "", fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}
