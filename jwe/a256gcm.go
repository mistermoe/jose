package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/mistermoe/jose/entropy"
	"github.com/mistermoe/jose/jwk"
)

const (
	// A256GCMJWA is the JWA name of the AES GCM using 256-bit key content encryption algorithm.
	A256GCMJWA string = "A256GCM"
	// A256GCMKeyType is the JWK key type used to represent an A256GCM content encryption key.
	A256GCMKeyType string = "oct"
	// A256GCMKeySize is the size of an A256GCM content encryption key in bytes (256 bits).
	A256GCMKeySize = 32
	// A256GCMIVSize is the size of an A256GCM initialization vector in bytes (96 bits).
	A256GCMIVSize = 12
	// A256GCMTagSize is the size of an A256GCM authentication tag in bytes (128 bits).
	A256GCMTagSize = 16
)

// A256GCMGenerateKey generates a new A256GCM content encryption key.
func A256GCMGenerateKey() (jwk.JWK, error) {
	key, err := entropy.Generate(entropy.Size256)
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to generate key: %w", err)
	}

	return jwk.JWK{
		KTY: A256GCMKeyType,
		ALG: A256GCMJWA,
		K:   base64.RawURLEncoding.EncodeToString(key),
	}, nil
}

// A256GCMGenerateIV generates a new A256GCM initialization vector.
func A256GCMGenerateIV() ([]byte, error) {
	iv, err := entropy.Generate(entropy.Size96)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initialization vector: %w", err)
	}

	return iv, nil
}

// A256GCMSeal encrypts the provided plaintext with the provided content encryption key and
// initialization vector, authenticating aad alongside it. It returns the ciphertext and the
// authentication tag separately, as required by the JWE compact serialization.
func A256GCMSeal(cek []byte, iv []byte, plaintext []byte, aad []byte) ([]byte, []byte, error) {
	gcm, err := a256gcmCipher(cek, iv)
	if err != nil {
		return nil, nil, err
	}

	sealed := gcm.Seal(nil, iv, plaintext, aad)
	split := len(sealed) - A256GCMTagSize

	return sealed[:split], sealed[split:], nil
}

// A256GCMOpen decrypts the provided ciphertext with the provided content encryption key,
// initialization vector and authentication tag, checking aad alongside it.
func A256GCMOpen(cek []byte, iv []byte, ciphertext []byte, tag []byte, aad []byte) ([]byte, error) {
	if len(tag) != A256GCMTagSize {
		return nil, fmt.Errorf("authentication tag must be %d bytes", A256GCMTagSize)
	}

	gcm, err := a256gcmCipher(cek, iv)
	if err != nil {
		return nil, err
	}

	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	plaintext, err := gcm.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

// a256gcmCipher builds an AES GCM AEAD from the provided content encryption key after validating
// both it and the initialization vector.
func a256gcmCipher(cek []byte, iv []byte) (cipher.AEAD, error) {
	if len(cek) != A256GCMKeySize {
		return nil, fmt.Errorf("content encryption key must be %d bytes", A256GCMKeySize)
	}

	if len(iv) != A256GCMIVSize {
		return nil, fmt.Errorf("initialization vector must be %d bytes", A256GCMIVSize)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return gcm, nil
}

// a256gcmKeyFromJwk extracts and validates the raw content encryption key from the provided jwk.
func a256gcmKeyFromJwk(key jwk.JWK) ([]byte, error) {
	if key.KTY != A256GCMKeyType {
		return nil, fmt.Errorf("unsupported key type: %s", key.KTY)
	}

	if key.ALG != "" && key.ALG != A256GCMJWA {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", key.ALG)
	}

	if key.K == "" {
		return nil, errors.New("k must be set")
	}

	cek, err := base64.RawURLEncoding.DecodeString(key.K)
	if err != nil {
		return nil, fmt.Errorf("failed to decode k: %w", err)
	}

	if len(cek) != A256GCMKeySize {
		return nil, fmt.Errorf("content encryption key must be %d bytes", A256GCMKeySize)
	}

	return cek, nil
}
