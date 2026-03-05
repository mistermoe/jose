package ecdsa

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/mistermoe/jose/jwk"
)

const (
	SECP384R1JWA           string = "ES384"
	SECP384R1JWACurve      string = "P-384"
	SECP384R1AlgorithmID   string = "secp384r1"
	SECP384R1KeySize              = 48
	SECP384R1SignatureSize        = 96

	// SEC1 uncompressed point prefix (0x04 || x || y).
	uncompressedPointPrefix byte = 0x04
)

func SECP384R1GeneratePrivateKey() (jwk.JWK, error) {
	key, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	pubBytes := key.PublicKey().Bytes()

	return jwk.JWK{
		KTY: KeyType,
		CRV: SECP384R1JWACurve,
		D:   base64.RawURLEncoding.EncodeToString(key.Bytes()),
		X:   base64.RawURLEncoding.EncodeToString(pubBytes[1 : 1+SECP384R1KeySize]),
		Y:   base64.RawURLEncoding.EncodeToString(pubBytes[1+SECP384R1KeySize:]),
	}, nil
}

func SECP384R1Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	dBytes, err := base64.RawURLEncoding.DecodeString(privateKey.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode d: %w", err)
	}

	ecdhKey, err := ecdh.P384().NewPrivateKey(padLeft(dBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct private key: %w", err)
	}

	pubBytes := ecdhKey.PublicKey().Bytes()

	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(pubBytes[1 : 1+SECP384R1KeySize]),
			Y:     new(big.Int).SetBytes(pubBytes[1+SECP384R1KeySize:]),
		},
		D: new(big.Int).SetBytes(dBytes),
	}

	hash := sha512.Sum384(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	signature := make([]byte, SECP384R1SignatureSize)
	copy(signature[:SECP384R1KeySize], padLeft(r.Bytes()))
	copy(signature[SECP384R1KeySize:], padLeft(s.Bytes()))

	return signature, nil
}

func SECP384R1Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	if publicKey.X == "" || publicKey.Y == "" {
		return false, errors.New("x and y must be set")
	}

	if len(signature) != SECP384R1SignatureSize {
		return false, fmt.Errorf("signature must be %d bytes", SECP384R1SignatureSize)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
	if err != nil {
		return false, fmt.Errorf("failed to decode x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(publicKey.Y)
	if err != nil {
		return false, fmt.Errorf("failed to decode y: %w", err)
	}

	key := &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	r := new(big.Int).SetBytes(signature[:SECP384R1KeySize])
	s := new(big.Int).SetBytes(signature[SECP384R1KeySize:])

	hash := sha512.Sum384(payload)
	return ecdsa.Verify(key, hash[:], r, s), nil
}

// SECP384R1BytesToPublicKey converts a P-384 public key to a JWK.
// Accepts the uncompressed point encoding used by [crypto/ecdh.P384].NewPublicKey
// (0x04 || x || y, 97 bytes).
func SECP384R1BytesToPublicKey(input []byte) (jwk.JWK, error) {
	ecdhKey, err := ecdh.P384().NewPublicKey(input)
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	raw := ecdhKey.Bytes()

	return jwk.JWK{
		KTY: KeyType,
		CRV: SECP384R1JWACurve,
		X:   base64.RawURLEncoding.EncodeToString(raw[1 : 1+SECP384R1KeySize]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[1+SECP384R1KeySize:]),
	}, nil
}

func SECP384R1PublicKeyToBytes(publicKey jwk.JWK) ([]byte, error) {
	if publicKey.X == "" || publicKey.Y == "" {
		return nil, errors.New("x and y must be set")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(publicKey.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	uncompressed := make([]byte, 0, 1+2*SECP384R1KeySize)
	uncompressed = append(uncompressed, uncompressedPointPrefix)
	uncompressed = append(uncompressed, padLeft(xBytes)...)
	uncompressed = append(uncompressed, padLeft(yBytes)...)

	// validate the point is on the curve
	if _, err = ecdh.P384().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	return uncompressed, nil
}

// SECP384R1PrivateJwkFromKey converts a *crypto/ecdsa.PrivateKey on the P-384
// curve into a private jwk.JWK.
func SECP384R1PrivateJwkFromKey(key *ecdsa.PrivateKey) (jwk.JWK, error) {
	if key.Curve != elliptic.P384() {
		return jwk.JWK{}, fmt.Errorf("expected P-384 curve, got %s", key.Curve.Params().Name)
	}

	return jwk.JWK{
		KTY: KeyType,
		CRV: SECP384R1JWACurve,
		D:   base64.RawURLEncoding.EncodeToString(padLeft(key.D.Bytes())),
		X:   base64.RawURLEncoding.EncodeToString(padLeft(key.PublicKey.X.Bytes())),
		Y:   base64.RawURLEncoding.EncodeToString(padLeft(key.PublicKey.Y.Bytes())),
	}, nil
}

// SECP384R1PublicJwkFromKey converts a *crypto/ecdsa.PublicKey on the P-384
// curve into a public jwk.JWK.
func SECP384R1PublicJwkFromKey(key *ecdsa.PublicKey) (jwk.JWK, error) {
	if key.Curve != elliptic.P384() {
		return jwk.JWK{}, fmt.Errorf("expected P-384 curve, got %s", key.Curve.Params().Name)
	}

	return jwk.JWK{
		KTY: KeyType,
		CRV: SECP384R1JWACurve,
		X:   base64.RawURLEncoding.EncodeToString(padLeft(key.X.Bytes())),
		Y:   base64.RawURLEncoding.EncodeToString(padLeft(key.Y.Bytes())),
	}, nil
}

func padLeft(b []byte) []byte {
	if len(b) >= SECP384R1KeySize {
		return b
	}
	padded := make([]byte, SECP384R1KeySize)
	copy(padded[SECP384R1KeySize-len(b):], b)
	return padded
}
