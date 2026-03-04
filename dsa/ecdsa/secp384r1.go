package ecdsa

import (
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
	SECP384R1JWA         string = "ES384"
	SECP384R1JWACurve    string = "P-384"
	SECP384R1AlgorithmID string = "secp384r1"
	SECP384R1KeySize            = 48
	SECP384R1SignatureSize      = 96
)

func SECP384R1GeneratePrivateKey() (jwk.JWK, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	d := key.D.Bytes()
	x := key.PublicKey.X.Bytes()
	y := key.PublicKey.Y.Bytes()

	dPadded := padLeft(d, SECP384R1KeySize)
	xPadded := padLeft(x, SECP384R1KeySize)
	yPadded := padLeft(y, SECP384R1KeySize)

	return jwk.JWK{
		KTY: KeyType,
		CRV: SECP384R1JWACurve,
		D:   base64.RawURLEncoding.EncodeToString(dPadded),
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
	}, nil
}

func SECP384R1Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	dBytes, err := base64.RawURLEncoding.DecodeString(privateKey.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode d: %w", err)
	}

	key := new(ecdsa.PrivateKey)
	key.Curve = elliptic.P384()
	key.D = new(big.Int).SetBytes(dBytes)
	key.PublicKey.X, key.PublicKey.Y = key.Curve.ScalarBaseMult(dBytes)

	hash := sha512.Sum384(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	rBytes := padLeft(r.Bytes(), SECP384R1KeySize)
	sBytes := padLeft(s.Bytes(), SECP384R1KeySize)

	signature := make([]byte, SECP384R1SignatureSize)
	copy(signature[:SECP384R1KeySize], rBytes)
	copy(signature[SECP384R1KeySize:], sBytes)

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
// Supports both compressed (0x02/0x03 prefix, 49 bytes) and
// uncompressed (0x04 prefix, 97 bytes) SEC 1 encodings.
func SECP384R1BytesToPublicKey(input []byte) (jwk.JWK, error) {
	x, y := elliptic.Unmarshal(elliptic.P384(), input)
	if x == nil {
		return jwk.JWK{}, errors.New("failed to parse public key")
	}

	return jwk.JWK{
		KTY: KeyType,
		CRV: SECP384R1JWACurve,
		X:   base64.RawURLEncoding.EncodeToString(padLeft(x.Bytes(), SECP384R1KeySize)),
		Y:   base64.RawURLEncoding.EncodeToString(padLeft(y.Bytes(), SECP384R1KeySize)),
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

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	if !elliptic.P384().IsOnCurve(x, y) {
		return nil, errors.New("point is not on the P-384 curve")
	}

	return elliptic.Marshal(elliptic.P384(), x, y), nil
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
