package rsa

import (
	"crypto"
	"crypto/rand"
	_rsa "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/mistermoe/jose/jwk"
)

const (
	RS256JWA         string = "RS256"
	RS256AlgorithmID string = "RS256"
	DefaultKeySize   int    = 2048
)

// RS256GeneratePrivateKey generates a new RSA private key for RS256.
func RS256GeneratePrivateKey() (jwk.JWK, error) {
	privateKey, err := _rsa.GenerateKey(rand.Reader, DefaultKeySize)
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	return rsaPrivateKeyToJWK(privateKey)
}

// RS256Sign signs the given payload with the given private key using RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
func RS256Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	rsaPrivateKey, err := jwkToRSAPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWK to RSA private key: %w", err)
	}

	hash := sha256.Sum256(payload)
	signature, err := _rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with RS256: %w", err)
	}

	return signature, nil
}

// RS256Verify verifies the given signature over the given payload with the given public key using RS256.
func RS256Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	rsaPublicKey, err := jwkToRSAPublicKey(publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to convert JWK to RSA public key: %w", err)
	}

	hash := sha256.Sum256(payload)
	err = _rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

// RS256BytesToPublicKey converts RSA public key bytes to a JWK.
func RS256BytesToPublicKey(input []byte) (jwk.JWK, error) {
	// Try to parse as DER first
	publicKey, err := x509.ParsePKIXPublicKey(input)
	if err != nil {
		// Try to parse as PEM
		block, _ := pem.Decode(input)
		if block == nil {
			return jwk.JWK{}, errors.New("failed to parse PEM block")
		}
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return jwk.JWK{}, fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	rsaPublicKey, ok := publicKey.(*_rsa.PublicKey)
	if !ok {
		return jwk.JWK{}, errors.New("not an RSA public key")
	}

	return rsaPublicKeyToJWK(rsaPublicKey)
}

// RS256PublicKeyToBytes converts an RSA public key JWK to bytes.
func RS256PublicKeyToBytes(publicKey jwk.JWK) ([]byte, error) {
	rsaPublicKey, err := jwkToRSAPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return x509.MarshalPKIXPublicKey(rsaPublicKey)
}

// Helper functions for JWK conversion

func rsaPrivateKeyToJWK(privateKey *_rsa.PrivateKey) (jwk.JWK, error) {
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())
	d := base64.RawURLEncoding.EncodeToString(privateKey.D.Bytes())

	return jwk.JWK{
		KTY: KeyType,
		ALG: RS256JWA,
		N:   n,
		E:   e,
		D:   d,
	}, nil
}

func rsaPublicKeyToJWK(publicKey *_rsa.PublicKey) (jwk.JWK, error) {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	return jwk.JWK{
		KTY: KeyType,
		ALG: RS256JWA,
		N:   n,
		E:   e,
	}, nil
}

func jwkToRSAPrivateKey(privateKey jwk.JWK) (*_rsa.PrivateKey, error) {
	if privateKey.N == "" || privateKey.E == "" || privateKey.D == "" {
		return nil, errors.New("n, e, and d must be set for RSA private key")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(privateKey.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(privateKey.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	dBytes, err := base64.RawURLEncoding.DecodeString(privateKey.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode d: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	d := new(big.Int).SetBytes(dBytes)

	rsaPrivateKey := &_rsa.PrivateKey{
		PublicKey: _rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D: d,
	}

	return rsaPrivateKey, nil
}

func jwkToRSAPublicKey(publicKey jwk.JWK) (*_rsa.PublicKey, error) {
	if publicKey.N == "" || publicKey.E == "" {
		return nil, errors.New("n and e must be set for RSA public key")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(publicKey.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(publicKey.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &_rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
