package rsa_test

import (
	"testing"

	"github.com/mistermoe/jose/dsa/rsa"
	"github.com/mistermoe/jose/jwk"

	"github.com/alecthomas/assert/v2"
)

func TestRS256GeneratePrivateKey(t *testing.T) {
	key, err := rsa.RS256GeneratePrivateKey()
	assert.NoError(t, err)

	assert.Equal(t, rsa.KeyType, key.KTY)
	assert.NotZero(t, key.N)
	assert.NotZero(t, key.E)
	assert.NotZero(t, key.D)
}

func TestRS256SignAndVerify(t *testing.T) {
	privateKey, err := rsa.RS256GeneratePrivateKey()
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := rsa.RS256Sign(payload, privateKey)
	assert.NoError(t, err)
	assert.True(t, len(signature) > 0, "signature is empty")

	// Extract public key
	publicKey := jwk.JWK{
		KTY: privateKey.KTY,
		N:   privateKey.N,
		E:   privateKey.E,
	}

	// Verify signature
	valid, err := rsa.RS256Verify(payload, signature, publicKey)
	assert.NoError(t, err)
	assert.True(t, valid, "signature verification failed")
}

func TestRS256VerifyInvalidSignature(t *testing.T) {
	privateKey, err := rsa.RS256GeneratePrivateKey()
	assert.NoError(t, err)

	payload := []byte("hello world")

	// Extract public key
	publicKey := jwk.JWK{
		KTY: privateKey.KTY,
		N:   privateKey.N,
		E:   privateKey.E,
	}

	// Try to verify invalid signature
	invalidSignature := []byte("invalid signature")
	valid, err := rsa.RS256Verify(payload, invalidSignature, publicKey)
	assert.NoError(t, err) // Should not error, just return false
	assert.False(t, valid, "invalid signature should not verify")
}

func TestRS256VerifyWithWrongPayload(t *testing.T) {
	privateKey, err := rsa.RS256GeneratePrivateKey()
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := rsa.RS256Sign(payload, privateKey)
	assert.NoError(t, err)

	// Extract public key
	publicKey := jwk.JWK{
		KTY: privateKey.KTY,
		N:   privateKey.N,
		E:   privateKey.E,
	}

	// Try to verify with different payload
	wrongPayload := []byte("goodbye world")
	valid, err := rsa.RS256Verify(wrongPayload, signature, publicKey)
	assert.NoError(t, err)
	assert.False(t, valid, "signature should not verify with wrong payload")
}

func TestRS256WithProvidedJWK(t *testing.T) {
	// Test with one of the provided JWT verification keys
	publicKey := jwk.JWK{
		KTY: "RSA",
		N:   "tH5pdWojgagY73Hy2WtH8vhoKpGAmP01E1CSuZn-02U_hTjFzAoDAiT6d7CcP14VHg4AGRWY82NCw5HL9vapXilR0Y1g3lFWwRCU1oXjApzhkTt3RVbM-jPWr5aEC_QN6yTE9qK1lwz1_x03rPMOuSP7BcDQCNazPLPwIDxMtzT47asH25OrtiN-nFA_imMAMrqKEBhmYtutGqKqhs6vI_PsNHxLFyR26Z-CgGrQ21Eensu0jl29vl0uYBfVUG4XpzOp7A5_rwVPaHx5ZibUSVG-eVu0RYObSKJTXQg8NKs3bEUHk9Z563PgTA9mf5VsvenNm6DxCJrvztxKvhg1Nw",
		E:   "AQAB",
	}

	// Since we don't have the private key for the provided JWK, we can't test signing
	// But we can test that the key can be converted to Go's RSA format
	_, err := rsa.RS256PublicKeyToBytes(publicKey)
	assert.NoError(t, err, "should be able to convert provided JWK to bytes")
}

func TestRS256BytesToPublicKey_Invalid(t *testing.T) {
	invalidBytes := []byte("invalid key data")
	_, err := rsa.RS256BytesToPublicKey(invalidBytes)
	assert.Error(t, err, "should error on invalid key data")
}

func TestRS256PublicKeyToBytes_Invalid(t *testing.T) {
	// Test with missing N
	invalidKey := jwk.JWK{
		KTY: "RSA",
		E:   "AQAB",
	}
	_, err := rsa.RS256PublicKeyToBytes(invalidKey)
	assert.Error(t, err, "should error when N is missing")

	// Test with missing E
	invalidKey2 := jwk.JWK{
		KTY: "RSA",
		N:   "tH5pdWojgagY73Hy2WtH8vhoKpGAmP01E1CSuZn-02U_hTjFzAoDAiT6d7CcP14VHg4AGRWY82NCw5HL9vapXilR0Y1g3lFWwRCU1oXjApzhkTt3RVbM-jPWr5aEC_QN6yTE9qK1lwz1_x03rPMOuSP7BcDQCNazPLPwIDxMtzT47asH25OrtiN-nFA_imMAMrqKEBhmYtutGqKqhs6vI_PsNHxLFyR26Z-CgGrQ21Eensu0jl29vl0uYBfVUG4XpzOp7A5_rwVPaHx5ZibUSVG-eVu0RYObSKJTXQg8NKs3bEUHk9Z563PgTA9mf5VsvenNm6DxCJrvztxKvhg1Nw",
	}
	_, err = rsa.RS256PublicKeyToBytes(invalidKey2)
	assert.Error(t, err, "should error when E is missing")
}
