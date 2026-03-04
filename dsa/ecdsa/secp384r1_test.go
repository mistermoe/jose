package ecdsa_test

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/mistermoe/jose/dsa/ecdsa"
	"github.com/mistermoe/jose/jwk"

	"github.com/alecthomas/assert/v2"
)

func TestSECP384R1GeneratePrivateKey(t *testing.T) {
	key, err := ecdsa.SECP384R1GeneratePrivateKey()
	assert.NoError(t, err)

	assert.Equal(t, ecdsa.KeyType, key.KTY)
	assert.Equal(t, ecdsa.SECP384R1JWACurve, key.CRV)
	assert.True(t, key.D != "", "privateJwk.D is empty")
	assert.True(t, key.X != "", "privateJwk.X is empty")
	assert.True(t, key.Y != "", "privateJwk.Y is empty")
}

func TestSECP384R1SignVerify(t *testing.T) {
	key, err := ecdsa.SECP384R1GeneratePrivateKey()
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := ecdsa.SECP384R1Sign(payload, key)
	assert.NoError(t, err)
	assert.Equal(t, ecdsa.SECP384R1SignatureSize, len(signature))

	pubKey := jwk.JWK{
		KTY: key.KTY,
		CRV: key.CRV,
		X:   key.X,
		Y:   key.Y,
	}

	legit, err := ecdsa.SECP384R1Verify(payload, signature, pubKey)
	assert.NoError(t, err)
	assert.True(t, legit, "failed to verify signature")
}

func TestSECP384R1Verify_WrongPayload(t *testing.T) {
	key, err := ecdsa.SECP384R1GeneratePrivateKey()
	assert.NoError(t, err)

	signature, err := ecdsa.SECP384R1Sign([]byte("hello world"), key)
	assert.NoError(t, err)

	pubKey := jwk.JWK{KTY: key.KTY, CRV: key.CRV, X: key.X, Y: key.Y}

	legit, err := ecdsa.SECP384R1Verify([]byte("wrong payload"), signature, pubKey)
	assert.NoError(t, err)
	assert.False(t, legit)
}

func TestSECP384R1BytesToPublicKey_Bad(t *testing.T) {
	_, err := ecdsa.SECP384R1BytesToPublicKey([]byte{0x00, 0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestSECP384R1BytesToPublicKey_Uncompressed(t *testing.T) {
	key, err := ecdsa.SECP384R1GeneratePrivateKey()
	assert.NoError(t, err)

	pubKey := jwk.JWK{KTY: key.KTY, CRV: key.CRV, X: key.X, Y: key.Y}
	keyBytes, err := ecdsa.SECP384R1PublicKeyToBytes(pubKey)
	assert.NoError(t, err)

	recovered, err := ecdsa.SECP384R1BytesToPublicKey(keyBytes)
	assert.NoError(t, err)

	assert.Equal(t, ecdsa.SECP384R1JWACurve, recovered.CRV)
	assert.Equal(t, ecdsa.KeyType, recovered.KTY)
	assert.Equal(t, pubKey.X, recovered.X)
	assert.Equal(t, pubKey.Y, recovered.Y)
}

func TestSECP384R1PublicKeyToBytes(t *testing.T) {
	key, err := ecdsa.SECP384R1GeneratePrivateKey()
	assert.NoError(t, err)

	pubKey := jwk.JWK{KTY: key.KTY, CRV: key.CRV, X: key.X, Y: key.Y}
	pubKeyBytes, err := ecdsa.SECP384R1PublicKeyToBytes(pubKey)
	assert.NoError(t, err)

	// uncompressed format: 0x04 || x (48 bytes) || y (48 bytes) = 97 bytes
	assert.Equal(t, 97, len(pubKeyBytes))
	assert.Equal(t, byte(0x04), pubKeyBytes[0])
}

func TestSECP384R1PublicKeyToBytes_Bad(t *testing.T) {
	vectors := []jwk.JWK{
		{
			KTY: "EC",
			CRV: ecdsa.SECP384R1JWACurve,
			X:   "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
		},
		{
			KTY: "EC",
			CRV: ecdsa.SECP384R1JWACurve,
			Y:   "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
		},
		{
			KTY: "EC",
			CRV: ecdsa.SECP384R1JWACurve,
			X:   "=///",
			Y:   "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg",
		},
		{
			KTY: "EC",
			CRV: ecdsa.SECP384R1JWACurve,
			X:   "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
			Y:   "=///",
		},
	}

	for _, vec := range vectors {
		pubKeyBytes, err := ecdsa.SECP384R1PublicKeyToBytes(vec)
		assert.Error(t, err)
		assert.Equal(t, nil, pubKeyBytes)
	}
}

func TestSECP384R1PublicKeyToBytes_NotOnCurve(t *testing.T) {
	// valid base64url but not a valid P-384 point
	xHex := "aa372568b1f7828da43e3b3b23a7f66cf9b2775b69388ab3ed55b1cc68a4e69c6cf71a4b3ebfcc76e7b20a06a35b27f0"
	yHex := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"

	xBytes, _ := hex.DecodeString(xHex)
	yBytes, _ := hex.DecodeString(yHex)

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	if elliptic.P384().IsOnCurve(x, y) {
		t.Skip("test point happens to be on the curve, skipping")
	}

	key := jwk.JWK{
		KTY: "EC",
		CRV: ecdsa.SECP384R1JWACurve,
		X:   "qjclaLH3go2kPjsyOn9mz5snd1tpOIqz7VWxzGik5pxs9xpLPr_8x257IKBqNbJ_A",
		Y:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8",
	}

	_, err := ecdsa.SECP384R1PublicKeyToBytes(key)
	assert.Error(t, err)
}
