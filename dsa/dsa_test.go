package dsa_test

import (
	_ecdsa "crypto/ecdsa"
	_ed25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_rsa "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/mistermoe/jose/dsa"
	"github.com/mistermoe/jose/dsa/ecdsa"
	"github.com/mistermoe/jose/dsa/eddsa"
	"github.com/mistermoe/jose/dsa/rsa"
	"github.com/mistermoe/jose/jwk"

	"github.com/alecthomas/assert/v2"
)

func TestGeneratePrivateKeySECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP256K1)

	assert.NoError(t, err)
	assert.Equal[string](t, ecdsa.SECP256K1JWACurve, privateJwk.CRV)
	assert.Equal[string](t, ecdsa.KeyType, privateJwk.KTY)
	assert.True(t, privateJwk.D != "", "privateJwk.D is empty")
	assert.True(t, privateJwk.X != "", "privateJwk.X is empty")
	assert.True(t, privateJwk.Y != "", "privateJwk.Y is empty")
}

func TestGeneratePrivateKeyED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDED25519)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	assert.NoError(t, err)
	assert.Equal(t, eddsa.ED25519JWACurve, privateJwk.CRV)
	assert.Equal(t, eddsa.KeyType, privateJwk.KTY)
	assert.True(t, privateJwk.D != "", "privateJwk.D is empty")
	assert.True(t, privateJwk.X != "", "privateJwk.X is empty")
}

func TestGeneratePrivateKeySECP384R1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP384R1)

	assert.NoError(t, err)
	assert.Equal[string](t, ecdsa.SECP384R1JWACurve, privateJwk.CRV)
	assert.Equal[string](t, ecdsa.KeyType, privateJwk.KTY)
	assert.True(t, privateJwk.D != "", "privateJwk.D is empty")
	assert.True(t, privateJwk.X != "", "privateJwk.X is empty")
	assert.True(t, privateJwk.Y != "", "privateJwk.Y is empty")
}

func TestSignSECP384R1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP384R1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)
	assert.True(t, len(signature) == 96, "invalid signature length")
}

func TestVerifySECP384R1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP384R1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	assert.NoError(t, err)

	assert.True(t, legit, "failed to verify signature")
}

func TestGetJWASECP384R1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP384R1)
	assert.NoError(t, err)

	jwa, err := dsa.GetJWA(privateJwk)
	assert.NoError(t, err)
	assert.Equal(t, ecdsa.SECP384R1JWA, jwa)
}

func TestSignSECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP256K1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)
	assert.True(t, len(signature) == 64, "invalid signature length")
}

func TestSignED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDED25519)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)
	assert.True(t, len(signature) == 64, "invalid signature length")
}

func TestSignDeterministicSECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP256K1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature1, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err, "failed to sign")

	signature2, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	assert.Equal(t, signature1, signature2, "signature is not deterministic")
}

func TestSignDeterministicED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDED25519)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature1, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err, "failed to sign")

	signature2, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	assert.Equal(t, signature1, signature2, "signature is not deterministic")
}

func TestVerifySECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP256K1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	assert.NoError(t, err)

	assert.True(t, legit, "failed to verify signature")
}

func TestVerifyED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDED25519)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	assert.NoError(t, err)

	assert.True(t, legit, "failed to verify signature")
}

func TestBytesToPublicKey_BadAlgorithm(t *testing.T) {
	_, err := dsa.BytesToPublicKey("yolocrypto", []byte{0x00, 0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestBytesToPublicKey_BadBytes(t *testing.T) {
	_, err := dsa.BytesToPublicKey(dsa.AlgorithmIDSECP256K1, []byte{0x00, 0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestBytesToPublicKey_SECP256K1(t *testing.T) {
	// vector taken from https://github.com/decentralized-identity/web5-js/blob/dids-new-crypto/packages/crypto/tests/fixtures/test-vectors/secp256k1/bytes-to-public-key.json
	publicKeyHex := "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	assert.NoError(t, err)

	jwk, err := dsa.BytesToPublicKey(dsa.AlgorithmIDSECP256K1, pubKeyBytes)
	assert.NoError(t, err)

	assert.Equal(t, ecdsa.SECP256K1JWACurve, jwk.CRV)
	assert.Equal(t, ecdsa.KeyType, jwk.KTY)
	assert.Equal(t, "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g", jwk.X)
	assert.Equal(t, "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg", jwk.Y)
}

func TestPublicKeyToBytes_UnsupportedKTY(t *testing.T) {
	_, err := dsa.PublicKeyToBytes(jwk.JWK{KTY: "yolocrypto"})
	assert.Error(t, err)
}

func TestGeneratePrivateKeyRS256(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDRS256)

	assert.NoError(t, err)
	assert.Equal(t, rsa.KeyType, privateJwk.KTY)
	assert.True(t, privateJwk.N != "", "privateJwk.N is empty")
	assert.True(t, privateJwk.E != "", "privateJwk.E is empty")
	assert.True(t, privateJwk.D != "", "privateJwk.D is empty")
}

func TestSignRS256(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDRS256)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)
	assert.True(t, len(signature) > 0, "signature is empty")
}

func TestVerifyRS256(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDRS256)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	assert.NoError(t, err)

	assert.True(t, legit, "failed to verify signature")
}

func TestGetJWARS256(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmIDRS256)
	assert.NoError(t, err)

	jwa, err := dsa.GetJWA(privateJwk)
	assert.NoError(t, err)
	assert.Equal(t, rsa.RS256JWA, jwa)
}

func TestVerifyWithProvidedJWTKeys(t *testing.T) {
	// Test with the provided JWT verification keys
	testKeys := []jwk.JWK{
		{
			KTY: "RSA",
			ALG: rsa.RS256JWA,
			N:   "tH5pdWojgagY73Hy2WtH8vhoKpGAmP01E1CSuZn-02U_hTjFzAoDAiT6d7CcP14VHg4AGRWY82NCw5HL9vapXilR0Y1g3lFWwRCU1oXjApzhkTt3RVbM-jPWr5aEC_QN6yTE9qK1lwz1_x03rPMOuSP7BcDQCNazPLPwIDxMtzT47asH25OrtiN-nFA_imMAMrqKEBhmYtutGqKqhs6vI_PsNHxLFyR26Z-CgGrQ21Eensu0jl29vl0uYBfVUG4XpzOp7A5_rwVPaHx5ZibUSVG-eVu0RYObSKJTXQg8NKs3bEUHk9Z563PgTA9mf5VsvenNm6DxCJrvztxKvhg1Nw",
			E:   "AQAB",
		},
		{
			KTY: "RSA",
			ALG: rsa.RS256JWA,
			N:   "v85Io5Rp7vwbSlkuAowWVcfUxZdPckijmLAZ3WEl3nTUTkz9YfmKJUiqdZMRuJxL50F3TRBKDxvfFbWX602sPTShoK6H2pdbQNrKsGV_KIlLLsIkcVnG-KNuY-ZnkZ9ppCH9yqjGw08imHlLsIngSK8VF03nCwUiv_VtZ27FltUttRxkoZGxCYX0-MRicIXPNKILml-xmknGNLsDCvAYqhbg3tZRKi1dZuHLhCb_YTov5YhprvVzm5OagvrvZuia_qilk-ctgqRJRPFGrVm75gkV4WdwxQQukCPqf5UfIopdOAB4wBdovddX3jjpjphq8-gKMPO-t_6siCt1xETSOQ",
			E:   "AQAB",
		},
	}

	for i, key := range testKeys {
		t.Run(fmt.Sprintf("Key%d", i+1), func(t *testing.T) {
			// Test that we can get the JWA for these keys
			jwa, err := dsa.GetJWA(key)
			assert.NoError(t, err)
			assert.Equal(t, rsa.RS256JWA, jwa)

			// Test that we can convert to bytes and back
			keyBytes, err := dsa.PublicKeyToBytes(key)
			assert.NoError(t, err)
			assert.True(t, len(keyBytes) > 0, "key bytes should not be empty")

			// Test algorithm ID
			algID, err := dsa.AlgorithmID(&key)
			assert.NoError(t, err)
			assert.Equal(t, rsa.RS256AlgorithmID, algID)
		})
	}
}

func marshalPrivateKeyToPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	assert.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func marshalPublicKeyToPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	assert.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestPrivateKeyFromPEM_SECP384R1(t *testing.T) {
	goKey, err := _ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	pemBytes := marshalPrivateKeyToPEM(t, goKey)
	result, err := dsa.PrivateKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, ecdsa.KeyType, result.KTY)
	assert.Equal(t, ecdsa.SECP384R1JWACurve, result.CRV)
	assert.True(t, result.D != "", "D should be set")
	assert.True(t, result.X != "", "X should be set")
	assert.True(t, result.Y != "", "Y should be set")

	dBytes, err := base64.RawURLEncoding.DecodeString(result.D)
	assert.NoError(t, err)

	goD := goKey.D.Bytes()
	// strip leading zero-padding that the JWK encoder adds
	for len(dBytes) > len(goD) && dBytes[0] == 0 {
		dBytes = dBytes[1:]
	}
	assert.Equal(t, goD, dBytes)
}

func TestPrivateKeyFromPEM_SECP384R1_SEC1(t *testing.T) {
	goKey, err := _ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	der, err := x509.MarshalECPrivateKey(goKey)
	assert.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	result, err := dsa.PrivateKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, ecdsa.KeyType, result.KTY)
	assert.Equal(t, ecdsa.SECP384R1JWACurve, result.CRV)
	assert.True(t, result.D != "", "D should be set")
}

func TestPrivateKeyFromPEM_Ed25519(t *testing.T) {
	goPub, goPriv, err := _ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pemBytes := marshalPrivateKeyToPEM(t, goPriv)
	result, err := dsa.PrivateKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, eddsa.KeyType, result.KTY)
	assert.Equal(t, eddsa.ED25519JWACurve, result.CRV)
	assert.True(t, result.D != "", "D should be set")
	assert.True(t, result.X != "", "X should be set")

	xBytes, err := base64.RawURLEncoding.DecodeString(result.X)
	assert.NoError(t, err)
	assert.Equal(t, []byte(goPub), xBytes)
}

func TestPrivateKeyFromPEM_RSA(t *testing.T) {
	goKey, err := _rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	pemBytes := marshalPrivateKeyToPEM(t, goKey)
	result, err := dsa.PrivateKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, rsa.KeyType, result.KTY)
	assert.True(t, result.N != "", "N should be set")
	assert.True(t, result.E != "", "E should be set")
	assert.True(t, result.D != "", "D should be set")
}

func TestPrivateKeyFromPEM_RSA_PKCS1(t *testing.T) {
	goKey, err := _rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(goKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	result, err := dsa.PrivateKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, rsa.KeyType, result.KTY)
	assert.True(t, result.D != "", "D should be set")
}

func TestPublicKeyFromPEM_SECP384R1(t *testing.T) {
	goKey, err := _ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	pemBytes := marshalPublicKeyToPEM(t, &goKey.PublicKey)
	result, err := dsa.PublicKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, ecdsa.KeyType, result.KTY)
	assert.Equal(t, ecdsa.SECP384R1JWACurve, result.CRV)
	assert.True(t, result.X != "", "X should be set")
	assert.True(t, result.Y != "", "Y should be set")
	assert.Equal(t, "", result.D)
}

func TestPublicKeyFromPEM_Ed25519(t *testing.T) {
	goPub, _, err := _ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pemBytes := marshalPublicKeyToPEM(t, goPub)
	result, err := dsa.PublicKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, eddsa.KeyType, result.KTY)
	assert.Equal(t, eddsa.ED25519JWACurve, result.CRV)
	assert.True(t, result.X != "", "X should be set")
	assert.Equal(t, "", result.D)
}

func TestPublicKeyFromPEM_RSA(t *testing.T) {
	goKey, err := _rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	pemBytes := marshalPublicKeyToPEM(t, &goKey.PublicKey)
	result, err := dsa.PublicKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	assert.Equal(t, rsa.KeyType, result.KTY)
	assert.True(t, result.N != "", "N should be set")
	assert.True(t, result.E != "", "E should be set")
	assert.Equal(t, "", result.D)
}

func TestPrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := dsa.PrivateKeyFromPEM([]byte("not a pem"))
	assert.Error(t, err)
}

func TestPublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := dsa.PublicKeyFromPEM([]byte("not a pem"))
	assert.Error(t, err)
}

func TestPrivateKeyFromPEM_UnsupportedCurve(t *testing.T) {
	goKey, err := _ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	pemBytes := marshalPrivateKeyToPEM(t, goKey)
	_, err = dsa.PrivateKeyFromPEM(pemBytes)
	assert.Error(t, err)
}

func TestPrivateKeyFromPEM_SignVerifyRoundTrip(t *testing.T) {
	goKey, err := _ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	pemBytes := marshalPrivateKeyToPEM(t, goKey)
	privateJwk, err := dsa.PrivateKeyFromPEM(pemBytes)
	assert.NoError(t, err)

	payload := []byte("round trip test")
	signature, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	publicJwk := dsa.GetPublicKey(privateJwk)
	legit, err := dsa.Verify(payload, signature, publicJwk)
	assert.NoError(t, err)
	assert.True(t, legit, "signature should verify after PEM round-trip")
}
