package jwt_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mistermoe/jose/dsa/eddsa"
	"github.com/mistermoe/jose/jwe"
	"github.com/mistermoe/jose/jws"
	"github.com/mistermoe/jose/jwt"

	"github.com/alecthomas/assert/v2"
)

func TestClaims_MarshalJSON(t *testing.T) {
	claims := jwt.Claims{
		Issuer: "issuer",
		Misc:   map[string]interface{}{"foo": "bar"},
	}

	b, err := json.Marshal(&claims)
	assert.NoError(t, err)

	obj := make(map[string]interface{})
	err = json.Unmarshal(b, &obj)
	assert.NoError(t, err)

	assert.Equal(t, "issuer", obj["iss"])
	assert.False(t, obj["foo"] == nil)
}

func TestClaims_UnmarshalJSON(t *testing.T) {
	claims := jwt.Claims{
		Issuer: "issuer",
		Misc:   map[string]interface{}{"foo": "bar"},
	}

	b, err := json.Marshal(&claims)
	assert.NoError(t, err)

	claimsAgane := jwt.Claims{}
	err = json.Unmarshal(b, &claimsAgane)
	assert.NoError(t, err)

	assert.Equal(t, claims.Issuer, claimsAgane.Issuer)
	assert.False(t, claimsAgane.Misc["foo"] == nil)
	assert.Equal(t, claimsAgane.Misc["foo"], claims.Misc["foo"])
}

func TestSign(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)

	claims := jwt.Claims{
		Issuer: "https://api.pocketmoney.host",
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	jwt, err := jwt.Sign(claims, privJwk)
	assert.NoError(t, err)

	assert.False(t, jwt == "", "expected jwt to not be empty")
}

func TestVerify(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	pubJwk := eddsa.GetPublicKey(privJwk)
	assert.NoError(t, err)

	claims := jwt.Claims{
		Issuer: "https://api.pocketmoney.host",
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	signedJWT, err := jwt.Sign(claims, privJwk)
	assert.NoError(t, err)

	assert.False(t, signedJWT == "", "expected jwt to not be empty")

	decoded, err := jwt.Verify(signedJWT, pubJwk)
	assert.NoError(t, err)
	assert.NotEqual(t, decoded, jwt.Decoded{}, "expected decoded to not be empty")
}

func TestVerify_BadClaims(t *testing.T) {
	okHeader, err := jws.Header{ALG: "ES256K"}.Encode()
	assert.NoError(t, err)

	input := fmt.Sprintf("%s.%s.%s", okHeader, "hehe", "hehe")

	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)
	pubJwk := eddsa.GetPublicKey(privJwk)

	decoded, err := jwt.Verify(input, pubJwk)
	assert.Error(t, err)
	assert.Equal(t, jwt.Decoded{}, decoded)
}

func Test_Decode_Empty(t *testing.T) {
	decoded, err := jwt.Decode("")
	assert.Error(t, err)
	assert.Equal(t, jwt.Decoded{}, decoded)
}

func TestEncrypt(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	claims := jwt.Claims{
		Issuer: "https://api.pocketmoney.host",
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	encryptedJWT, err := jwt.Encrypt(claims, key)
	assert.NoError(t, err)
	assert.False(t, encryptedJWT == "", "expected jwt to not be empty")

	// the claims must not be readable without the key.
	assert.False(t, strings.Contains(encryptedJWT, "pocketmoney"))

	decoded, err := jwe.Decode(encryptedJWT)
	assert.NoError(t, err)
	assert.Equal(t, "JWT", decoded.Header.TYP)
}

func TestDecrypt(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	claims := jwt.Claims{
		Issuer:     "https://api.pocketmoney.host",
		Subject:    "subject",
		Audience:   "audience",
		JTI:        "jti",
		IssuedAt:   time.Now().Unix(),
		Expiration: time.Now().Add(time.Hour).Unix(),
		Misc:       map[string]interface{}{"c_nonce": "abcd123"},
	}

	encryptedJWT, err := jwt.Encrypt(claims, key)
	assert.NoError(t, err)

	decrypted, err := jwt.Decrypt(encryptedJWT, key)
	assert.NoError(t, err)

	assert.Equal(t, claims.Issuer, decrypted.Claims.Issuer)
	assert.Equal(t, claims.Subject, decrypted.Claims.Subject)
	assert.Equal(t, claims.Audience, decrypted.Claims.Audience)
	assert.Equal(t, claims.JTI, decrypted.Claims.JTI)
	assert.Equal(t, claims.IssuedAt, decrypted.Claims.IssuedAt)
	assert.Equal(t, claims.Expiration, decrypted.Claims.Expiration)
	assert.Equal(t, claims.Misc["c_nonce"], decrypted.Claims.Misc["c_nonce"])
}

func TestDecrypt_Expired(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	claims := jwt.Claims{
		Issuer:     "https://api.pocketmoney.host",
		Expiration: time.Now().Add(-time.Hour).Unix(),
	}

	encryptedJWT, err := jwt.Encrypt(claims, key)
	assert.NoError(t, err)

	decrypted, err := jwt.Decrypt(encryptedJWT, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT has expired")
	assert.Equal(t, jwt.Decrypted{}, decrypted)
}

func TestDecrypt_WrongKey(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	otherKey, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	encryptedJWT, err := jwt.Encrypt(jwt.Claims{Issuer: "issuer"}, key)
	assert.NoError(t, err)

	decrypted, err := jwt.Decrypt(encryptedJWT, otherKey)
	assert.Error(t, err)
	assert.Equal(t, jwt.Decrypted{}, decrypted)
}

func TestDecrypt_NotAJWE(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)

	signedJWT, err := jwt.Sign(jwt.Claims{Issuer: "issuer"}, privJwk)
	assert.NoError(t, err)

	vectors := []string{"", signedJWT}

	for _, vector := range vectors {
		decrypted, decryptErr := jwt.Decrypt(vector, key)
		assert.Error(t, decryptErr, "expected decryption to fail. vector: %s", vector)
		assert.Equal(t, jwt.Decrypted{}, decrypted)
	}
}

func TestDecrypt_PayloadIsNotJSON(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	encryptedJWE, err := jwe.Encrypt([]byte("not json"), key)
	assert.NoError(t, err)

	decrypted, err := jwt.Decrypt(encryptedJWE, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed encrypted JWT. Failed to unmarshal claims")
	assert.Equal(t, jwt.Decrypted{}, decrypted)
}
