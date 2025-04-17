package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mistermoe/jose/dsa/eddsa"
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
