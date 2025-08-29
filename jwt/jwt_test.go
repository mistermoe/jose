package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mistermoe/jose/dsa/eddsa"
	"github.com/mistermoe/jose/jwk"
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

func TestVerify_RS256(t *testing.T) {
	publicJwkJson := `{ "kty": "RSA", "use": "sig", "kid": "1499c154ccc8a25e24d8de8b1a9f845aefb6f3ca", "e": "AQAB", "n": "tH5pdWojgagY73Hy2WtH8vhoKpGAmP01E1CSuZn-02U_hTjFzAoDAiT6d7CcP14VHg4AGRWY82NCw5HL9vapXilR0Y1g3lFWwRCU1oXjApzhkTt3RVbM-jPWr5aEC_QN6yTE9qK1lwz1_x03rPMOuSP7BcDQCNazPLPwIDxMtzT47asH25OrtiN-nFA_imMAMrqKEBhmYtutGqKqhs6vI_PsNHxLFyR26Z-CgGrQ21Eensu0jl29vl0uYBfVUG4XpzOp7A5_rwVPaHx5ZibUSVG-eVu0RYObSKJTXQg8NKs3bEUHk9Z563PgTA9mf5VsvenNm6DxCJrvztxKvhg1Nw", "alg": "RS256" }`

	var publicJwk jwk.JWK
	err := json.Unmarshal([]byte(publicJwkJson), &publicJwk)
	assert.NoError(t, err)

	vector := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE0OTljMTU0Y2NjOGEyNWUyNGQ4ZGU4YjFhOWY4NDVhZWZiNmYzY2EiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI2ODU2MTk4NDMzNS1pNThtaGkwN2ExcWV2Zm0xaWlzNmFyZnNqcTRzZTZlYi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjY4NTYxOTg0MzM1LWk1OG1oaTA3YTFxZXZmbTFpaXM2YXJmc2pxNHNlNmViLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE0MjcwOTA5NDUwMDE2NDg2Mzc4IiwiaGQiOiJteXBvY2tldC5tb25leSIsImVtYWlsIjoibW9lQG15cG9ja2V0Lm1vbmV5IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5iZiI6MTc1NjQzNjM2NCwibmFtZSI6Ik1vZSBKYW5nZGEiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSUlNOThqZ0JlX190OWFnT1FXWVNxOC1aOU0yZWZnNHJGNnR5TnpoZEY5b1pRSXE0LV89czk2LWMiLCJnaXZlbl9uYW1lIjoiTW9lIiwiZmFtaWx5X25hbWUiOiJKYW5nZGEiLCJpYXQiOjE3NTY0MzY2NjQsImV4cCI6MTc1NjQ0MDI2NCwianRpIjoiNjc1YmUwNDk1OWRiZTJhYTVkZWUzODRhY2ExNzYwMWQ4ZjkyZGRhMSJ9.WrhuDa-8O6ZSYHR476k2ZTtsI0mKsjPzTGluwHR5RkxXpLRYRyxjXUQCDpPa3lhGe4QBJtCBs5iTLxny5hzHphJrTzW43CvNgfv9AquF0IY4NpSmbzpMrg3roa-090pDPyLlKKHzWbunS8XWutODSO8msiRwOVdd__oXZWW9DmEbTnIbaYz43twOF3tX0sdrPvhMYNloHAvwE8c-wlHSfhoTiU54KScrcfHrmEFKJN_Xib8PAEikOJQTVT3aMaeCAr93Y5f6ntuJ58npcuhgm1iBTgc-i3Pg2NAdAmJegs6LT981U1_S4tTjbLQc9OL6M8MCjVySpbux43TmqTM12w"

	decoded, err := jwt.Verify(vector, publicJwk)
	assert.NoError(t, err)
	assert.NotZero(t, decoded)
}
