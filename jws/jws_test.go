package jws_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mistermoe/jose/dsa/eddsa"
	"github.com/mistermoe/jose/jws"

	"github.com/alecthomas/assert/v2"
)

func TestDecode(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)

	payload := []byte("hi")

	compactJWS, err := jws.Sign(payload, privJwk)
	assert.NoError(t, err)

	decoded, err := jws.Decode(compactJWS)
	assert.NoError(t, err)

	assert.Equal(t, payload, decoded.Payload)
}

func TestDecode_HeaderIsNotBase64Url(t *testing.T) {
	compactJWS := "lol." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	decoded, err := jws.Decode(compactJWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to decode header")
	assert.Equal(t, jws.Decoded{}, decoded)
}

func TestDecode_PayloadIsNotBase64Url(t *testing.T) {
	compactJWS := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"{woohoo}." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	decoded, err := jws.Decode(compactJWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to decode payload")
	assert.Equal(t, jws.Decoded{}, decoded)
}

func TestDecode_SignatureIsNotBase64Url(t *testing.T) {
	compactJWS := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"{woot}"

	decoded, err := jws.Decode(compactJWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to decode signature")
	assert.Equal(t, jws.Decoded{}, decoded)
}

func TestDecode_Bad(t *testing.T) {
	badHeader := base64.RawURLEncoding.EncodeToString([]byte("hehe"))
	vectors := []string{
		"",
		"..",
		"a.b.c",
		fmt.Sprintf("%s.%s.%s", badHeader, badHeader, badHeader),
	}

	for _, vector := range vectors {
		decoded, err := jws.Decode(vector)

		assert.Error(t, err, "expected verification error. vector: %s", vector)
		assert.Equal(t, jws.Decoded{}, decoded, "expected empty DecodedJWS")
	}
}

func TestSign(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)

	payload := map[string]any{"hello": "world"}
	payloadBytes, err := json.Marshal(payload)
	assert.NoError(t, err)

	compactJWS, err := jws.Sign(payloadBytes, privJwk)
	assert.NoError(t, err)

	assert.True(t, compactJWS != "", "expected signature to be non-empty")

	parts := strings.Split(compactJWS, ".")
	assert.Equal(t, 3, len(parts), "expected 3 parts in compact JWS")

	header, err := jws.DecodeHeader(parts[0])
	assert.NoError(t, err)

	assert.NotZero(t, header.ALG, "expected alg to be set in jws header")
}

func TestSign_Detached(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)

	payload := map[string]any{"hello": "world"}
	payloadBytes, err := json.Marshal(payload)
	assert.NoError(t, err)

	compactJWS, err := jws.Sign(payloadBytes, privJwk, jws.DetachedPayload(true))
	assert.NoError(t, err)

	assert.True(t, compactJWS != "", "expected signature to be non-empty")

	parts := strings.Split(compactJWS, ".")
	assert.Equal(t, 3, len(parts), "expected 3 parts in compact JWS")
	assert.Equal(t, parts[1], "", "expected empty payload")
}

func TestSign_CustomType(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)

	payload := map[string]any{"hello": "world"}
	payloadBytes, err := json.Marshal(payload)
	assert.NoError(t, err)

	customType := "openid4vci-proof+jwt"

	compactJWS, err := jws.Sign(payloadBytes, privJwk, jws.Type(customType))
	assert.NoError(t, err)

	parts := strings.Split(compactJWS, ".")
	encodedHeader := parts[0]
	header, err := jws.DecodeHeader(encodedHeader)
	assert.NoError(t, err)

	assert.Equal(t, customType, header.TYP)
}

func TestDecoded_Verify(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	assert.NoError(t, err)

	payload := map[string]any{"hello": "world"}
	payloadBytes, err := json.Marshal(payload)
	assert.NoError(t, err)

	compactJWS, err := jws.Sign(payloadBytes, privJwk)
	assert.NoError(t, err)

	decoded, err := jws.Decode(compactJWS)
	assert.NoError(t, err)
	assert.NotEqual(t, jws.Decoded{}, decoded, "expected decoded to not be empty")
}

func TestDecoded_Verify_Bad(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	pubJwk := eddsa.GetPublicKey(privJwk)
	assert.NoError(t, err)

	header, err := jws.Header{
		ALG: "ES256K",
	}.Encode()
	assert.NoError(t, err)

	payloadJSON := map[string]any{"hello": "world"}
	payloadBytes, _ := json.Marshal(payloadJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	compactJWS := fmt.Sprintf("%s.%s.%s", header, payload, payload)

	_, err = jws.Verify(compactJWS, pubJwk)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestVerify(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	pubJwk := eddsa.GetPublicKey(privJwk)
	assert.NoError(t, err)

	payload := map[string]any{"hello": "world"}
	payloadBytes, err := json.Marshal(payload)
	assert.NoError(t, err)

	compactJWS, err := jws.Sign(payloadBytes, privJwk)
	assert.NoError(t, err)

	_, err = jws.Verify(compactJWS, pubJwk)
	assert.NoError(t, err)
}

func TestVerify_Detached(t *testing.T) {
	privJwk, err := eddsa.ED25519GeneratePrivateKey()
	pubJwk := eddsa.GetPublicKey(privJwk)
	assert.NoError(t, err)

	payload := []byte("hi")

	compactJWS, err := jws.Sign(payload, privJwk, jws.DetachedPayload(true))
	assert.NoError(t, err)

	decoded, err := jws.Verify(compactJWS, pubJwk, jws.Payload(payload))
	assert.NoError(t, err)

	assert.Equal(t, payload, decoded.Payload)
}
