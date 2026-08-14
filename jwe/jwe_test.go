package jwe_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/mistermoe/jose/jwe"
	"github.com/mistermoe/jose/jwk"
)

func TestEncrypt(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), key)
	assert.NoError(t, err)

	parts := strings.Split(compactJWE, ".")
	assert.Equal(t, jwe.NumCompactParts, len(parts))
	assert.Equal(t, "", parts[1], "encrypted key segment must be empty for dir")

	header, err := jwe.DecodeHeader(parts[0])
	assert.NoError(t, err)
	assert.Equal(t, jwe.AlgorithmDirect, header.ALG)
	assert.Equal(t, jwe.A256GCMJWA, header.ENC)

	thumbprint, err := key.ComputeThumbprint()
	assert.NoError(t, err)
	assert.Equal(t, thumbprint, header.KID)
}

func TestEncrypt_Options(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello"), key, jwe.Type("JWT"), jwe.ContentType("JSON"))
	assert.NoError(t, err)

	decoded, err := jwe.Decode(compactJWE)
	assert.NoError(t, err)
	assert.Equal(t, "JWT", decoded.Header.TYP)
	assert.Equal(t, "JSON", decoded.Header.CTY)
}

func TestEncrypt_IsNotDeterministic(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	first, err := jwe.Encrypt([]byte("hello"), key)
	assert.NoError(t, err)

	second, err := jwe.Encrypt([]byte("hello"), key)
	assert.NoError(t, err)

	assert.NotEqual(t, first, second, "a fresh iv must be used per encryption")
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	payloads := [][]byte{
		[]byte(""),
		[]byte("hello world"),
		[]byte("👋 unicode ✨ payload"),
		[]byte(strings.Repeat("a", 100000)),
	}

	for _, payload := range payloads {
		compactJWE, encryptErr := jwe.Encrypt(payload, key)
		assert.NoError(t, encryptErr)

		decrypted, decryptErr := jwe.Decrypt(compactJWE, key)
		assert.NoError(t, decryptErr)
		assert.Equal(t, string(payload), string(decrypted.Payload))
	}
}

func TestDecrypt_DecodeFirst(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), key)
	assert.NoError(t, err)

	decoded, err := jwe.Decode(compactJWE)
	assert.NoError(t, err)
	assert.Equal(t, nil, decoded.Payload, "Decode must not decrypt")

	thumbprint, err := key.ComputeThumbprint()
	assert.NoError(t, err)
	assert.Equal(t, thumbprint, decoded.Header.KID, "kid enables resolving the key after decoding")

	payload, err := decoded.Decrypt(key)
	assert.NoError(t, err)
	assert.Equal(t, "hello world", string(payload))
}

func TestDecrypt_WrongKey(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	otherKey, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), key)
	assert.NoError(t, err)

	_, err = jwe.Decrypt(compactJWE, otherKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt payload")
}

func TestDecrypt_Tampered(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), key)
	assert.NoError(t, err)

	// every segment is covered by the authentication tag, either as the aad (the header) or as
	// the sealed data itself.
	for i := range jwe.NumCompactParts {
		if i == 1 {
			continue // the encrypted key segment is empty for dir and checked separately.
		}

		parts := strings.Split(compactJWE, ".")
		parts[i] = tamper(t, parts[i])

		_, err = jwe.Decrypt(strings.Join(parts, "."), key)
		assert.Error(t, err, "expected decryption to fail. tampered part: %d", i)
	}
}

func TestDecrypt_TamperedHeader(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), key)
	assert.NoError(t, err)

	parts := strings.Split(compactJWE, ".")

	// re-encode a semantically identical header. the aad is the encoded header bytes exactly as
	// they appeared on the wire, so even a benign re-encoding must fail authentication.
	header, err := jwe.DecodeHeader(parts[0])
	assert.NoError(t, err)

	header.TYP = "JWT"
	parts[0], err = header.Encode()
	assert.NoError(t, err)

	_, err = jwe.Decrypt(strings.Join(parts, "."), key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt payload")
}

func TestDecrypt_NonEmptyEncryptedKey(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), key)
	assert.NoError(t, err)

	parts := strings.Split(compactJWE, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte("not empty"))

	_, err = jwe.Decrypt(strings.Join(parts, "."), key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted key must be empty when alg is dir")
}

func TestDecrypt_UnsupportedAlgorithms(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	vectors := []jwe.Header{
		{ALG: "A128KW", ENC: jwe.A256GCMJWA},
		{ALG: "", ENC: jwe.A256GCMJWA},
		{ALG: jwe.AlgorithmDirect, ENC: "A128GCM"},
		{ALG: jwe.AlgorithmDirect, ENC: ""},
	}

	for _, header := range vectors {
		encodedHeader, encodeErr := header.Encode()
		assert.NoError(t, encodeErr)

		compactJWE := encodedHeader + "..aXZpdml2aXZpdml2.Y2lwaGVy.dGFndGFndGFndGFndGFndA"

		_, err = jwe.Decrypt(compactJWE, key)
		assert.Error(t, err, "expected decryption to fail. alg: %s, enc: %s", header.ALG, header.ENC)
		assert.Contains(t, err.Error(), "unsupported")
	}
}

func TestDecrypt_BadIVAndTagSizes(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	header := jwe.Header{ALG: jwe.AlgorithmDirect, ENC: jwe.A256GCMJWA}

	encodedHeader, err := header.Encode()
	assert.NoError(t, err)

	shortIV := encodedHeader + "..aXY.Y2lwaGVy.dGFndGFndGFndGFndGFndA"

	_, err = jwe.Decrypt(shortIV, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initialization vector must be 12 bytes")

	shortTag := encodedHeader + "..aXZpdml2aXZpdml2.Y2lwaGVy.dGFn"

	_, err = jwe.Decrypt(shortTag, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication tag must be 16 bytes")
}

func TestDecode_WrongNumberOfParts(t *testing.T) {
	vectors := []string{
		"",
		"a.b.c",
		"a.b.c.d",
		"a.b.c.d.e.f",
	}

	for _, vector := range vectors {
		decoded, err := jwe.Decode(vector)
		assert.Error(t, err, "expected decode to fail. vector: %s", vector)
		assert.Contains(t, err.Error(), "malformed JWE. Expected 5 parts")
		assert.Equal(t, jwe.Decoded{}, decoded)
	}
}

func TestDecode_SegmentIsNotBase64Url(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), key)
	assert.NoError(t, err)

	messages := []string{
		"Failed to decode header",
		"Failed to decode encrypted key",
		"Failed to decode initialization vector",
		"Failed to decode ciphertext",
		"Failed to decode authentication tag",
	}

	for i, message := range messages {
		parts := strings.Split(compactJWE, ".")
		parts[i] = "!!!not base64url!!!"

		_, err = jwe.Decode(strings.Join(parts, "."))
		assert.Error(t, err, "expected decode to fail. part: %d", i)
		assert.Contains(t, err.Error(), message)
	}
}

func TestDecode_HeaderIsNotJSON(t *testing.T) {
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte("not json"))

	_, err := jwe.Decode(encodedHeader + "..aXZpdml2aXZpdml2.Y2lwaGVy.dGFndGFndGFndGFndGFndA")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed JWE. Failed to decode header")
}

func TestEncryptDecrypt_BadKeys(t *testing.T) {
	valid, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	compactJWE, err := jwe.Encrypt([]byte("hello world"), valid)
	assert.NoError(t, err)

	vectors := []jwk.JWK{
		{},
		{KTY: "EC", CRV: "secp256k1", X: "abc", Y: "def"},
		{KTY: "oct", ALG: jwe.A256GCMJWA},
		{KTY: "oct", ALG: jwe.A256GCMJWA, K: "!!!not base64url!!!"},
		{KTY: "oct", ALG: jwe.A256GCMJWA, K: base64.RawURLEncoding.EncodeToString(make([]byte, 16))},
		{KTY: "oct", ALG: "A128GCM", K: valid.K},
	}

	for _, vector := range vectors {
		_, err = jwe.Encrypt([]byte("hello world"), vector)
		assert.Error(t, err, "expected encryption to fail. vector: %+v", vector)
		assert.Contains(t, err.Error(), "invalid content encryption key")

		_, err = jwe.Decrypt(compactJWE, vector)
		assert.Error(t, err, "expected decryption to fail. vector: %+v", vector)
		assert.Contains(t, err.Error(), "invalid content encryption key")
	}
}

// tamper flips a bit in the decoded bytes of a base64url encoded compact JWE segment.
func tamper(t *testing.T, segment string) string {
	t.Helper()

	bytes, err := base64.RawURLEncoding.DecodeString(segment)
	assert.NoError(t, err)

	if len(bytes) == 0 {
		bytes = []byte{0}
	}

	bytes[0] ^= 0xff

	return base64.RawURLEncoding.EncodeToString(bytes)
}
