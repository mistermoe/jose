package jwe_test

import (
	"encoding/base64"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/mistermoe/jose/jwe"
)

// test vectors taken from RFC 7516 Appendix A.1. That example uses `RSA-OAEP` key management, but
// the content encryption step is `A256GCM` and its inputs and outputs are published in full.
// https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1
const (
	rfc7516A1EncodedHeader = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
	rfc7516A1Plaintext     = "The true sign of intelligence is not knowledge but imagination."
	rfc7516A1IV            = "48V1_ALb6US04U3b"
	rfc7516A1Ciphertext    = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A"
	rfc7516A1Tag           = "XFBoMYUZodetZdvTiFvSkQ"
)

// rfc7516A1CEK is the content encryption key from RFC 7516 Appendix A.1.2.
var rfc7516A1CEK = []byte{
	177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
	212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
	234, 64, 252,
}

func TestA256GCMSeal_RFC7516Vector(t *testing.T) {
	iv, err := base64.RawURLEncoding.DecodeString(rfc7516A1IV)
	assert.NoError(t, err)

	ciphertext, tag, err := jwe.A256GCMSeal(
		rfc7516A1CEK,
		iv,
		[]byte(rfc7516A1Plaintext),
		[]byte(rfc7516A1EncodedHeader),
	)
	assert.NoError(t, err)

	assert.Equal(t, rfc7516A1Ciphertext, base64.RawURLEncoding.EncodeToString(ciphertext))
	assert.Equal(t, rfc7516A1Tag, base64.RawURLEncoding.EncodeToString(tag))
}

func TestA256GCMOpen_RFC7516Vector(t *testing.T) {
	iv, err := base64.RawURLEncoding.DecodeString(rfc7516A1IV)
	assert.NoError(t, err)

	ciphertext, err := base64.RawURLEncoding.DecodeString(rfc7516A1Ciphertext)
	assert.NoError(t, err)

	tag, err := base64.RawURLEncoding.DecodeString(rfc7516A1Tag)
	assert.NoError(t, err)

	plaintext, err := jwe.A256GCMOpen(rfc7516A1CEK, iv, ciphertext, tag, []byte(rfc7516A1EncodedHeader))
	assert.NoError(t, err)
	assert.Equal(t, rfc7516A1Plaintext, string(plaintext))
}

func TestA256GCMOpen_WrongAAD(t *testing.T) {
	iv, err := base64.RawURLEncoding.DecodeString(rfc7516A1IV)
	assert.NoError(t, err)

	ciphertext, err := base64.RawURLEncoding.DecodeString(rfc7516A1Ciphertext)
	assert.NoError(t, err)

	tag, err := base64.RawURLEncoding.DecodeString(rfc7516A1Tag)
	assert.NoError(t, err)

	plaintext, err := jwe.A256GCMOpen(rfc7516A1CEK, iv, ciphertext, tag, []byte("nope"))
	assert.Error(t, err)
	assert.Equal(t, nil, plaintext)
}

func TestA256GCMGenerateKey(t *testing.T) {
	key, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)
	assert.Equal(t, "oct", key.KTY)
	assert.Equal(t, jwe.A256GCMJWA, key.ALG)

	k, err := base64.RawURLEncoding.DecodeString(key.K)
	assert.NoError(t, err)
	assert.Equal(t, jwe.A256GCMKeySize, len(k))

	other, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)
	assert.NotEqual(t, key.K, other.K)
}

func TestA256GCMGenerateIV(t *testing.T) {
	iv, err := jwe.A256GCMGenerateIV()
	assert.NoError(t, err)
	assert.Equal(t, jwe.A256GCMIVSize, len(iv))

	other, err := jwe.A256GCMGenerateIV()
	assert.NoError(t, err)
	assert.NotEqual(t, iv, other)
}

func TestA256GCMSeal_BadKeyOrIV(t *testing.T) {
	iv, err := base64.RawURLEncoding.DecodeString(rfc7516A1IV)
	assert.NoError(t, err)

	_, _, err = jwe.A256GCMSeal(rfc7516A1CEK[:16], iv, []byte("hello"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "content encryption key must be 32 bytes")

	_, _, err = jwe.A256GCMSeal(rfc7516A1CEK, iv[:8], []byte("hello"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initialization vector must be 12 bytes")
}

func TestA256GCMOpen_BadTagSize(t *testing.T) {
	iv, err := base64.RawURLEncoding.DecodeString(rfc7516A1IV)
	assert.NoError(t, err)

	_, err = jwe.A256GCMOpen(rfc7516A1CEK, iv, []byte("ciphertext"), []byte("short"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication tag must be 16 bytes")
}
