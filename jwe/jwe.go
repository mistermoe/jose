// Package jwe implements a subset of the JSON Web Encryption spec (https://datatracker.ietf.org/doc/html/rfc7516)
package jwe

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mistermoe/jose/jwk"
)

const (
	// NumCompactParts is the number of parts in a compact JWE.
	NumCompactParts = 5

	// AlgorithmDirect is the `dir` key management algorithm, wherein the shared symmetric key is
	// used directly as the content encryption key.
	//
	// [Specification]: https://datatracker.ietf.org/doc/html/rfc7518#section-4.5
	AlgorithmDirect = "dir"
)

// Decode decodes the given JWE string into a [Decoded] type.
//
// # Note
//
// The given JWE input is assumed to be a [compact JWE]. The payload is not decrypted. Use
// [Decrypt] or [Decoded.Decrypt] to decrypt the payload.
//
// [compact JWE]: https://datatracker.ietf.org/doc/html/rfc7516#section-7.1
func Decode(compactJWE string) (Decoded, error) {
	parts := strings.Split(compactJWE, ".")
	if len(parts) != NumCompactParts {
		return Decoded{}, fmt.Errorf("malformed JWE. Expected 5 parts, got %d", len(parts))
	}

	header, err := DecodeHeader(parts[0])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWE. Failed to decode header: %w", err)
	}

	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWE. Failed to decode encrypted key: %w", err)
	}

	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWE. Failed to decode initialization vector: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWE. Failed to decode ciphertext: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWE. Failed to decode authentication tag: %w", err)
	}

	return Decoded{
		Header:       header,
		EncryptedKey: encryptedKey,
		IV:           iv,
		Ciphertext:   ciphertext,
		Tag:          tag,
		Parts:        parts,
	}, nil
}

// DecodeHeader decodes the base64url encoded JWE header into a [Header].
func DecodeHeader(base64UrlEncodedHeader string) (Header, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(base64UrlEncodedHeader)
	if err != nil {
		return Header{}, err
	}

	var header Header
	err = json.Unmarshal(bytes, &header)
	if err != nil {
		return Header{}, err
	}

	return header, nil
}

// options that encrypt function can take.
type encryptOpts struct {
	typ string
	cty string
}

// EncryptOpt is a type that represents an option that can be passed to
// [github.com/mistermoe/jose/jwe.Encrypt].
type EncryptOpt func(opts *encryptOpts)

// Type is used to set the `typ` JWE header value.
func Type(typ string) EncryptOpt {
	return func(opts *encryptOpts) {
		opts.typ = typ
	}
}

// ContentType is used to set the `cty` JWE header value. It declares the media type of the
// encrypted payload.
//
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12
func ContentType(cty string) EncryptOpt {
	return func(opts *encryptOpts) {
		opts.cty = cty
	}
}

// Encrypt encrypts the payload provided with the jwk provided and returns a compact JWE.
//
// # Note
//
// The provided jwk is used directly as the content encryption key, i.e. the `dir` key management
// algorithm. It must be an `oct` key holding 32 bytes of key material.
func Encrypt(payload []byte, key jwk.JWK, opts ...EncryptOpt) (string, error) {
	o := encryptOpts{}
	for _, opt := range opts {
		opt(&o)
	}

	cek, err := a256gcmKeyFromJwk(key)
	if err != nil {
		return "", fmt.Errorf("invalid content encryption key: %w", err)
	}

	kid, err := key.ComputeThumbprint()
	if err != nil {
		return "", fmt.Errorf("failed to compute jwk thumbprint: %w", err)
	}

	header := Header{ALG: AlgorithmDirect, ENC: A256GCMJWA, KID: kid, TYP: o.typ, CTY: o.cty}

	base64UrlEncodedHeader, err := header.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to base64 url encode header: %w", err)
	}

	iv, err := A256GCMGenerateIV()
	if err != nil {
		return "", err
	}

	// the additional authenticated data is the ASCII bytes of the base64url encoded header.
	ciphertext, tag, err := A256GCMSeal(cek, iv, payload, []byte(base64UrlEncodedHeader))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt payload: %w", err)
	}

	compactJWE := base64UrlEncodedHeader + "." +
		"" + "." +
		base64.RawURLEncoding.EncodeToString(iv) + "." +
		base64.RawURLEncoding.EncodeToString(ciphertext) + "." +
		base64.RawURLEncoding.EncodeToString(tag)

	return compactJWE, nil
}

// Decrypt decrypts the provided compactJWE using the jwk. The returned [Decoded] has its Payload
// populated with the decrypted plaintext.
func Decrypt(compactJWE string, key jwk.JWK) (Decoded, error) {
	decodedJWE, err := Decode(compactJWE)
	if err != nil {
		return decodedJWE, fmt.Errorf("decryption failed: %w", err)
	}

	payload, err := decodedJWE.Decrypt(key)
	if err != nil {
		return decodedJWE, err
	}

	decodedJWE.Payload = payload

	return decodedJWE, nil
}

// Decoded is a compact JWE decoded into its parts.
type Decoded struct {
	Header       Header
	EncryptedKey []byte
	IV           []byte
	Ciphertext   []byte
	Tag          []byte
	// Payload is the decrypted plaintext. It is only populated by [Decrypt].
	Payload []byte
	Parts   []string
}

// Decrypt decrypts the JWE using the provided jwk and returns the plaintext payload.
func (jwe Decoded) Decrypt(key jwk.JWK) ([]byte, error) {
	if jwe.Header.ALG != AlgorithmDirect {
		return nil, fmt.Errorf("unsupported algorithm: %s", jwe.Header.ALG)
	}

	if jwe.Header.ENC != A256GCMJWA {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", jwe.Header.ENC)
	}

	if len(jwe.EncryptedKey) != 0 {
		return nil, errors.New("encrypted key must be empty when alg is dir")
	}

	cek, err := a256gcmKeyFromJwk(key)
	if err != nil {
		return nil, fmt.Errorf("invalid content encryption key: %w", err)
	}

	// the additional authenticated data is the ASCII bytes of the base64url encoded header
	// exactly as they appeared on the wire.
	payload, err := A256GCMOpen(cek, jwe.IV, jwe.Ciphertext, jwe.Tag, []byte(jwe.Parts[0]))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	return payload, nil
}

// Header represents a JWE (JSON Web Encryption) header. See [Specification] for more details.
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7516#section-4
type Header struct {
	// Identifies the cryptographic algorithm used to encrypt or determine the value of the content
	// encryption key. This Header Parameter MUST be present and MUST be understood and processed by
	// implementations.
	//
	// [Specification]: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
	ALG string `json:"alg,omitempty"`
	// Identifies the content encryption algorithm used to perform authenticated encryption on the
	// plaintext to produce the ciphertext and the Authentication Tag. This algorithm MUST be an AEAD
	// algorithm with a specified key length. This Header Parameter MUST be present and MUST be
	// understood and processed by implementations.
	//
	// [Specification]: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
	ENC string `json:"enc,omitempty"`
	// Key ID Header Parameter https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6
	KID string `json:"kid,omitempty"`
	// Type Header Parameter https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.11
	TYP string `json:"typ,omitempty"`
	// Content Type Header Parameter https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12
	CTY string `json:"cty,omitempty"`
}

// Encode returns the base64url encoded header.
func (j Header) Encode() (string, error) {
	bytes, err := json.Marshal(j)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
