package jws

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mistermoe/jose/dsa"
	"github.com/mistermoe/jose/jwk"
)

const (
	NumCompactParts = 3
)

// Decode decodes the given JWS string into a [Decoded] type
//
// # Note
//
// The given JWS input is assumed to be a [compact JWS]
//
// [compact JWS]: https://datatracker.ietf.org/doc/html/rfc7515#section-7.1
func Decode(jws string, opts ...DecodeOption) (Decoded, error) {
	o := decodeOptions{}

	for _, opt := range opts {
		opt(&o)
	}

	parts := strings.Split(jws, ".")
	if len(parts) != NumCompactParts {
		return Decoded{}, fmt.Errorf("malformed JWS. Expected 3 parts, got %d", len(parts))
	}

	header, err := DecodeHeader(parts[0])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWS. Failed to decode header: %w", err)
	}

	var payload []byte
	if o.payload == nil {
		payload, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return Decoded{}, fmt.Errorf("malformed JWS. Failed to decode payload: %w", err)
		}
	} else {
		payload = o.payload
		parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	}

	signature, err := DecodeSignature(parts[2])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWS. Failed to decode signature: %w", err)
	}

	return Decoded{
		Header:    header,
		Payload:   payload,
		Signature: signature,
		Parts:     parts,
	}, nil
}

type decodeOptions struct {
	payload []byte
}

// DecodeOption represents an option that can be passed to [Decode] or [Verify].
type DecodeOption func(opts *decodeOptions)

// Payload can be passed to [Decode] or [Verify] to provide a detached payload.
// More info on detached payloads can be found [here].
//
// [here]: https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
func Payload(p []byte) DecodeOption {
	return func(opts *decodeOptions) {
		opts.payload = p
	}
}

// DecodeHeader decodes the base64url encoded JWS header into a [Header].
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

// DecodeSignature decodes the base64url encoded JWS signature into a byte array.
func DecodeSignature(base64UrlEncodedSignature string) ([]byte, error) {
	signature, err := base64.RawURLEncoding.DecodeString(base64UrlEncodedSignature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// options that sign function can take.
type signOpts struct {
	detached bool
	typ      string
}

// SignOpt is a type that represents an option that can be passed to [github.com/mistermoe/jose/jws.Sign].
type SignOpt func(opts *signOpts)

// DetachedPayload is an option that can be passed to [github.com/mistermoe/jose/jws.Sign].
// It is used to indicate whether the payload should be included in the signature.
// More details can be found [here].
//
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
func DetachedPayload(detached bool) SignOpt {
	return func(opts *signOpts) {
		opts.detached = detached
	}
}

// Type is used to set the `typ` JWS header value.
func Type(typ string) SignOpt {
	return func(opts *signOpts) {
		opts.typ = typ
	}
}

// Sign signs the payload provided with the jwk provided and returns a compact JWS.
func Sign(payload []byte, jwk jwk.JWK, opts ...SignOpt) (string, error) {
	o := signOpts{detached: false}
	for _, opt := range opts {
		opt(&o)
	}

	kid, err := jwk.ComputeThumbprint()
	if err != nil {
		return "", fmt.Errorf("failed to compute jwk thumbprint: %w", err)
	}

	header := Header{ALG: jwk.ALG, KID: kid, TYP: o.typ}
	base64UrlEncodedHeader, err := header.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to base64 url encode header: %w", err)
	}

	base64UrlEncodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	toSign := base64UrlEncodedHeader + "." + base64UrlEncodedPayload
	toSignBytes := []byte(toSign)

	signature, err := dsa.Sign(toSignBytes, jwk)
	if err != nil {
		return "", fmt.Errorf("failed to compute signature: %w", err)
	}

	base64UrlEncodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	var compactJWS string
	if o.detached {
		compactJWS = base64UrlEncodedHeader + "." + "." + base64UrlEncodedSignature
	} else {
		compactJWS = toSign + "." + base64UrlEncodedSignature
	}

	return compactJWS, nil
}

// Verify does an integrity check on the provided compactJWS using the jwk.
func Verify(compactJWS string, publicJwk jwk.JWK, opts ...DecodeOption) (Decoded, error) {
	decodedJWS, err := Decode(compactJWS, opts...)
	if err != nil {
		return decodedJWS, fmt.Errorf("signature verification failed: %w", err)
	}

	err = decodedJWS.Verify(publicJwk)

	return decodedJWS, err
}

// Decoded is a compact JWS decoded into its parts.
type Decoded struct {
	Header    Header
	Payload   []byte
	Signature []byte
	Parts     []string
}

// Verify does an integrity check using the provided jwk.
func (jws Decoded) Verify(publicJwk jwk.JWK) error {
	if jws.Header.ALG == "" {
		return errors.New("malformed JWS header. alg and kid are required")
	}

	toVerify := jws.Parts[0] + "." + jws.Parts[1]

	verified, err := dsa.Verify([]byte(toVerify), jws.Signature, publicJwk)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if !verified {
		return errors.New("invalid signature")
	}

	return nil
}

// Header represents a JWS (JSON Web Signature) header. See [Specification] for more details.
// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#section-4
type Header struct {
	// Ide	ntifies the cryptographic algorithm used to secure the JWS. The JWS Signature value is not
	// valid if the "alg" value does not represent a supported algorithm or if there is not a key for
	// use with that algorithm associated with the party that digitally signed or MACed the content.
	//
	// "alg" values should either be registered in the IANA "JSON Web Signature and Encryption
	// Algorithms" registry or be a value that contains a Collision-Resistant Name. The "alg" value is
	// a case-sensitive ASCII string.  This Header Parameter MUST be present and MUST be understood
	// and processed by implementations.
	//
	// [Specification]: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1
	ALG string `json:"alg,omitempty"`
	// Key ID Header Parameter https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	KID string `json:"kid,omitempty"`
	// Type Header Parameter https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
	TYP string `json:"typ,omitempty"`
}

// Encode returns the base64url encoded header.
func (j Header) Encode() (string, error) {
	bytes, err := json.Marshal(j)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
