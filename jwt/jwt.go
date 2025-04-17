package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mistermoe/jose/jwk"
	"github.com/mistermoe/jose/jws"
)

// Decode decodes the 3-part base64url encoded jwt into it's relevant parts.
func Decode(jwt string) (Decoded, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != jws.NumCompactParts {
		return Decoded{}, fmt.Errorf("malformed JWT. Expected 3 parts, got %d", len(parts))
	}

	header, err := jws.DecodeHeader(parts[0])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWT. Failed to decode header: %w", err)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWT. Failed to decode claims: %w", err)
	}

	claims := Claims{}
	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWT. Failed to unmarshal claims: %w", err)
	}

	signature, err := jws.DecodeSignature(parts[2])
	if err != nil {
		return Decoded{}, fmt.Errorf("malformed JWT. Failed to decode signature: %w", err)
	}

	return Decoded{
		Header:    header,
		Claims:    claims,
		Signature: signature,
		Parts:     parts,
	}, nil
}

// signOpts is a type that holds all the options that can be passed to Sign.
type signOpts struct {
	typ string
}

// SignOpt is a type returned by all individual Sign Options.
type SignOpt func(opts *signOpts)

// Type is an option that can be used to set the typ header of the JWT.
func Type(t string) SignOpt {
	return func(opts *signOpts) {
		opts.typ = t
	}
}

// Sign signs the provided claims using the provided jwk and returns a compact JWT.
func Sign(claims Claims, privateJwk jwk.JWK, opts ...SignOpt) (string, error) {
	o := signOpts{typ: ""}
	for _, opt := range opts {
		opt(&o)
	}

	jwsOpts := make([]jws.SignOpt, 0)

	if o.typ != "" {
		jwsOpts = append(jwsOpts, jws.Type(o.typ))
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt claims: %w", err)
	}

	return jws.Sign(payload, privateJwk, jwsOpts...)
}

// Verify checks the integrity of the provided jwt using the provided jwk.
func Verify(jwt string, publicJwk jwk.JWK) (Decoded, error) {
	decodedJWT, err := Decode(jwt)
	if err != nil {
		return Decoded{}, err
	}

	err = decodedJWT.Verify(publicJwk)

	return decodedJWT, err
}

type Header = jws.Header

// Decoded represents a JWT Decoded into it's relevant parts.
type Decoded struct {
	Header    Header
	Claims    Claims
	Signature []byte
	Parts     []string
}

// Verify verifies a JWT (JSON Web Token).
func (jwt Decoded) Verify(publicJwk jwk.JWK) error {
	if jwt.Claims.Expiration != 0 && time.Now().Unix() > jwt.Claims.Expiration {
		return errors.New("JWT has expired")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(jwt.Parts[1])
	if err != nil {
		return fmt.Errorf("malformed JWT. Failed to decode claims: %w", err)
	}

	decodedJWS := jws.Decoded{
		Header:    jwt.Header,
		Payload:   claimsBytes,
		Signature: jwt.Signature,
		Parts:     jwt.Parts,
	}

	err = decodedJWS.Verify(publicJwk)
	if err != nil {
		return fmt.Errorf("JWT signature verification failed: %w", err)
	}

	return nil
}

// Claims represents JWT (JSON Web Token) Claims
//
// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4
type Claims struct {
	// The "iss" (issuer) claim identifies the principal that issued the
	// JWT.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`
	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// The "aud" (audience) claim identifies the recipients that the JWT is
	// intended for.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`

	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT must not be accepted for processing.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	Expiration int64 `json:"exp,omitempty"`

	// The "nbf" (not before) claim identifies the time before which the JWT
	// must not be accepted for processing.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore int64 `json:"nbf,omitempty"`

	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt int64 `json:"iat,omitempty"`

	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	//
	// Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	JTI string `json:"jti,omitempty"`

	Misc map[string]any `json:"-"`
}

func (c Claims) MarshalJSON() ([]byte, error) {
	copied := cpy(c)

	bytes, err := json.Marshal(copied)
	if err != nil {
		return nil, err
	}

	var combined map[string]interface{}
	err = json.Unmarshal(bytes, &combined)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt claims: %w", err)
	}

	// Add private claims to the map
	for key, value := range c.Misc {
		combined[key] = value
	}

	return json.Marshal(combined)
}

func (c *Claims) UnmarshalJSON(b []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	registeredClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"exp": true, "nbf": true, "iat": true,
		"jti": true,
	}

	misc := make(map[string]any)
	for key, value := range m {
		if _, ok := registeredClaims[key]; !ok {
			misc[key] = value
		}
	}

	claims := cpy{}
	if err := json.Unmarshal(b, &claims); err != nil {
		return err
	}

	claims.Misc = misc
	*c = Claims(claims)

	return nil
}

// cpy is a copy of Claims that is used to marshal/unmarshal the claims without infinitely looping.
type cpy Claims

// ExpiresIn returns the provided duration as seconds since epoch. This function is useful when
// setting the `Expiration` claim.
func ExpiresIn(issuedAt time.Time, duration string) (int64, error) {
	parsedDuration, err := time.ParseDuration(duration)
	if err != nil {
		return 0, fmt.Errorf("failed to parse duration. error: %w", err)
	}

	expiresIn := issuedAt.Add(parsedDuration).Unix()

	return expiresIn, nil
}
