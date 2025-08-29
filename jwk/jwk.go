// Package jwk implements a subset of the JSON Web Key spec (https://tools.ietf.org/html/rfc7517)
package jwk

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// JWK represents a JSON Web Key as per RFC7517 (https://tools.ietf.org/html/rfc7517)
// Note that this is a subset of the spec. There are a handful of properties that the
// spec allows for that are not represented here at the moment. This is because we
// only need a subset of the spec for our purposes.
type JWK struct {
	ALG string `json:"alg,omitempty"`
	KTY string `json:"kty,omitempty"`
	CRV string `json:"crv,omitempty"`
	D   string `json:"d,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// RSA key parameters
	N string `json:"n,omitempty"` // RSA modulus
	E string `json:"e,omitempty"` // RSA exponent
}

// ComputeThumbprint computes the JWK thumbprint as per RFC7638 (https://tools.ietf.org/html/rfc7638)
func (j JWK) ComputeThumbprint() (string, error) {
	var thumbprintPayload map[string]interface{}

	switch j.KTY {
	case "RSA":
		// For RSA keys, use "e", "kty", "n" as per RFC 7638
		thumbprintPayload = map[string]interface{}{
			"e":   j.E,
			"kty": j.KTY,
			"n":   j.N,
		}
	case "EC", "OKP":
		// For elliptic curve and OKP keys, use existing logic
		thumbprintPayload = map[string]interface{}{
			"crv": j.CRV,
			"kty": j.KTY,
			"x":   j.X,
		}
		if j.Y != "" {
			thumbprintPayload["y"] = j.Y
		}
	default:
		// Fallback to existing logic for unknown key types
		thumbprintPayload = map[string]interface{}{
			"crv": j.CRV,
			"kty": j.KTY,
			"x":   j.X,
		}
		if j.Y != "" {
			thumbprintPayload["y"] = j.Y
		}
	}

	bytes, err := json.Marshal(thumbprintPayload)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(bytes)
	thumbprint := base64.RawURLEncoding.EncodeToString(digest[:])

	return thumbprint, nil
}
