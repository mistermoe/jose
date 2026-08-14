package jwk_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/mistermoe/jose/jwk"
)

// test vector taken from RFC 7638 Section 3.1. The thumbprint of the RSA key given there is
// published in Section 3.1 as `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.
// https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
func TestComputeThumbprint_RSA(t *testing.T) {
	key := jwk.JWK{
		KTY: "RSA",
		E:   "AQAB",
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjB" +
			"ZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8" +
			"KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_" +
			"xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}

	thumbprint, err := key.ComputeThumbprint()
	assert.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint)
}

// oct thumbprints are computed over the required members `k` and `kty` only.
// https://datatracker.ietf.org/doc/html/rfc7638#section-3.2
func TestComputeThumbprint_Oct(t *testing.T) {
	key := jwk.JWK{KTY: "oct", ALG: "A256GCM", K: "GawgguFyGrWKav7AX4VKUg"}

	thumbprint, err := key.ComputeThumbprint()
	assert.NoError(t, err)
	assert.NotZero(t, thumbprint)

	// `alg` is not a thumbprint member, so it must not affect the result.
	withoutAlg := jwk.JWK{KTY: "oct", K: key.K}

	other, err := withoutAlg.ComputeThumbprint()
	assert.NoError(t, err)
	assert.Equal(t, thumbprint, other)
}

// oct thumbprints must be distinct per key. Before `oct` was handled explicitly it fell through to
// the EC/OKP branch, which hashes `crv`/`kty`/`x` and therefore produced the same thumbprint for
// every symmetric key.
func TestComputeThumbprint_OctIsKeySpecific(t *testing.T) {
	first := jwk.JWK{KTY: "oct", K: "GawgguFyGrWKav7AX4VKUg"}
	second := jwk.JWK{KTY: "oct", K: "AxfQrbn7hMBrHLzWnhHcpg"}

	firstThumbprint, err := first.ComputeThumbprint()
	assert.NoError(t, err)

	secondThumbprint, err := second.ComputeThumbprint()
	assert.NoError(t, err)

	assert.NotEqual(t, firstThumbprint, secondThumbprint)
}

func TestComputeThumbprint_EC(t *testing.T) {
	key := jwk.JWK{
		KTY: "EC",
		CRV: "P-256",
		X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}

	thumbprint, err := key.ComputeThumbprint()
	assert.NoError(t, err)
	assert.NotZero(t, thumbprint)

	// `y` participates in the EC thumbprint.
	withoutY := jwk.JWK{KTY: key.KTY, CRV: key.CRV, X: key.X}

	other, err := withoutY.ComputeThumbprint()
	assert.NoError(t, err)
	assert.NotEqual(t, thumbprint, other)
}
