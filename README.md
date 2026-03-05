# jose

A Go implementation of the JOSE (JSON Object Signing and Encryption) family of specs, focused on signing and verification.

## Functionality

* Key generation, import (PEM), and conversion to/from bytes for EC, EdDSA, and RSA keys
* JWS (JSON Web Signature) signing and verification, including detached payloads
* JWT (JSON Web Token) signing, verification, and claims handling
* JWK thumbprints (RFC 7638)
* Cryptographically secure random entropy generation

## Supported Algorithms

| Algorithm ID | Key Type | Curve / Scheme | JWA |
|---|---|---|---|
| `secp256k1` | EC | secp256k1 | ES256K |
| `secp384r1` | EC | P-384 | ES384 |
| `Ed25519` | OKP | Ed25519 | EdDSA |
| `RS256` | RSA | RSASSA-PKCS1-v1_5 + SHA-256 | RS256 |

---

## `jwk` -- JSON Web Key

Defines the `JWK` struct used across the entire library. All keys -- regardless of algorithm -- are represented as a single `jwk.JWK` value.

### API

| Function | Description |
|---|---|
| `JWK.ComputeThumbprint()` | RFC 7638 thumbprint (base64url-encoded SHA-256) |

### Usage

```go
key, _ := dsa.GeneratePrivateKey(dsa.AlgorithmIDED25519)
thumbprint, _ := key.ComputeThumbprint()
```

---

## `dsa` -- Digital Signature Algorithms

Facade over algorithm-specific sub-packages (`dsa/ecdsa`, `dsa/eddsa`, `dsa/rsa`). All functions accept or return `jwk.JWK` and route to the correct implementation based on the key's type and curve.

```mermaid
flowchart TD
    caller["dsa.Sign(payload, key)"] --> ktySwitch{"key.KTY"}
    ktySwitch -->|EC| ecdsaPkg["dsa/ecdsa"]
    ktySwitch -->|OKP| eddsaPkg["dsa/eddsa"]
    ktySwitch -->|RSA| rsaPkg["dsa/rsa"]
    ecdsaPkg --> crvSwitch{"key.CRV"}
    crvSwitch -->|secp256k1| secp256k1["secp256k1.go"]
    crvSwitch -->|"P-384"| secp384r1["secp384r1.go"]
    eddsaPkg --> ed25519["ed25519.go"]
    rsaPkg --> rs256["rs256.go"]
```

### API

| Function | Description |
|---|---|
| `GeneratePrivateKey(algorithmID)` | Generate a new private key |
| `GetPublicKey(privateKey)` | Derive the public key from a private key |
| `Sign(payload, privateKey)` | Sign raw bytes |
| `Verify(payload, signature, publicKey)` | Verify a signature over raw bytes |
| `PrivateKeyFromPEM(pemBytes)` | Parse a PEM-encoded private key into a JWK |
| `PublicKeyFromPEM(pemBytes)` | Parse a PEM-encoded public key into a JWK |
| `BytesToPublicKey(algorithmID, input)` | Deserialize a public key from raw/DER bytes |
| `PublicKeyToBytes(publicKey)` | Serialize a public key to bytes |
| `GetJWA(key)` | Get the JWA algorithm string for a key |
| `AlgorithmID(key)` | Get the algorithm ID for a key |

### Usage

```go
// generate a key
privateKey, _ := dsa.GeneratePrivateKey(dsa.AlgorithmIDSECP384R1)
publicKey := dsa.GetPublicKey(privateKey)

// sign and verify
signature, _ := dsa.Sign([]byte("hello"), privateKey)
ok, _ := dsa.Verify([]byte("hello"), signature, publicKey)

// import from PEM
pemBytes := []byte(`-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`)

imported, _ := dsa.PrivateKeyFromPEM(pemBytes)
```

`PrivateKeyFromPEM` accepts PKCS#8, SEC 1 (EC), and PKCS#1 (RSA) encodings. The key type is detected automatically -- no algorithm ID is needed.

---

## `jws` -- JSON Web Signature

Signs and verifies compact JWS (RFC 7515). The API separates decoding from verification so callers can inspect the header and payload before deciding whether to verify, or verify against a key selected based on the decoded header's `kid`.

### API

| Function | Description |
|---|---|
| `Sign(payload, key, ...opts)` | Produce a compact JWS string |
| `Decode(compactJWS, ...opts)` | Decode without verifying |
| `Verify(compactJWS, publicKey, ...opts)` | Decode and verify in one step |
| `Decoded.Verify(publicKey)` | Verify a previously decoded JWS |

#### Sign Options

| Option | Description |
|---|---|
| `DetachedPayload(true)` | Omit the payload from the compact serialization ([RFC 7515 Appendix F](https://datatracker.ietf.org/doc/html/rfc7515#appendix-F)) |
| `Type(typ)` | Set the `typ` header (e.g. `openid4vci-proof+jwt`) |

#### Decode Options

| Option | Description |
|---|---|
| `Payload(p)` | Supply the detached payload for decoding/verification |

### Verify then use

`jws.Verify` decodes and verifies in a single call, returning the decoded JWS. This is the common path when you already have the public key on hand and just need the verified payload.

```go
decoded, err := jws.Verify(compactJWS, publicKey)
if err != nil {
    // integrity check failed
}
// safe to use decoded.Payload
```

### Decode first, verify later

`jws.Decode` returns the decoded header, payload, and signature without checking integrity. This is useful when the public key isn't known ahead of time -- for example, when a message arrives and you need to read the `kid` from the header to look up the right key from a key store before verifying.

```go
decoded, _ := jws.Decode(compactJWS)

// inspect the header to determine which key to use
publicKey, _ := keyStore.GetKey(decoded.Header.KID)

// now verify with the resolved key
err := decoded.Verify(publicKey)
```

The same pattern applies to `jwt.Decode` / `jwt.Verify` and `jwt.Decoded.Verify`.

#### Detached Payloads

Some protocols (e.g. certain OAuth and identity flows) require the payload to be transmitted out-of-band rather than embedded in the JWS. The `DetachedPayload` option supports this by producing a compact JWS with an empty payload segment. On the verification side, the `Payload` option supplies the detached content.

```go
// sign with detached payload
compact, _ := jws.Sign(payload, privateKey, jws.DetachedPayload(true))
// compact looks like: eyJhbGci...  ..  SflKxw...  (empty middle segment)

// verify by supplying the payload separately
decoded, _ := jws.Verify(compact, publicKey, jws.Payload(payload))
```

---

## `jwt` -- JSON Web Token

Built on top of `jws`. Handles JWT-specific concerns: structured claims, expiration checking, and custom `typ` headers. The same decode/verify separation from `jws` applies here -- `jwt.Verify` decodes, checks expiration, and verifies the signature in one call, while `jwt.Decode` + `jwt.Decoded.Verify` lets you inspect claims or resolve a key before verifying.

### API

| Function | Description |
|---|---|
| `Sign(claims, privateKey, ...opts)` | Sign claims into a compact JWT |
| `Decode(jwt)` | Decode without verifying |
| `Verify(jwt, publicKey)` | Decode, check expiration, and verify signature |
| `Decoded.Verify(publicKey)` | Verify a previously decoded JWT |
| `ExpiresIn(issuedAt, duration)` | Compute an expiration timestamp from a duration string |

### Claims

`jwt.Claims` has typed fields for the registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) and a `Misc` map for arbitrary custom claims. Both are merged into a flat JSON object during serialization, so the wire format is a standard JWT claims set with no nesting.

```go
claims := jwt.Claims{
    Issuer:   "https://example.com",
    IssuedAt: time.Now().Unix(),
    Misc: map[string]any{
        "c_nonce": "abc123",
        "scope":   "openid",
    },
}

signedJWT, _ := jwt.Sign(claims, privateKey)

// verify (also checks expiration)
decoded, _ := jwt.Verify(signedJWT, publicKey)
fmt.Println(decoded.Claims.Issuer)         // "https://example.com"
fmt.Println(decoded.Claims.Misc["scope"])  // "openid"
```

---

## `entropy`

Cryptographically secure random byte generation following [NIST SP 800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf) size recommendations.

### API

| Function | Description |
|---|---|
| `Generate(size)` | Generate random bytes (returns `[]byte`) |
| `GenerateNonce(size)` | Generate a hex-encoded nonce string |

Predefined sizes: `Size112`, `Size128`, `Size192`, `Size256`.

---

## Adding Support for a New Algorithm

The library is structured so each algorithm lives in its own file within the appropriate `dsa` sub-package. Adding a new algorithm involves three steps:

### 1. Create the implementation file

Add a new file in the relevant sub-package (e.g. `dsa/ecdsa/secp256r1.go` for P-256). The file should export:

* Constants: JWA name, JWA curve, algorithm ID, key/signature sizes
* `<Alg>GeneratePrivateKey() (jwk.JWK, error)`
* `<Alg>Sign(payload []byte, privateKey jwk.JWK) ([]byte, error)`
* `<Alg>Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error)`
* `<Alg>BytesToPublicKey(input []byte) (jwk.JWK, error)`
* `<Alg>PublicKeyToBytes(publicKey jwk.JWK) ([]byte, error)`
* `<Alg>PrivateJwkFromKey(key <go-crypto-type>) (jwk.JWK, error)` (for PEM support)

Use an existing file like `dsa/ecdsa/secp256k1.go` or `dsa/ecdsa/secp384r1.go` as a template.

### 2. Register in the sub-package facade

In the sub-package's facade file (e.g. `dsa/ecdsa/ecdsa.go`):

* Add the new algorithm ID to the `algorithmIDs` map
* Add `case` branches in `GeneratePrivateKey`, `Sign`, `Verify`, `GetJWA`, `BytesToPublicKey`, `PublicKeyToBytes`, `AlgorithmID`, `PrivateJwkFromKey`, and `PublicJwkFromKey`

### 3. Wire into the top-level facade

If the new algorithm uses an existing key type (EC, OKP, RSA), no changes are needed in `dsa/dsa.go` -- routing is already handled by `KTY`. If it introduces a new key type, add the corresponding `case` branches in `dsa/dsa.go`.

Expose a new `AlgorithmID` constant in `dsa/dsa.go` for convenience:

```go
const AlgorithmIDSECP256R1 = ecdsa.SECP256R1AlgorithmID
```
