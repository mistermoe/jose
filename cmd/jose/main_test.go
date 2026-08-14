package main_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/mistermoe/jose/jwe"
	"github.com/mistermoe/jose/jwk"
)

// binPath is the compiled cli under test, built once by TestMain.
var binPath string

type envelope struct {
	JWE string  `json:"jwe"`
	JWK jwk.JWK `json:"jwk"`
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "jose-cli")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	binPath = filepath.Join(dir, "jose")

	build := exec.Command("go", "build", "-o", binPath, ".")

	output, err := build.CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, string(output))
		os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()

	os.RemoveAll(dir)
	os.Exit(code)
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	// arbitrary binary, including null bytes and bytes outside the ascii range.
	payload := make([]byte, 0, 512)
	for i := range 512 {
		payload = append(payload, byte(i%256))
	}

	stdout, _, err := runCLI(t, payload, "encrypt")
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)

	plaintext, _, err := runCLI(t, nil, "decrypt", "-key", marshal(t, env.JWK), env.JWE)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(payload, plaintext), "expected the decrypted blob to match the input")
}

func TestKeygen(t *testing.T) {
	stdout, _, err := runCLI(t, nil, "keygen")
	assert.NoError(t, err)

	key := jwk.JWK{}
	assert.NoError(t, json.Unmarshal(stdout, &key))

	assert.Equal(t, "oct", key.KTY)
	assert.Equal(t, jwe.A256GCMJWA, key.ALG)

	k, err := base64.RawURLEncoding.DecodeString(key.K)
	assert.NoError(t, err)
	assert.Equal(t, jwe.A256GCMKeySize, len(k))

	thumbprint, err := key.ComputeThumbprint()
	assert.NoError(t, err)
	assert.Equal(t, thumbprint, key.KID)

	// no private material beyond `k`, and nothing from the asymmetric key parameters.
	assert.Equal(t, "", key.D)
	assert.Equal(t, "", key.X)
	assert.Equal(t, "", key.N)
}

func TestKeygen_IsNotDeterministic(t *testing.T) {
	first, _, err := runCLI(t, nil, "keygen")
	assert.NoError(t, err)

	second, _, err := runCLI(t, nil, "keygen")
	assert.NoError(t, err)

	assert.NotEqual(t, string(first), string(second))
}

func TestKeygen_OutFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")

	stdout, _, err := runCLI(t, nil, "keygen", "-out", path)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(stdout), "expected nothing on stdout when -out is a file")

	contents, err := os.ReadFile(path)
	assert.NoError(t, err)

	key := jwk.JWK{}
	assert.NoError(t, json.Unmarshal(contents, &key))
	assert.Equal(t, "oct", key.KTY)
}

// a generated key must be usable by encrypt, otherwise keygen has no consumer.
func TestKeygen_FeedsEncrypt(t *testing.T) {
	generated, _, err := runCLI(t, nil, "keygen")
	assert.NoError(t, err)

	key := jwk.JWK{}
	assert.NoError(t, json.Unmarshal(generated, &key))

	stdout, _, err := runCLI(t, []byte("hello world"), "encrypt", "-key", string(generated))
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)
	assert.Equal(t, key.K, env.JWK.K, "expected the supplied key to be used verbatim")

	plaintext, _, err := runCLI(t, nil, "decrypt", "-key", string(generated), env.JWE)
	assert.NoError(t, err)
	assert.Equal(t, "hello world", string(plaintext))
}

// the point of supplying a key is encrypting several blobs under one key.
func TestEncrypt_SuppliedKeyIsReusedAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")

	_, _, err := runCLI(t, nil, "keygen", "-out", keyPath)
	assert.NoError(t, err)

	first, _, err := runCLI(t, []byte("first"), "encrypt", "-key", keyPath)
	assert.NoError(t, err)

	second, _, err := runCLI(t, []byte("second"), "encrypt", "-key", keyPath)
	assert.NoError(t, err)

	firstEnv := decodeEnvelope(t, first)
	secondEnv := decodeEnvelope(t, second)

	assert.Equal(t, firstEnv.JWK.K, secondEnv.JWK.K)
	assert.NotEqual(t, firstEnv.JWE, secondEnv.JWE, "a fresh iv must still be used per encryption")

	// the one key decrypts both blobs.
	plaintext, _, err := runCLI(t, nil, "decrypt", "-key", keyPath, firstEnv.JWE)
	assert.NoError(t, err)
	assert.Equal(t, "first", string(plaintext))

	plaintext, _, err = runCLI(t, nil, "decrypt", "-key", keyPath, secondEnv.JWE)
	assert.NoError(t, err)
	assert.Equal(t, "second", string(plaintext))
}

func TestEncrypt_BadSuppliedKey(t *testing.T) {
	vectors := []struct {
		key     string
		message string
	}{
		{"/does/not/exist.json", "failed to read key"},
		{"{not json", "failed to parse key"},
		{`{"alg":"A256GCM"}`, "key is missing `kty`"},
		{`{"kty":"oct","k":"AAAA"}`, "content encryption key must be 32 bytes"},
	}

	for _, vector := range vectors {
		_, stderr, err := runCLI(t, []byte("hello"), "encrypt", "-key", vector.key)
		assert.Error(t, err, "expected failure. key: %s", vector.key)
		assert.Contains(t, stderr, vector.message)
	}
}

func TestEncrypt_Envelope(t *testing.T) {
	stdout, _, err := runCLI(t, []byte("hello world"), "encrypt")
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)

	assert.Equal(t, "oct", env.JWK.KTY)
	assert.Equal(t, jwe.A256GCMJWA, env.JWK.ALG)

	k, err := base64.RawURLEncoding.DecodeString(env.JWK.K)
	assert.NoError(t, err)
	assert.Equal(t, jwe.A256GCMKeySize, len(k))

	// the echoed kid must match the one in the JWE header.
	decoded, err := jwe.Decode(env.JWE)
	assert.NoError(t, err)
	assert.Equal(t, decoded.Header.KID, env.JWK.KID)
	assert.NotZero(t, env.JWK.KID)

	// the plaintext must not be recoverable from the envelope without the key.
	assert.False(t, strings.Contains(env.JWE, base64.RawURLEncoding.EncodeToString([]byte("hello world"))))
}

func TestEncrypt_UsesAFreshKeyEachTime(t *testing.T) {
	first, _, err := runCLI(t, []byte("hello"), "encrypt")
	assert.NoError(t, err)

	second, _, err := runCLI(t, []byte("hello"), "encrypt")
	assert.NoError(t, err)

	assert.NotEqual(t, decodeEnvelope(t, first).JWK.K, decodeEnvelope(t, second).JWK.K)
}

func TestEncryptDecrypt_InAndOutFiles(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("hello from a file")

	in := filepath.Join(dir, "blob.bin")
	assert.NoError(t, os.WriteFile(in, payload, 0o600))

	sealed := filepath.Join(dir, "sealed.json")

	_, _, err := runCLI(t, nil, "encrypt", "-in", in, "-out", sealed)
	assert.NoError(t, err)

	contents, err := os.ReadFile(sealed)
	assert.NoError(t, err)

	env := decodeEnvelope(t, contents)

	keyPath := filepath.Join(dir, "key.json")
	assert.NoError(t, os.WriteFile(keyPath, []byte(marshal(t, env.JWK)), 0o600))

	jwePath := filepath.Join(dir, "token.jwe")
	assert.NoError(t, os.WriteFile(jwePath, []byte(env.JWE), 0o600))

	out := filepath.Join(dir, "out.bin")

	// key from a file, JWE from a file, plaintext to a file.
	_, _, err = runCLI(t, nil, "decrypt", "-key", keyPath, "-in", jwePath, "-out", out)
	assert.NoError(t, err)

	recovered, err := os.ReadFile(out)
	assert.NoError(t, err)
	assert.Equal(t, string(payload), string(recovered))
}

func TestDecrypt_JWEFromStdin(t *testing.T) {
	stdout, _, err := runCLI(t, []byte("hello"), "encrypt")
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)

	// a trailing newline, as a shell redirect would produce, must be tolerated.
	plaintext, _, err := runCLI(t, []byte(env.JWE+"\n"), "decrypt", "-key", marshal(t, env.JWK))
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(plaintext))
}

func TestDecrypt_WrongKey(t *testing.T) {
	stdout, _, err := runCLI(t, []byte("hello"), "encrypt")
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)

	other, err := jwe.A256GCMGenerateKey()
	assert.NoError(t, err)

	_, stderr, err := runCLI(t, nil, "decrypt", "-key", marshal(t, other), env.JWE)
	assert.Error(t, err)
	assert.Contains(t, stderr, "failed to decrypt payload")
}

func TestDecrypt_Tampered(t *testing.T) {
	stdout, _, err := runCLI(t, []byte("hello world"), "encrypt")
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)

	parts := strings.Split(env.JWE, ".")

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	assert.NoError(t, err)

	ciphertext[0] ^= 0xff
	parts[3] = base64.RawURLEncoding.EncodeToString(ciphertext)

	_, stderr, err := runCLI(t, nil, "decrypt", "-key", marshal(t, env.JWK), strings.Join(parts, "."))
	assert.Error(t, err)
	assert.Contains(t, stderr, "failed to decrypt payload")
}

func TestDecrypt_BadUsage(t *testing.T) {
	stdout, _, err := runCLI(t, []byte("hello"), "encrypt")
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)
	key := marshal(t, env.JWK)

	vectors := []struct {
		args    []string
		message string
	}{
		{[]string{"decrypt", env.JWE}, "-key is required"},
		{[]string{"decrypt", "-key", key, "not.a.jwe"}, "malformed JWE. Expected 5 parts"},
		{[]string{"decrypt", "-key", key, env.JWE, env.JWE}, "expected at most one JWE argument"},
		{[]string{"decrypt", "-key", "/does/not/exist.json", env.JWE}, "failed to read key"},
		{[]string{"decrypt", "-key", "{not json", env.JWE}, "failed to parse key"},
		{[]string{"decrypt", "-key", `{"alg":"A256GCM"}`, env.JWE}, "key is missing `kty`"},
		{[]string{"decrypt", "-key", `{"kty":"oct","k":"AAAA"}`, env.JWE}, "content encryption key must be 32 bytes"},
	}

	for _, vector := range vectors {
		_, stderr, runErr := runCLI(t, nil, vector.args...)
		assert.Error(t, runErr, "expected failure. args: %v", vector.args)
		assert.Contains(t, stderr, vector.message)
	}
}

// passing the whole encrypt envelope where a jwk is expected is an easy mistake, so it gets its
// own hint rather than a bare `kty` complaint.
func TestDecrypt_EnvelopePassedAsKey(t *testing.T) {
	stdout, _, err := runCLI(t, []byte("hello"), "encrypt")
	assert.NoError(t, err)

	env := decodeEnvelope(t, stdout)

	_, stderr, err := runCLI(t, nil, "decrypt", "-key", string(stdout), env.JWE)
	assert.Error(t, err)
	assert.Contains(t, stderr, "that looks like an encrypt envelope")
}

func TestRun_Usage(t *testing.T) {
	stdout, _, err := runCLI(t, nil, "help")
	assert.NoError(t, err)
	assert.Contains(t, string(stdout), "jose keygen")
	assert.Contains(t, string(stdout), "jose encrypt")
	assert.Contains(t, string(stdout), "jose decrypt")

	_, stderr, err := runCLI(t, nil)
	assert.Error(t, err)
	assert.Contains(t, stderr, "no command given")

	_, stderr, err = runCLI(t, nil, "frobnicate")
	assert.Error(t, err)
	assert.Contains(t, stderr, "unknown command: frobnicate")
}

// runCLI invokes the compiled binary, returning its stdout and stderr.
func runCLI(t *testing.T, stdin []byte, args ...string) ([]byte, string, error) {
	t.Helper()

	cmd := exec.Command(binPath, args...)
	cmd.Stdin = bytes.NewReader(stdin)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()

	return stdout.Bytes(), stderr.String(), err
}

// decodeEnvelope parses the JSON envelope written by the encrypt subcommand.
func decodeEnvelope(t *testing.T, output []byte) envelope {
	t.Helper()

	env := envelope{}
	err := json.Unmarshal(output, &env)
	assert.NoError(t, err)

	return env
}

// marshal renders a jwk as the inline JSON accepted by the -key flag.
func marshal(t *testing.T, key jwk.JWK) string {
	t.Helper()

	bytes, err := json.Marshal(key)
	assert.NoError(t, err)

	return string(bytes)
}
