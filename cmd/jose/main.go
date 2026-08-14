// Command jose encrypts and decrypts arbitrary blobs as compact JWEs.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mistermoe/jose/jwe"
	"github.com/mistermoe/jose/jwk"
)

const usage = `jose encrypts and decrypts arbitrary blobs as compact JWEs.

usage:
  jose keygen [-out FILE]
  jose encrypt [-key KEY] [-in FILE] [-out FILE]
  jose decrypt -key KEY [-in FILE] [-out FILE] [JWE]

keygen writes a freshly generated A256GCM key as an oct JWK.

encrypt reads a blob and writes a JSON envelope holding the compact JWE
alongside the key needed to decrypt it. A fresh key is generated unless -key
supplies one.

decrypt reads a compact JWE and writes the recovered blob. The JWE is taken from
the JWE argument if given, otherwise from -in.

KEY is either a path to a file holding an oct JWK or the JWK itself as inline
JSON. ` + "`-`" + ` means stdin for -in and stdout for -out. Both default to ` + "`-`" + `.

examples:
  jose encrypt < photo.jpg > sealed.json
  jose decrypt -key "$(jq -c .jwk sealed.json)" "$(jq -r .jwe sealed.json)" > photo.jpg

  jose keygen > key.json
  jose encrypt -key key.json < photo.jpg > sealed.json
`

// outputPerm is the mode used for files created by -out.
const outputPerm = 0o600

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "jose: "+err.Error())
		os.Exit(1)
	}
}

// run dispatches to the requested subcommand.
func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)

		return errors.New("no command given")
	}

	switch args[0] {
	case "keygen":
		return keygen(args[1:])
	case "encrypt":
		return encrypt(args[1:])
	case "decrypt":
		return decrypt(args[1:])
	case "help", "-h", "-help", "--help":
		fmt.Fprint(os.Stdout, usage)

		return nil
	default:
		fmt.Fprint(os.Stderr, usage)

		return fmt.Errorf("unknown command: %s", args[0])
	}
}

// keygen writes a freshly generated content encryption key.
func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := flags.String("out", "-", "file to write the JWK to")

	if err := flags.Parse(args); err != nil {
		return err
	}

	key, err := resolveKey("")
	if err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	return writeOutput(*out, append(bytes, '\n'))
}

// encrypt encrypts a blob and writes the JSON envelope.
func encrypt(args []string) error {
	flags := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	keyValue := flags.String("key", "", "oct JWK to encrypt with. a fresh key is generated when omitted")
	in := flags.String("in", "-", "file holding the blob to encrypt")
	out := flags.String("out", "-", "file to write the JSON envelope to")

	if err := flags.Parse(args); err != nil {
		return err
	}

	payload, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("failed to read payload: %w", err)
	}

	key, err := resolveKey(*keyValue)
	if err != nil {
		return err
	}

	compactJWE, err := jwe.Encrypt(payload, key)
	if err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(envelope{JWE: compactJWE, JWK: key}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	return writeOutput(*out, append(bytes, '\n'))
}

// decrypt decrypts a compact JWE and writes the recovered blob.
func decrypt(args []string) error {
	flags := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	keyValue := flags.String("key", "", "oct JWK to decrypt with: a file path or inline JSON")
	in := flags.String("in", "-", "file holding the compact JWE")
	out := flags.String("out", "-", "file to write the decrypted blob to")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if *keyValue == "" {
		return errors.New("-key is required")
	}

	key, err := readKey(*keyValue)
	if err != nil {
		return err
	}

	compactJWE, err := readCompactJWE(flags.Args(), *in)
	if err != nil {
		return err
	}

	decrypted, err := jwe.Decrypt(compactJWE, key)
	if err != nil {
		return err
	}

	return writeOutput(*out, decrypted.Payload)
}

// envelope is the JSON document encrypt writes: a compact JWE alongside the key that decrypts it.
type envelope struct {
	JWE string  `json:"jwe"`
	JWK jwk.JWK `json:"jwk"`
}

// readCompactJWE resolves the compact JWE from the positional arguments, falling back to the
// contents of the -in path.
func readCompactJWE(args []string, in string) (string, error) {
	if len(args) > 1 {
		return "", fmt.Errorf("expected at most one JWE argument, got %d", len(args))
	}

	if len(args) == 1 {
		return strings.TrimSpace(args[0]), nil
	}

	bytes, err := readInput(in)
	if err != nil {
		return "", fmt.Errorf("failed to read JWE: %w", err)
	}

	return strings.TrimSpace(string(bytes)), nil
}

// resolveKey returns the key to encrypt with, generating a fresh one when no value is given. The
// returned key always carries its thumbprint as `kid`, matching the one in the JWE header, so an
// envelope is self-describing.
func resolveKey(value string) (jwk.JWK, error) {
	var (
		key jwk.JWK
		err error
	)

	if value == "" {
		key, err = jwe.A256GCMGenerateKey()
	} else {
		key, err = readKey(value)
	}

	if err != nil {
		return jwk.JWK{}, err
	}

	key.KID, err = key.ComputeThumbprint()
	if err != nil {
		return jwk.JWK{}, err
	}

	return key, nil
}

// readKey parses an oct JWK from either inline JSON or the file at the provided path.
func readKey(value string) (jwk.JWK, error) {
	bytes := []byte(value)

	if !strings.HasPrefix(strings.TrimSpace(value), "{") {
		var err error

		bytes, err = os.ReadFile(value)
		if err != nil {
			return jwk.JWK{}, fmt.Errorf("failed to read key: %w", err)
		}
	}

	var key jwk.JWK
	if err := json.Unmarshal(bytes, &key); err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to parse key: %w", err)
	}

	if key.KTY == "" {
		var env envelope
		if json.Unmarshal(bytes, &env) == nil && env.JWK.KTY != "" {
			return jwk.JWK{}, errors.New("that looks like an encrypt envelope. pass just its `jwk` field")
		}

		return jwk.JWK{}, errors.New("key is missing `kty`")
	}

	return key, nil
}

// readInput reads the file at path, or stdin when path is `-`.
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}

	return os.ReadFile(path)
}

// writeOutput writes bytes to the file at path, or to stdout when path is `-`.
func writeOutput(path string, bytes []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(bytes)

		return err
	}

	return os.WriteFile(path, bytes, outputPerm)
}
