package entropy_test

import (
	"encoding/hex"
	"testing"

	"github.com/mistermoe/jose/entropy"

	"github.com/alecthomas/assert/v2"
)

func Test_GenerateEntropy(t *testing.T) {
	bytes, err := entropy.Generate(entropy.Size128)
	assert.NoError(t, err)
	assert.Equal(t, int(entropy.Size128), len(bytes))
}

func Test_GenerateEntropy_CustomSize(t *testing.T) {
	customSize := 99
	bytes, err := entropy.Generate(entropy.Size(customSize))
	assert.NoError(t, err)
	assert.Equal(t, customSize, len(bytes))
}

func Test_GenerateEntropy_InvalidSize(t *testing.T) {
	bytes, err := entropy.Generate(0)
	assert.Error(t, err)
	assert.Equal(t, nil, bytes)

	bytes, err = entropy.Generate(-1)
	assert.Error(t, err)
	assert.Equal(t, nil, bytes)
}

func Test_GenerateNonce(t *testing.T) {
	nonce, err := entropy.GenerateNonce(entropy.Size128)
	assert.NoError(t, err)
	assert.Equal(t, int(entropy.Size128)*2, len(nonce))

	_, err = hex.DecodeString(nonce)
	assert.NoError(t, err)
}

func Test_GenerateNonce_CustomSize(t *testing.T) {
	customSize := 99
	nonce, err := entropy.GenerateNonce(entropy.Size(99))
	assert.NoError(t, err)
	assert.Equal(t, customSize*2, len(nonce))

	_, err = hex.DecodeString(nonce)
	assert.NoError(t, err)
}

func Test_GenerateNonce_InvalidSize(t *testing.T) {
	nonce, err := entropy.GenerateNonce(0)
	assert.Error(t, err)
	assert.Equal(t, "", nonce)
}
