package key_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thedataflows/saml-tools/key"
)

func FuzzLoadKey(f *testing.F) {
	// Seed with valid and invalid inputs
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"))
	f.Add([]byte("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ=="))
	f.Add([]byte("not-valid-pem"))
	f.Add([]byte(""))
	f.Add([]byte{0x00, 0x01, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic, always return error or success
		loader := key.NewLoader()
		loader.Load(string(data))
	})
}

func TestLoader_Load_ShortBase64(t *testing.T) {
	loader := key.NewLoader()

	// Short strings that look like base64 but are too short
	_, err := loader.Load("aGVsbG8=")
	assert.ErrorIs(t, err, key.ErrInvalidKey)
}

func TestLoader_Load_PathWithSpecialChars(t *testing.T) {
	loader := key.NewLoader()

	// Path that contains dot but doesn't exist
	_, err := loader.Load("./key.pem")
	assert.ErrorIs(t, err, key.ErrKeyNotFound)
}
