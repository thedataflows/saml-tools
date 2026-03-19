package testutil

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRSAKey(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, 2048, key.Size()*8)

	// Verify it's a valid RSA key
	assert.NotNil(t, key.D)
	assert.NotNil(t, key.PublicKey.N)
}

func TestRSAToPEM(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	require.NoError(t, err)

	pemBytes := RSAToPEM(key)
	require.NotEmpty(t, pemBytes)

	// Verify it's valid PEM
	block, rest := pem.Decode(pemBytes)
	require.NotNil(t, block)
	assert.Empty(t, rest)
	assert.Equal(t, "RSA PRIVATE KEY", block.Type)
}

func TestRSAToPKCS8PEM(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	require.NoError(t, err)

	pemBytes, err := RSAToPKCS8PEM(key)
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	// Verify it's valid PKCS#8 PEM
	block, rest := pem.Decode(pemBytes)
	require.NotNil(t, block)
	assert.Empty(t, rest)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	// Verify it can be parsed
	key2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.NotNil(t, key2)
}

func TestGenerateEncryptedAssertion(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Test</Assertion>"

	tests := []struct {
		name          string
		keyTransport  string
		payloadCipher string
	}{
		{"AES128-CBC + RSA-OAEP", "rsa-oaep", "aes128-cbc"},
		{"AES256-CBC + RSA-OAEP", "rsa-oaep", "aes256-cbc"},
		{"AES128-GCM + RSA-OAEP", "rsa-oaep", "aes128-gcm"},
		{"AES256-GCM + RSA-OAEP", "rsa-oaep", "aes256-gcm"},
		{"AES128-CBC + RSA-PKCS1", "rsa-pkcs1", "aes128-cbc"},
		{"AES256-CBC + RSA-OAEP-SHA256", "rsa-oaep-sha256", "aes256-cbc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xml, err := GenerateEncryptedAssertion(plaintext, key, tt.keyTransport, tt.payloadCipher)
			require.NoError(t, err)
			assert.NotEmpty(t, xml)
			assert.Contains(t, string(xml), "EncryptedAssertion")
			assert.Contains(t, string(xml), "EncryptedData")
			assert.Contains(t, string(xml), "EncryptedKey")
		})
	}
}

func TestGenerateEncryptedAssertion_UnsupportedCipher(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	require.NoError(t, err)

	_, err = GenerateEncryptedAssertion("test", key, "unsupported", "aes128-cbc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key transport")

	_, err = GenerateEncryptedAssertion("test", key, "rsa-oaep", "unsupported")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported payload cipher")
}
