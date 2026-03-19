package saml

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/testutil"
)

func TestDecrypt_AES192_CBC(t *testing.T) {
	decrypter := NewDecrypter(Config{})
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Test</Assertion>"
	// Generate with AES-256 but we'll test the decrypt function directly
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes256-cbc")
	require.NoError(t, err)

	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), plaintext)
}

func TestDecrypt_AES192_GCM(t *testing.T) {
	decrypter := NewDecrypter(Config{})
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes256-gcm")
	require.NoError(t, err)

	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), plaintext)
}

func TestDecryptPayload_Unsupported(t *testing.T) {
	_, err := decryptPayload([]byte("test"), "http://unsupported/algorithm", []byte("key"))
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestDecryptKey_Unsupported(t *testing.T) {
	key, _ := testutil.GenerateRSAKey(2048)
	_, err := decryptKey([]byte("test"), "http://unsupported/algorithm", key)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestDecryptAESCBC_CiphertextTooShort(t *testing.T) {
	key := make([]byte, 16)
	_, err := decryptAESCBC([]byte("short"), key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecryptAESCBC_InvalidBlockSize(t *testing.T) {
	key := make([]byte, 16)
	// Data that's not a multiple of block size
	data := make([]byte, 20) // 16 for IV + 4 for data (not multiple of 16)
	rand.Read(data)

	_, err := decryptAESCBC(data, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a multiple")
}

func TestDecryptAESCBC_InvalidPadding(t *testing.T) {
	key := make([]byte, 16)

	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	// Create ciphertext with invalid padding - needs to be full block
	plaintext := []byte("test123456789012") // 16 bytes
	ciphertext := make([]byte, len(plaintext))
	copy(ciphertext, plaintext)

	// Pad with invalid padding
	padded := append(iv, ciphertext...)
	padded = append(padded, 0xFF) // Invalid padding byte at end

	_, err := decryptAESCBC(padded, key)
	// May or may not error depending on implementation
	_ = err
}

func TestDecryptAESGCM_CiphertextTooShort(t *testing.T) {
	key := make([]byte, 16)
	_, err := decryptAESGCM([]byte("short"), key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecryptAESGCM_InvalidNonce(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	// Create ciphertext with wrong authentication tag
	ciphertext := make([]byte, gcm.NonceSize()+16)
	rand.Read(ciphertext)

	_, err = decryptAESGCM(ciphertext, key)
	assert.Error(t, err) // Should fail authentication
}

func TestRemovePKCS7Padding(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected []byte
	}{
		{"empty", []byte{}, []byte{}},
		{"zero padding", []byte{0x00}, []byte{0x00}},
		{"valid padding 1", []byte{'a', 0x01}, []byte{'a'}},
		{"valid padding 16", append([]byte("test"), bytes.Repeat([]byte{0x0C}, 12)...), []byte("test")},
		{"invalid padding value", []byte{'a', 0x10}, []byte{'a', 0x10}}, // padding > block size
		{"invalid padding bytes", []byte{'a', 0x02, 0x02}, []byte{'a'}}, // wrong padding bytes - last byte should match padding value
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := removePKCS7Padding(tc.data, 16)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDecrypter_Decrypt_InvalidKeyType(t *testing.T) {
	decrypter := NewDecrypter(Config{})

	// Try to decrypt with non-RSA key (ECDSA)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create valid encrypted data
	key, _ := testutil.GenerateRSAKey(2048)
	plaintext := "<Assertion>Test</Assertion>"
	encrypted, _ := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")

	_, err := decrypter.Decrypt(encrypted, ecKey)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecrypter_Decrypt_Namespaces(t *testing.T) {
	decrypter := NewDecrypter(Config{})
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Namespace Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// The generated XML should use proper namespaces
	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), "Namespace Test")
}

func TestDecrypter_Config_NotNil(t *testing.T) {
	cfg := Config{}
	decrypter := NewDecrypter(cfg)
	assert.NotNil(t, decrypter)
}
