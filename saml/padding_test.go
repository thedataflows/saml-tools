package saml_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/saml"
	"github.com/thedataflows/saml-tools/testutil"
)

func TestDecryptRSA_PKCS1_AES128_CBC_Padding(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})

	// Generate a fresh RSA key
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Test plaintext with various lengths to check padding
	plaintexts := []string{
		"A",                             // 1 byte - should have 15 padding bytes
		"Hello",                         // 5 bytes - should have 11 padding bytes
		"Test content",                  // 12 bytes - should have 4 padding bytes
		"Sixteen bytes!!!",              // 16 bytes - should have 16 padding bytes
		"This is a longer test message", // 29 bytes - should have 3 padding bytes
		"<Assertion>Test</Assertion>",   // XML-like content
		strings.Repeat("X", 100),        // Longer content
	}

	for i, plaintext := range plaintexts {
		t.Run(fmt.Sprintf("plaintext_%d_len_%d", i, len(plaintext)), func(t *testing.T) {
			// Encrypt with rsa-pkcs1 and aes128-cbc
			encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-pkcs1", "aes128-cbc")
			require.NoError(t, err)

			// Decrypt
			decrypted, err := decrypter.Decrypt(encrypted, key)
			require.NoError(t, err)

			// Verify the decrypted content matches original (with proper padding removal)
			assert.Equal(t, plaintext, string(decrypted),
				"Decrypted content should match original without padding")

			// Additional check: verify no extra padding bytes remain
			assert.False(t, bytes.HasSuffix(decrypted, []byte{byte(16)}),
				"Decrypted content should not have trailing padding bytes")
			assert.False(t, bytes.HasSuffix(decrypted, []byte{byte(15)}),
				"Decrypted content should not have trailing padding bytes")
			assert.False(t, bytes.HasSuffix(decrypted, []byte{byte(1)}),
				"Decrypted content should not have trailing padding bytes")
		})
	}
}
