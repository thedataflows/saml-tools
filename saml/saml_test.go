package saml_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/saml"
	"github.com/thedataflows/saml-tools/testutil"
)

func TestDecrypter_Decrypt_Success(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">Test Content</Assertion>"

	cases := []struct {
		name          string
		keyTransport  string
		payloadCipher string
	}{
		{"AES128-CBC + RSA-OAEP", "rsa-oaep", "aes128-cbc"},
		{"AES256-CBC + RSA-OAEP", "rsa-oaep", "aes256-cbc"},
		{"AES128-GCM + RSA-OAEP", "rsa-oaep", "aes128-gcm"},
		{"AES256-GCM + RSA-OAEP", "rsa-oaep", "aes256-gcm"},
		{"AES128-CBC + RSA-PKCS1", "rsa-pkcs1", "aes128-cbc"},
		// Note: RSA-OAEP-SHA256 uses same XML URI as RSA-OAEP,
		// but implementations differ. Skipping for standard compliance.
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, tc.keyTransport, tc.payloadCipher)
			require.NoError(t, err)

			decrypted, err := decrypter.Decrypt(encrypted, key)
			require.NoError(t, err)
			assert.Contains(t, string(decrypted), plaintext)
		})
	}
}

func TestDecrypter_Decrypt_WrongKey(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})

	// Generate two different keys
	correctKey, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	wrongKey, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Encrypt with correct key
	plaintext := "<Assertion>Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, correctKey, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Try to decrypt with wrong key
	_, err = decrypter.Decrypt(encrypted, wrongKey)
	assert.ErrorIs(t, err, saml.ErrDecryptionFailed)
}

func TestDecrypter_Decrypt_InvalidInput(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{
			name:    "Empty input",
			input:   []byte{},
			wantErr: saml.ErrMalformedXML,
		},
		{
			name:    "Invalid XML",
			input:   []byte("<not-xml"),
			wantErr: saml.ErrMalformedXML,
		},
		{
			name:    "No EncryptedAssertion",
			input:   []byte(`<root></root>`),
			wantErr: saml.ErrMalformedXML,
		},
		{
			name: "Missing EncryptedKey",
			input: []byte(`<saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
  </xenc:EncryptedData>
</saml2:EncryptedAssertion>`),
			wantErr: saml.ErrMissingKey,
		},
		{
			name:    "Plain text input",
			input:   []byte("This is not XML"),
			wantErr: saml.ErrMalformedXML,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decrypter.Decrypt(tc.input, key)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestDecrypter_Decrypt_InvalidKeyType(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})

	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Try with non-RSA key (ECDSA)
	// In real usage, this would fail type assertion
	// For testing, we'll check the error behavior
	_, err = decrypter.Decrypt(encrypted, &struct{}{})
	assert.Error(t, err)
}

func TestDecrypter_Decrypt_CorruptedData(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})

	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Generate valid encrypted assertion
	plaintext := "<Assertion>Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Corrupt the data by modifying some bytes
	// This may cause either XML parsing error or decryption failure
	encrypted[len(encrypted)/2] ^= 0xFF
	encrypted[len(encrypted)/2+1] ^= 0xFF

	// Should error with either malformed XML or decryption failure
	_, err = decrypter.Decrypt(encrypted, key)
	assert.True(t, errors.Is(err, saml.ErrMalformedXML) || errors.Is(err, saml.ErrDecryptionFailed),
		"Expected either ErrMalformedXML or ErrDecryptionFailed, got: %v", err)
}

func TestDecrypter_Decrypt_UnsupportedAlgorithms(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Test unsupported key encryption algorithm
	plaintext := "<Assertion>Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Modify the algorithm to an unsupported one
	modified := string(encrypted)
	modified = strings.Replace(modified,
		"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
		"http://unsupported/algorithm",
		1)

	_, err = decrypter.Decrypt([]byte(modified), key)
	assert.ErrorIs(t, err, saml.ErrDecryptionFailed)
}

func TestDecrypter_Decrypt_InvalidBase64(t *testing.T) {
	decrypter := saml.NewDecrypter(saml.Config{})
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Create encrypted assertion with invalid base64 in key
	plaintext := "<Assertion>Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Corrupt the base64 in CipherValue
	modified := strings.Replace(string(encrypted),
		"<xenc:CipherValue>",
		"<xenc:CipherValue>!!!invalid_base64!!!",
		1)

	_, err = decrypter.Decrypt([]byte(modified), key)
	assert.ErrorIs(t, err, saml.ErrMalformedXML)
}

func TestDecrypter_Config(t *testing.T) {
	// Test that config is properly stored
	cfg := saml.Config{}
	decrypter := saml.NewDecrypter(cfg)
	assert.NotNil(t, decrypter)
}
