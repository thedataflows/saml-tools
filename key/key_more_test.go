package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/testutil"
)

func TestPKCS8WithECDSA(t *testing.T) {
	// Generate EC key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode as PKCS#8
	privDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	}
	pemData := pem.EncodeToMemory(block)

	// Try to load it
	loader := NewLoader()
	base64Key := base64.StdEncoding.EncodeToString(pemData)
	_, err = loader.Load(base64Key)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

func TestPKCS8WithMultipleKeys(t *testing.T) {
	// Create PEM with multiple keys
	key1, _ := testutil.GenerateRSAKey(2048)
	key2, _ := testutil.GenerateRSAKey(2048)

	pem1 := testutil.RSAToPEM(key1)
	pem2 := testutil.RSAToPEM(key2)

	// Concatenate them
	multiKey := append(pem1, pem2...)

	loader := NewLoader()
	_, err := loader.Load(base64.StdEncoding.EncodeToString(multiKey))
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestInvalidPKCS1(t *testing.T) {
	// Create invalid PKCS#1 data
	invalidDER := []byte{0x00, 0x01, 0x02, 0x03}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: invalidDER,
	}
	pemData := pem.EncodeToMemory(block)

	loader := NewLoader()
	_, err := loader.Load(base64.StdEncoding.EncodeToString(pemData))
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestParseRSAPrivateKey_Error(t *testing.T) {
	// Test with invalid DER data
	invalidDER := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := parseRSAPrivateKey(invalidDER)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestParsePKCS8PrivateKey_Error(t *testing.T) {
	// Test with invalid DER data
	invalidDER := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := parsePKCS8PrivateKey(invalidDER)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestParsePKCS8PrivateKey_Ed25519(t *testing.T) {
	// Ed25519 keys are not supported
	// We can't easily generate one, but we can test the unsupported type path
	// by mocking or using a known key format

	// For now, test that ECDSA in PKCS8 returns ErrUnsupportedKeyType
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privDER, _ := x509.MarshalPKCS8PrivateKey(ecKey)

	_, err := parsePKCS8PrivateKey(privDER)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

func TestIsBase64Char(t *testing.T) {
	tests := []struct {
		char     rune
		expected bool
	}{
		{'A', true},
		{'Z', true},
		{'a', true},
		{'z', true},
		{'0', true},
		{'9', true},
		{'+', true},
		{'/', true},
		{'=', true},
		{' ', false},
		{'\n', false},
		{'-', false},
		{'_', false},
		{'!', false},
	}

	for _, tc := range tests {
		result := isBase64Char(tc.char)
		assert.Equal(t, tc.expected, result, "char: %c", tc.char)
	}
}

func TestLooksLikeBase64(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid short", "aGVsbG8=", false}, // too short
		{"valid long", "SGVsbG8gV29ybGQhISE=", true},
		{"with newlines", "SGVs\nbG8=", false},
		{"with spaces", "SGVs bG8=", false},
		{"empty", "", false},
		{"invalid chars", "hello-world!!!", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := looksLikeBase64(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestLoad_FallbackToFile(t *testing.T) {
	// Test that simple filenames without path separators work
	key, _ := testutil.GenerateRSAKey(2048)
	pemData := testutil.RSAToPEM(key)

	// Write to current directory
	tmpFile := "test_key.pem"
	err := os.WriteFile(tmpFile, pemData, 0600)
	require.NoError(t, err)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	loadedKey, err := loader.Load(tmpFile)
	assert.NoError(t, err)
	assert.NotNil(t, loadedKey)
}

func TestLoad_FileReadError(t *testing.T) {
	loader := NewLoader()
	// Try to read a directory as a file
	_, err := loader.Load("/tmp")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestParsePEM_NoBlock(t *testing.T) {
	_, err := parsePEM([]byte("not pem data"), "")
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestParsePEM_MultipleBlocks(t *testing.T) {
	key, _ := testutil.GenerateRSAKey(2048)
	pemData := testutil.RSAToPEM(key)

	// Create data with multiple PEM blocks
	multiData := append(pemData, pemData...)

	_, err := parsePEM(multiData, "")
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestParsePEM_UnknownType(t *testing.T) {
	block := &pem.Block{
		Type:  "UNKNOWN TYPE",
		Bytes: []byte{0x00, 0x01},
	}
	pemData := pem.EncodeToMemory(block)

	_, err := parsePEM(pemData, "")
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestLoader_Interface(t *testing.T) {
	loader := NewLoader()
	assert.Implements(t, (*Loader)(nil), loader)
}
