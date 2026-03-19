package key_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/key"
	"github.com/thedataflows/saml-tools/testutil"
)

func TestLoader_Load_PEMFile(t *testing.T) {
	loader := key.NewLoader()

	// Create temp file with RSA key
	keyPair, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	pemBytes := testutil.RSAToPEM(keyPair)
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.pem")
	err = os.WriteFile(keyFile, pemBytes, 0600)
	require.NoError(t, err)

	// Test loading from file
	loadedKey, err := loader.Load(keyFile)
	require.NoError(t, err)
	require.NotNil(t, loadedKey)

	rsaKey, ok := loadedKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.D, rsaKey.D)
}

func TestLoader_Load_PKCS8PEMFile(t *testing.T) {
	loader := key.NewLoader()

	keyPair, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	pemBytes, err := testutil.RSAToPKCS8PEM(keyPair)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.pem")
	err = os.WriteFile(keyFile, pemBytes, 0600)
	require.NoError(t, err)

	loadedKey, err := loader.Load(keyFile)
	require.NoError(t, err)
	require.NotNil(t, loadedKey)

	rsaKey, ok := loadedKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.D, rsaKey.D)
}

func TestLoader_Load_Base64String(t *testing.T) {
	loader := key.NewLoader()

	keyPair, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	pemBytes := testutil.RSAToPEM(keyPair)
	base64Key := base64.StdEncoding.EncodeToString(pemBytes)

	loadedKey, err := loader.Load(base64Key)
	require.NoError(t, err)
	require.NotNil(t, loadedKey)

	rsaKey, ok := loadedKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, keyPair.D, rsaKey.D)
}

func TestLoader_Load_UnsupportedKeyType(t *testing.T) {
	loader := key.NewLoader()

	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	privBlock := pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	pemBytes := pem.EncodeToMemory(&privBlock)

	base64Key := base64.StdEncoding.EncodeToString(pemBytes)

	_, err = loader.Load(base64Key)
	assert.ErrorIs(t, err, key.ErrUnsupportedKeyType)
}

func TestLoader_Load_PasswordProtected(t *testing.T) {
	loader := key.NewLoader()

	// Create a password-protected PEM
	keyPair, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	privDER := x509.MarshalPKCS1PrivateKey(keyPair)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
		Bytes:   privDER,
	}
	pemBytes := pem.EncodeToMemory(&privBlock)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "encrypted.pem")
	err = os.WriteFile(keyFile, pemBytes, 0600)
	require.NoError(t, err)

	_, err = loader.Load(keyFile)
	assert.ErrorIs(t, err, key.ErrPasswordProtected)
}

func TestLoader_Load_InvalidPEM(t *testing.T) {
	loader := key.NewLoader()

	_, err := loader.Load("not-valid-pem-content")
	assert.ErrorIs(t, err, key.ErrInvalidKey)
}

func TestLoader_Load_Empty(t *testing.T) {
	loader := key.NewLoader()

	_, err := loader.Load("")
	assert.ErrorIs(t, err, key.ErrEmptyKey)
}

func TestLoader_Load_FileNotFound(t *testing.T) {
	loader := key.NewLoader()

	_, err := loader.Load("/nonexistent/path/to/key.pem")
	assert.ErrorIs(t, err, key.ErrKeyNotFound)
}

func TestLoader_Load_Directory(t *testing.T) {
	loader := key.NewLoader()

	tmpDir := t.TempDir()
	_, err := loader.Load(tmpDir)
	assert.ErrorIs(t, err, key.ErrInvalidKey)
}

func TestLoader_Load_InvalidBase64(t *testing.T) {
	loader := key.NewLoader()

	// Valid base64 but invalid PEM content
	_, err := loader.Load(base64.StdEncoding.EncodeToString([]byte("not a pem")))
	assert.ErrorIs(t, err, key.ErrInvalidKey)
}

func TestLoader_Load_InvalidPEMInFile(t *testing.T) {
	loader := key.NewLoader()

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "invalid.pem")
	err := os.WriteFile(keyFile, []byte("not-valid-pem"), 0600)
	require.NoError(t, err)

	_, err = loader.Load(keyFile)
	assert.ErrorIs(t, err, key.ErrInvalidKey)
}
