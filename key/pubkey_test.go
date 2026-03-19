package key_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/key"
)

func generateTestCertificate(t *testing.T) (*rsa.PrivateKey, []byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return privateKey, certDER, certPEM
}

func generateTestPublicKey(t *testing.T) (*rsa.PrivateKey, []byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return privateKey, pubKeyDER, pubKeyPEM
}

func TestPublicKeyLoader_LoadPublicKey_FromCertificateFile(t *testing.T) {
	_, _, certPEM := generateTestCertificate(t)

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test.crt")
	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(certFile)

	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.NotNil(t, cert)
	assert.Equal(t, 2048, pubKey.N.BitLen())
}

func TestPublicKeyLoader_LoadPublicKey_FromPublicKeyFile(t *testing.T) {
	_, _, pubKeyPEM := generateTestPublicKey(t)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.pub")
	err := os.WriteFile(keyFile, pubKeyPEM, 0644)
	require.NoError(t, err)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(keyFile)

	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Nil(t, cert) // No certificate when loading raw public key
	assert.Equal(t, 2048, pubKey.N.BitLen())
}

func TestPublicKeyLoader_LoadPublicKey_FromBase64Certificate(t *testing.T) {
	_, _, certPEM := generateTestCertificate(t)
	base64Cert := base64.StdEncoding.EncodeToString(certPEM)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(base64Cert)

	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.NotNil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_FromBase64PublicKey(t *testing.T) {
	_, _, pubKeyPEM := generateTestPublicKey(t)
	base64Key := base64.StdEncoding.EncodeToString(pubKeyPEM)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(base64Key)

	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Nil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_EmptyInput(t *testing.T) {
	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey("")

	assert.ErrorIs(t, err, key.ErrEmptyPublicKey)
	assert.Nil(t, pubKey)
	assert.Nil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_FileNotFound(t *testing.T) {
	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey("/nonexistent/path/to/key.pem")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
	assert.Nil(t, pubKey)
	assert.Nil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.pem")
	err := os.WriteFile(invalidFile, []byte("not a valid pem"), 0644)
	require.NoError(t, err)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(invalidFile)

	assert.ErrorIs(t, err, key.ErrInvalidPublicKey)
	assert.Nil(t, pubKey)
	assert.Nil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_InvalidBase64(t *testing.T) {
	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey("!!!invalid!!!")

	assert.ErrorIs(t, err, key.ErrInvalidPublicKey)
	assert.Nil(t, pubKey)
	assert.Nil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_MultiplePEMBlocks(t *testing.T) {
	_, _, certPEM := generateTestCertificate(t)
	_, _, pubKeyPEM := generateTestPublicKey(t)

	// Concatenate two PEM blocks
	combined := append(certPEM, pubKeyPEM...)

	tmpDir := t.TempDir()
	multiFile := filepath.Join(tmpDir, "multi.pem")
	err := os.WriteFile(multiFile, combined, 0644)
	require.NoError(t, err)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(multiFile)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple PEM blocks")
	assert.Nil(t, pubKey)
	assert.Nil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_DERFormat(t *testing.T) {
	_, certDER, _ := generateTestCertificate(t)

	tmpDir := t.TempDir()
	derFile := filepath.Join(tmpDir, "test.der")
	err := os.WriteFile(derFile, certDER, 0644)
	require.NoError(t, err)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(derFile)

	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.NotNil(t, cert)
}

func TestPublicKeyLoader_LoadPublicKey_VariousExtensions(t *testing.T) {
	_, _, certPEM := generateTestCertificate(t)

	extensions := []string{"test.pem", "test.cert", "test.crt", "test.der"}

	for _, ext := range extensions {
		t.Run(ext, func(t *testing.T) {
			tmpDir := t.TempDir()
			certFile := filepath.Join(tmpDir, ext)
			err := os.WriteFile(certFile, certPEM, 0644)
			require.NoError(t, err)

			loader := key.NewPublicKeyLoader()
			pubKey, cert, err := loader.LoadPublicKey(certFile)

			assert.NoError(t, err)
			assert.NotNil(t, pubKey)
			assert.NotNil(t, cert)
		})
	}
}

func TestPublicKeyLoader_LoadPublicKey_PKCS1Format(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create PKCS#1 format public key
	pubKeyDER := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "pkcs1.pub")
	err = os.WriteFile(keyFile, pubKeyPEM, 0644)
	require.NoError(t, err)

	loader := key.NewPublicKeyLoader()
	pubKey, cert, err := loader.LoadPublicKey(keyFile)

	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Nil(t, cert)
	assert.Equal(t, 2048, pubKey.N.BitLen())
}
