package cmd_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCertificate(t *testing.T) (*rsa.PrivateKey, []byte) {
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

	return privateKey, certPEM
}

func generateTestPublicKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return privateKey, pubKeyPEM
}

func TestCLI_Encrypt_Help(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "encrypt", "--help")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	outputStr := string(output)
	assert.Contains(t, outputStr, "encrypt")
	assert.Contains(t, outputStr, "--key")
	assert.Contains(t, outputStr, "--output")
	assert.Contains(t, outputStr, "--algorithm")
	assert.Contains(t, outputStr, "--cipher")
	assert.Contains(t, outputStr, "--include-cert")
}

func TestCLI_Encrypt_MissingKey(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "encrypt")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "--key")
}

func TestCLI_Encrypt_InvalidKeyFile(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "encrypt", "--key", "/nonexistent/key.pem")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "public key")
}

func TestCLI_Encrypt_InvalidKeyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "invalid.pem")
	err := os.WriteFile(keyFile, []byte("not a valid key"), 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", keyFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "invalid public key")
}

func TestCLI_Encrypt_NoInput(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "no data provided")
}

func TestCLI_Encrypt_FileInput(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>`

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(plaintext), 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	outputStr := string(output)
	assert.Contains(t, outputStr, "EncryptedAssertion")
	assert.Contains(t, outputStr, "CipherValue")
	assert.Contains(t, outputStr, "samlp:Response")
}

func TestCLI_Encrypt_StdinInput(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</saml:Assertion>`

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile)
	cmd.Dir = ".."
	cmd.Stdin = bytes.NewReader([]byte(plaintext))

	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "EncryptedAssertion")
}

func TestCLI_Encrypt_Base64Key(t *testing.T) {
	_, certPEM := generateTestCertificate(t)
	base64Cert := base64.StdEncoding.EncodeToString(certPEM)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test">Test</saml:Assertion>`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	err := os.WriteFile(inputFile, []byte(plaintext), 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", base64Cert, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "EncryptedAssertion")
}

func TestCLI_Encrypt_OutputFile(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test">Test</saml:Assertion>`

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")
	outputFile := filepath.Join(tmpDir, "output.xml")

	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(plaintext), 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile, "--output", outputFile, inputFile)
	cmd.Dir = ".."
	err = cmd.Run()

	assert.NoError(t, err)

	output, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Contains(t, string(output), "EncryptedAssertion")
}

func TestCLI_Encrypt_Pretty(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test">Test</saml:Assertion>`

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(plaintext), 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile, "--pretty", inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	outputStr := string(output)
	// Pretty printed should have indentation
	assert.Contains(t, outputStr, "  <")
}

func TestCLI_Encrypt_WithPublicKey(t *testing.T) {
	_, pubKeyPEM := generateTestPublicKey(t)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test">Test</saml:Assertion>`

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err := os.WriteFile(keyFile, pubKeyPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(plaintext), 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", keyFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "EncryptedAssertion")
	// Raw public key should not include X509Certificate
	assert.NotContains(t, string(output), "X509Certificate")
}

func TestCLI_Encrypt_AllAlgorithms(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test">Test</saml:Assertion>`

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(plaintext), 0644)
	require.NoError(t, err)

	tests := []struct {
		algorithm string
		cipher    string
	}{
		{"rsa-oaep", "aes128-cbc"},
		{"rsa-oaep", "aes256-cbc"},
		{"rsa-oaep", "aes128-gcm"},
		{"rsa-oaep", "aes256-gcm"},
		{"rsa-pkcs1", "aes128-cbc"},
		{"rsa-pkcs1", "aes256-cbc"},
		{"rsa-pkcs1", "aes128-gcm"},
		{"rsa-pkcs1", "aes256-gcm"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm+"_"+tt.cipher, func(t *testing.T) {
			cmd := exec.Command("go", "run", ".", "encrypt",
				"--key", certFile,
				"--algorithm", tt.algorithm,
				"--cipher", tt.cipher,
				inputFile)
			cmd.Dir = ".."
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err)
			assert.Contains(t, string(output), "EncryptedAssertion")
		})
	}
}

func TestCLI_Encrypt_RoundTrip(t *testing.T) {
	privateKey, certPEM := generateTestCertificate(t)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>`

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	privKeyFile := filepath.Join(tmpDir, "private.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")
	encryptedFile := filepath.Join(tmpDir, "encrypted.xml")

	// Write files
	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = os.WriteFile(privKeyFile, privKeyPEM, 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(plaintext), 0644)
	require.NoError(t, err)

	// Encrypt
	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile, "--output", encryptedFile, inputFile)
	cmd.Dir = ".."
	err = cmd.Run()
	require.NoError(t, err)

	// Decrypt
	cmd = exec.Command("go", "run", ".", "decrypt", "--key", privKeyFile, encryptedFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "user@example.com")
	assert.Contains(t, string(output), "saml:Assertion")
}

func TestCLI_Encrypt_InvalidInput(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	inputFile := filepath.Join(tmpDir, "input.txt")

	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte("not valid xml"), 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "malformed XML")
}

func TestCLI_Encrypt_NonExistentInputFile(t *testing.T) {
	_, certPEM := generateTestCertificate(t)

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	err := os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "encrypt", "--key", certFile, "/nonexistent/file.xml")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "no such file")
}
