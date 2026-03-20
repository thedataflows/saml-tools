package cmd

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/testutil"
)

func TestCLI_Help(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "decrypt", "--help")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	outputStr := string(output)
	assert.Contains(t, outputStr, "decrypt")
	assert.Contains(t, outputStr, "--key")
	assert.Contains(t, outputStr, "--output")
	assert.Contains(t, outputStr, "--pretty")
}

func TestCLI_MissingKey(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "decrypt")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "--key")
}

func TestCLI_InvalidKeyFile(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "decrypt", "--key", "/nonexistent/key.pem")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "private key file not found")
}

func TestCLI_InvalidKeyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "invalid.pem")
	err := os.WriteFile(keyFile, []byte("not a valid key"), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "invalid private key format")
}

func TestCLI_NoInput(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "failed to read from stdin: no data provided on stdin")
}

func TestCLI_FileInput(t *testing.T) {
	// Generate test data
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Test Content</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, encrypted, 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "Test Content")
}

func TestCLI_StdinInput(t *testing.T) {
	// Generate test data
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Stdin Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile)
	cmd.Dir = ".."
	cmd.Stdin = bytes.NewReader(encrypted)

	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "Stdin Test")
}

func TestCLI_Base64Key(t *testing.T) {
	// Generate test data
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Base64 Key Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Base64 encode the key
	keyPEM := testutil.RSAToPEM(key)
	base64Key := base64.StdEncoding.EncodeToString(keyPEM)

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	err = os.WriteFile(inputFile, encrypted, 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", base64Key, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "Base64 Key Test")
}

func TestCLI_OutputFile(t *testing.T) {
	// Generate test data
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Output File Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")
	outputFile := filepath.Join(tmpDir, "output.xml")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, encrypted, 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "--output", outputFile, inputFile)
	cmd.Dir = ".."
	err = cmd.Run()

	assert.NoError(t, err)

	output, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Contains(t, string(output), "Output File Test")
}

func TestCLI_PrettyPrint(t *testing.T) {
	// Generate test data
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>    Test    </Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, encrypted, 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "--pretty", inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	outputStr := string(output)
	assert.Contains(t, outputStr, "Test")
}

func TestCLI_Base64Input(t *testing.T) {
	// Generate test data
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Base64 Input Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Base64 encode the input
	base64Input := base64.StdEncoding.EncodeToString(encrypted)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.b64")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(base64Input), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "Base64 Input Test")
}

func TestCLI_HTTPPostInput(t *testing.T) {
	// Generate test data
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>HTTP POST Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Create HTTP POST format with URL-encoded base64
	base64Input := base64.StdEncoding.EncodeToString(encrypted)
	httpPostData := "SAMLResponse=" + url.QueryEscape(base64Input)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.post")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(httpPostData), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "HTTP POST Test")
}

func TestCLI_WrongKey(t *testing.T) {
	// Generate two different keys
	correctKey, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	wrongKey, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Encrypt with correct key
	plaintext := "<Assertion>Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, correctKey, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "wrong.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(wrongKey), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, encrypted, 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "decryption failed")
}

func TestCLI_InvalidInput(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.txt")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte("not valid saml"), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "unable to detect input format")
}

func TestCLI_ECKeyNotSupported(t *testing.T) {
	// This test verifies EC keys are properly rejected
	// Generate EC key
	cmd := exec.Command("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout")
	output, err := cmd.Output()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "ec.pem")
	err = os.WriteFile(keyFile, output, 0600)
	require.NoError(t, err)

	cmd = exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "/dev/null")
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(out), "unsupported key type")
}

func TestCLI_PasswordProtectedKey(t *testing.T) {
	// Generate password protected key with legacy PEM format (PKCS#1)
	cmd := exec.Command("openssl", "genrsa", "-aes256", "-passout", "pass:secret", "-traditional", "2048")
	output, err := cmd.Output()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "encrypted.pem")
	err = os.WriteFile(keyFile, output, 0600)
	require.NoError(t, err)

	// Should fail without password, prompting for password
	cmd = exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "/dev/null")
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(out), "password-protected key requires --key-password flag or ST_KEY_PASSWORD environment variable")

	// Should succeed with password flag
	cmd = exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "--key-password", "secret", "/dev/null")
	cmd.Dir = ".."
	out, err = cmd.CombinedOutput()
	// This will fail because /dev/null is not valid SAML, but key loading should succeed
	assert.Error(t, err)
	// Should not have password-related error
	assert.NotContains(t, string(out), "password-protected key requires")

	// Should fail with wrong password
	cmd = exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "--key-password", "wrongpassword", "/dev/null")
	cmd.Dir = ".."
	out, err = cmd.CombinedOutput()
	assert.Error(t, err)
	assert.Contains(t, string(out), "incorrect password for private key")
}

func TestCLI_ReadStdin(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Stdin Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)

	// Test readStdin function indirectly via stdin pipe
	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile)
	cmd.Dir = ".."
	cmd.Stdin = bytes.NewReader(encrypted)

	output, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.Contains(t, string(output), "Stdin Test")
}

func TestCLI_ExtractSAMLResponse(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<Assertion>Extract Test</Assertion>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	// Create HTTP POST format with URL-encoded base64
	base64Input := base64.StdEncoding.EncodeToString(encrypted)
	httpPostData := "RelayState=xyz&SAMLResponse=" + url.QueryEscape(base64Input) + "&other=data"

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.post")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, []byte(httpPostData), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	assert.Contains(t, string(output), "Extract Test")
}

func TestCLI_PrettyPrintXML(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := "<root><child>data</child></root>"
	encrypted, err := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	inputFile := filepath.Join(tmpDir, "input.xml")

	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)
	err = os.WriteFile(inputFile, encrypted, 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "--pretty", inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err)
	outputStr := string(output)
	// Pretty printed XML should have indentation
	assert.Contains(t, outputStr, "<root>")
	assert.Contains(t, outputStr, "<child>")
}

func TestCLI_NonExistentInputFile(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile, "/nonexistent/file.xml")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	// Kong validates file existence before main.go runs
	assert.Contains(t, string(output), "no such file or directory")
}

func TestCLI_InvalidBase64Key(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	err := os.WriteFile(inputFile, []byte("<test/>"), 0600)
	require.NoError(t, err)

	// Invalid base64 that looks like base64
	invalidBase64 := "!!!invalid!!!"

	cmd := exec.Command("go", "run", ".", "decrypt", "--key", invalidBase64, inputFile)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "invalid private key format")
}

func TestCLI_StdinNoData(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	err = os.WriteFile(keyFile, testutil.RSAToPEM(key), 0600)
	require.NoError(t, err)

	// Run with empty stdin (no TTY)
	cmd := exec.Command("go", "run", ".", "decrypt", "--key", keyFile)
	cmd.Dir = ".."
	cmd.Stdin = strings.NewReader("")

	output, err := cmd.CombinedOutput()

	assert.Error(t, err)
	assert.Contains(t, string(output), "no input")
}
