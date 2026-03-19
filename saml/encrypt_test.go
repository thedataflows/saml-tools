package saml_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/saml-tools/saml"
	"github.com/thedataflows/saml-tools/testutil"
)

func TestEncrypter_Encrypt_DefaultOptions(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>`

	encrypter := saml.NewEncrypter()
	opts := saml.EncryptOptions{
		TargetNode:    "saml:Assertion",
		KeyTransport:  "rsa-oaep",
		PayloadCipher: "aes128-cbc",
	}

	encrypted, err := encrypter.Encrypt([]byte(plaintext), &key.PublicKey, opts)
	require.NoError(t, err)

	// Verify it's valid XML with EncryptedAssertion
	encryptedStr := string(encrypted)
	assert.Contains(t, encryptedStr, "EncryptedAssertion")
	assert.Contains(t, encryptedStr, "EncryptedData")
	assert.Contains(t, encryptedStr, "CipherValue")

	// Verify it can be decrypted
	decrypter := saml.NewDecrypter(saml.Config{})
	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)

	// Verify the decrypted content contains original assertion data
	decryptedStr := string(decrypted)
	assert.Contains(t, decryptedStr, "user@example.com")
	assert.Contains(t, decryptedStr, "saml:Assertion")
}

func TestEncrypter_Encrypt_AllAlgorithms(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>test@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>`

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
		{"AES256-CBC + RSA-PKCS1", "rsa-pkcs1", "aes256-cbc"},
		{"AES128-GCM + RSA-PKCS1", "rsa-pkcs1", "aes128-gcm"},
		{"AES256-GCM + RSA-PKCS1", "rsa-pkcs1", "aes256-gcm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(testT *testing.T) {
			encrypter := saml.NewEncrypter()
			opts := saml.EncryptOptions{
				TargetNode:    "saml:Assertion",
				KeyTransport:  tt.keyTransport,
				PayloadCipher: tt.payloadCipher,
			}

			encrypted, err := encrypter.Encrypt([]byte(plaintext), &key.PublicKey, opts)
			require.NoError(testT, err)

			// Verify it can be decrypted
			decrypter := saml.NewDecrypter(saml.Config{})
			decrypted, err := decrypter.Decrypt(encrypted, key)
			require.NoError(testT, err)

			// Verify the content
			assert.Contains(testT, string(decrypted), "test@example.com")
		})
	}
}

func TestEncrypter_Encrypt_WithCertificate(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Generate a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</saml:Assertion>`

	encrypter := saml.NewEncrypter()
	opts := saml.EncryptOptions{
		TargetNode:    "saml:Assertion",
		KeyTransport:  "rsa-oaep",
		PayloadCipher: "aes128-cbc",
		Certificate:   cert,
	}

	encrypted, err := encrypter.Encrypt([]byte(plaintext), &key.PublicKey, opts)
	require.NoError(t, err)

	// Verify certificate is included
	encryptedStr := string(encrypted)
	assert.Contains(t, encryptedStr, "X509Certificate")
	assert.Contains(t, encryptedStr, "X509Data")

	// Verify it can be decrypted
	decrypter := saml.NewDecrypter(saml.Config{})
	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), "idp.example.com")
}

func TestEncrypter_Encrypt_InvalidOptions(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test">Test</saml:Assertion>`

	tests := []struct {
		name    string
		opts    saml.EncryptOptions
		wantErr string
	}{
		{
			name: "nil public key",
			opts: saml.EncryptOptions{
				TargetNode:    "saml:Assertion",
				KeyTransport:  "rsa-oaep",
				PayloadCipher: "aes128-cbc",
			},
			wantErr: "public key is nil",
		},
		{
			name: "unsupported cipher",
			opts: saml.EncryptOptions{
				TargetNode:    "saml:Assertion",
				KeyTransport:  "rsa-oaep",
				PayloadCipher: "aes-999",
			},
			wantErr: "unsupported cipher",
		},
		{
			name: "unsupported key transport",
			opts: saml.EncryptOptions{
				TargetNode:    "saml:Assertion",
				KeyTransport:  "invalid",
				PayloadCipher: "aes128-cbc",
			},
			wantErr: "unsupported key transport",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(testT *testing.T) {
			encrypter := saml.NewEncrypter()
			var pubKey *rsa.PublicKey
			if tt.name != "nil public key" {
				pubKey = &key.PublicKey
			}

			_, err := encrypter.Encrypt([]byte(plaintext), pubKey, tt.opts)
			assert.Error(testT, err)
			assert.Contains(testT, err.Error(), tt.wantErr)
		})
	}
}

func TestEncrypter_Encrypt_InvalidXML(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext string
		wantErr   string
	}{
		{
			name:      "invalid XML",
			plaintext: "not valid xml",
			wantErr:   "malformed XML",
		},
		{
			name:      "missing assertion",
			plaintext: "<root><child>test</child></root>",
			wantErr:   "target node",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(testT *testing.T) {
			encrypter := saml.NewEncrypter()
			opts := saml.EncryptOptions{
				TargetNode:    "saml:Assertion",
				KeyTransport:  "rsa-oaep",
				PayloadCipher: "aes128-cbc",
			}

			_, err := encrypter.Encrypt([]byte(tt.plaintext), &key.PublicKey, opts)
			assert.Error(testT, err)
			assert.Contains(testT, err.Error(), tt.wantErr)
		})
	}
}

func TestEncrypter_Encrypt_WrapInResponse(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Input without Response wrapper
	plaintext := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</saml:Assertion>`

	encrypter := saml.NewEncrypter()
	opts := saml.EncryptOptions{
		TargetNode:    "saml:Assertion",
		KeyTransport:  "rsa-oaep",
		PayloadCipher: "aes128-cbc",
	}

	encrypted, err := encrypter.Encrypt([]byte(plaintext), &key.PublicKey, opts)
	require.NoError(t, err)

	// Verify it wrapped in Response
	encryptedStr := string(encrypted)
	assert.Contains(t, encryptedStr, "samlp:Response")
	assert.Contains(t, encryptedStr, "samlp:Status")
	assert.Contains(t, encryptedStr, "StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"")

	// Verify it can be decrypted
	decrypter := saml.NewDecrypter(saml.Config{})
	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), "idp.example.com")
}

func TestEncrypter_Encrypt_AlreadyInResponse(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Input already wrapped in Response
	plaintext := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`

	encrypter := saml.NewEncrypter()
	opts := saml.EncryptOptions{
		TargetNode:    "saml:Assertion",
		KeyTransport:  "rsa-oaep",
		PayloadCipher: "aes128-cbc",
	}

	encrypted, err := encrypter.Encrypt([]byte(plaintext), &key.PublicKey, opts)
	require.NoError(t, err)

	// Verify Response structure is preserved
	encryptedStr := string(encrypted)
	assert.Contains(t, encryptedStr, "samlp:Response")
	assert.Contains(t, encryptedStr, "saml:Issuer>https://idp.example.com")

	// Verify assertion is encrypted
	assert.Contains(t, encryptedStr, "saml:EncryptedAssertion")
	assert.NotContains(t, encryptedStr, "<saml:Assertion ID=")

	// Verify it can be decrypted
	decrypter := saml.NewDecrypter(saml.Config{})
	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), "user@example.com")
}

func TestEncrypter_Encrypt_TargetNodeOption(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	plaintext := `<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion ID="_test">Test Content</saml:Assertion>
</root>`

	encrypter := saml.NewEncrypter()
	opts := saml.EncryptOptions{
		TargetNode:    "saml:Assertion",
		KeyTransport:  "rsa-oaep",
		PayloadCipher: "aes128-cbc",
	}

	encrypted, err := encrypter.Encrypt([]byte(plaintext), &key.PublicKey, opts)
	require.NoError(t, err)

	// Verify encryption
	assert.Contains(t, string(encrypted), "saml:EncryptedAssertion")

	// Verify decryption
	decrypter := saml.NewDecrypter(saml.Config{})
	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Contains(t, string(decrypted), "Test Content")
}

func TestEncrypter_RoundTrip(t *testing.T) {
	key, err := testutil.GenerateRSAKey(2048)
	require.NoError(t, err)

	// Complex assertion with multiple elements
	plaintext := `<?xml version="1.0" encoding="UTF-8"?>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a75adf55-01d7-40cc-929f-dbd8372ebdfc" IssueInstant="2024-01-15T10:30:00Z" Version="2.0">
  <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="2024-01-15T10:35:00Z" Recipient="https://sp.example.com/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2024-01-15T10:25:00Z" NotOnOrAfter="2024-01-15T10:35:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com/metadata</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
</saml:Assertion>`

	encrypter := saml.NewEncrypter()
	encOpts := saml.EncryptOptions{
		TargetNode:    "saml:Assertion",
		PayloadCipher: "aes256-gcm",
		KeyTransport:  "rsa-oaep",
	}

	// Encrypt
	encrypted, err := encrypter.Encrypt([]byte(plaintext), &key.PublicKey, encOpts)
	require.NoError(t, err)

	// Decrypt
	decrypter := saml.NewDecrypter(saml.Config{})
	decrypted, err := decrypter.Decrypt(encrypted, key)
	require.NoError(t, err)

	// Verify all original content is present
	decryptedStr := string(decrypted)
	assert.Contains(t, decryptedStr, "user@example.com")
	assert.Contains(t, decryptedStr, "https://idp.example.com/metadata")
	assert.Contains(t, decryptedStr, "https://sp.example.com/metadata")
	assert.Contains(t, decryptedStr, "urn:oasis:names:tc:SAML:2.0:cm:bearer")
}
