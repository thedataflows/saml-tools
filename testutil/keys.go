package testutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
)

// GenerateRSAKey creates a deterministic RSA key for testing.
// In production, use crypto/rand without seeding for true randomness.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// RSAToPEM exports an RSA private key to PEM format
func RSAToPEM(key *rsa.PrivateKey) []byte {
	privDER := x509.MarshalPKCS1PrivateKey(key)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	return pem.EncodeToMemory(&privBlock)
}

// RSAToPKCS8PEM exports an RSA private key to PKCS#8 PEM format
func RSAToPKCS8PEM(key *rsa.PrivateKey) ([]byte, error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	privBlock := pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	return pem.EncodeToMemory(&privBlock), nil
}

// GenerateEncryptedAssertion creates an encrypted SAML assertion.
// This is a simplified version for testing purposes.
func GenerateEncryptedAssertion(
	plaintext string,
	key *rsa.PrivateKey,
	keyTransport string,
	payloadCipher string,
) ([]byte, error) {
	// Generate a random symmetric key
	var symKey []byte
	var cipherURI string

	switch payloadCipher {
	case "aes128-cbc":
		symKey = make([]byte, 16)
		cipherURI = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	case "aes256-cbc":
		symKey = make([]byte, 32)
		cipherURI = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	case "aes128-gcm":
		symKey = make([]byte, 16)
		cipherURI = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	case "aes256-gcm":
		symKey = make([]byte, 32)
		cipherURI = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	default:
		return nil, fmt.Errorf("unsupported payload cipher: %s", payloadCipher)
	}

	if _, err := io.ReadFull(rand.Reader, symKey); err != nil {
		return nil, err
	}

	// Encrypt the symmetric key with RSA
	var encryptedKey []byte
	var keyTransportURI string

	switch keyTransport {
	case "rsa-oaep":
		keyTransportURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		hash := sha1.New()
		encryptedKey, _ = rsa.EncryptOAEP(hash, rand.Reader, &key.PublicKey, symKey, nil)
	case "rsa-oaep-sha256":
		keyTransportURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		hash := sha256.New()
		encryptedKey, _ = rsa.EncryptOAEP(hash, rand.Reader, &key.PublicKey, symKey, nil)
	case "rsa-pkcs1":
		keyTransportURI = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		encryptedKey, _ = rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, symKey)
	default:
		return nil, fmt.Errorf("unsupported key transport: %s", keyTransport)
	}

	// Encrypt the plaintext with the symmetric key
	var encryptedData []byte

	if payloadCipher == "aes128-cbc" || payloadCipher == "aes256-cbc" {
		block, err := aes.NewCipher(symKey)
		if err != nil {
			return nil, err
		}

		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}

		mode := cipher.NewCBCEncrypter(block, iv)
		paddedPlaintext := pkcs7Pad([]byte(plaintext), aes.BlockSize)
		encryptedData = make([]byte, len(paddedPlaintext))
		mode.CryptBlocks(encryptedData, paddedPlaintext)
		encryptedData = append(iv, encryptedData...)
	} else {
		// GCM mode
		block, err := aes.NewCipher(symKey)
		if err != nil {
			return nil, err
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		encryptedData = aead.Seal(nonce, nonce, []byte(plaintext), nil)
	}

	// Build the EncryptedAssertion XML
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
    <xenc:EncryptionMethod Algorithm="%s"/>
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xenc:EncryptedKey>
        <xenc:EncryptionMethod Algorithm="%s"/>
        <xenc:CipherData>
          <xenc:CipherValue>%s</xenc:CipherValue>
        </xenc:CipherData>
      </xenc:EncryptedKey>
    </ds:KeyInfo>
    <xenc:CipherData>
      <xenc:CipherValue>%s</xenc:CipherValue>
    </xenc:CipherData>
  </xenc:EncryptedData>
</saml2:EncryptedAssertion>`,
		cipherURI,
		keyTransportURI,
		base64.StdEncoding.EncodeToString(encryptedKey),
		base64.StdEncoding.EncodeToString(encryptedData),
	)

	return []byte(xml), nil
}

// pkcs7Pad adds PKCS#7 padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}
