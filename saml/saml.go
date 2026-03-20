// Package saml provides SAML 2.0 encrypted assertion decryption functionality.
package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
)

var (
	ErrMalformedXML         = errors.New("malformed XML")
	ErrMissingKey           = errors.New("missing encryption key")
	ErrDecryptionFailed     = errors.New("decryption failed")
	ErrUnsupportedAlgorithm = errors.New("unsupported encryption algorithm")
)

// Decrypter provides methods to decrypt SAML encrypted assertions
type Decrypter interface {
	Decrypt(encryptedData []byte, privateKey crypto.PrivateKey) ([]byte, error)
}

// Config holds configuration for the decrypter
type Config struct {
	// Future configuration options
}

type decrypter struct {
	cfg Config
}

// NewDecrypter creates a new SAML decrypter with the given configuration
func NewDecrypter(cfg Config) Decrypter {
	return &decrypter{cfg: cfg}
}

// Decrypt decrypts a SAML encrypted assertion using the provided private key
func (d *decrypter) Decrypt(encryptedData []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	// Parse the XML document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(encryptedData); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedXML, err)
	}

	// Find EncryptedAssertion element
	var encryptedAssertion *etree.Element
	for _, el := range []string{"//saml:EncryptedAssertion", "//saml2:EncryptedAssertion", "//EncryptedAssertion"} {
		encryptedAssertion = doc.FindElement(el)
		if encryptedAssertion == nil {
			continue
		}
	}

	if encryptedAssertion == nil {
		return nil, fmt.Errorf("%w: no EncryptedAssertion element found", ErrMalformedXML)
	}

	// Find EncryptedData element
	encryptedDataEl := encryptedAssertion.FindElement(".//xenc:EncryptedData")
	if encryptedDataEl == nil {
		encryptedDataEl = encryptedAssertion.FindElement(".//EncryptedData")
	}
	if encryptedDataEl == nil {
		return nil, fmt.Errorf("%w: no EncryptedData element found", ErrMalformedXML)
	}

	// Get encryption method
	encryptionMethod := encryptedDataEl.FindElement(".//xenc:EncryptionMethod")
	if encryptionMethod == nil {
		encryptionMethod = encryptedDataEl.FindElement(".//EncryptionMethod")
	}
	if encryptionMethod == nil {
		return nil, fmt.Errorf("%w: no EncryptionMethod found", ErrMalformedXML)
	}

	algo := encryptionMethod.SelectAttrValue("Algorithm", "")

	// Find EncryptedKey
	encryptedKey := encryptedDataEl.FindElement(".//xenc:EncryptedKey")
	if encryptedKey == nil {
		encryptedKey = encryptedDataEl.FindElement(".//EncryptedKey")
	}
	if encryptedKey == nil {
		// Try to find in KeyInfo
		keyInfo := encryptedDataEl.FindElement(".//ds:KeyInfo")
		if keyInfo == nil {
			keyInfo = encryptedDataEl.FindElement(".//KeyInfo")
		}
		if keyInfo != nil {
			encryptedKey = keyInfo.FindElement(".//xenc:EncryptedKey")
			if encryptedKey == nil {
				encryptedKey = keyInfo.FindElement(".//EncryptedKey")
			}
		}
	}
	if encryptedKey == nil {
		return nil, ErrMissingKey
	}

	// Get key encryption method
	keyEncryptionMethod := encryptedKey.FindElement(".//xenc:EncryptionMethod")
	if keyEncryptionMethod == nil {
		keyEncryptionMethod = encryptedKey.FindElement(".//EncryptionMethod")
	}
	if keyEncryptionMethod == nil {
		return nil, fmt.Errorf("%w: no key encryption method found", ErrMalformedXML)
	}

	keyAlgo := keyEncryptionMethod.SelectAttrValue("Algorithm", "")

	// Get encrypted key value
	cipherValue := encryptedKey.FindElement(".//xenc:CipherValue")
	if cipherValue == nil {
		cipherValue = encryptedKey.FindElement(".//CipherValue")
	}
	if cipherValue == nil {
		return nil, fmt.Errorf("%w: no cipher value for key", ErrMissingKey)
	}

	encryptedKeyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cipherValue.Text()))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid key encoding: %v", ErrMalformedXML, err)
	}

	// Get encrypted data value
	dataCipherValue := encryptedDataEl.FindElement(".//xenc:CipherValue")
	if dataCipherValue == nil {
		dataCipherValue = encryptedDataEl.FindElement(".//CipherValue")
	}
	if dataCipherValue == nil {
		return nil, fmt.Errorf("%w: no cipher value for data", ErrMalformedXML)
	}

	encryptedPayload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dataCipherValue.Text()))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid data encoding: %v", ErrMalformedXML, err)
	}

	// Decrypt the symmetric key
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: private key must be RSA", ErrDecryptionFailed)
	}

	symmetricKey, err := decryptKey(encryptedKeyBytes, keyAlgo, rsaKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Decrypt the payload
	plaintext, err := decryptPayload(encryptedPayload, algo, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

func decryptKey(encryptedKey []byte, algorithm string, privateKey *rsa.PrivateKey) ([]byte, error) {
	switch algorithm {
	case "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, encryptedKey, nil)
	case "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
		return rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedKey)
	default:
		if strings.Contains(algorithm, "rsa-oaep") {
			// Try with SHA1 as default
			return rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, encryptedKey, nil)
		}
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
}

func decryptPayload(encryptedPayload []byte, algorithm string, key []byte) ([]byte, error) {
	switch algorithm {
	case "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		"http://www.w3.org/2001/04/xmlenc#aes192-cbc",
		"http://www.w3.org/2001/04/xmlenc#aes256-cbc":
		return decryptAESCBC(encryptedPayload, key)
	case "http://www.w3.org/2009/xmlenc11#aes128-gcm",
		"http://www.w3.org/2009/xmlenc11#aes192-gcm",
		"http://www.w3.org/2009/xmlenc11#aes256-gcm":
		return decryptAESGCM(encryptedPayload, key)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
}

func decryptAESCBC(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	plaintext = removePKCS7Padding(plaintext, aes.BlockSize)

	return plaintext, nil
}

func decryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	return aead.Open(nil, nonce, ciphertext, nil)
}

func removePKCS7Padding(data []byte, blockSize int) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 || len(data) < padding {
		return data
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return data
		}
	}
	return data[:len(data)-padding]
}

func init() {
	// Ensure rand.Reader is available
	_ = io.Discard
}
