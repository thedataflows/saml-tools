// Package saml provides SAML 2.0 encrypted assertion encryption functionality.
package saml

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/beevik/etree"
)

var (
	ErrEncryptionFailed = errors.New("encryption failed")
)

// Encrypter provides methods to encrypt SAML assertions
type Encrypter interface {
	Encrypt(plaintextXML []byte, publicKey *rsa.PublicKey, opts EncryptOptions) ([]byte, error)
}

// EncryptOptions holds configuration for encryption
type EncryptOptions struct {
	TargetNode    string            // default: "saml:Assertion"
	KeyTransport  string            // "rsa-oaep" (default) or "rsa-pkcs1"
	PayloadCipher string            // "aes128-cbc" (default), "aes256-cbc", "aes128-gcm", "aes256-gcm"
	Certificate   *x509.Certificate // Optional: for KeyInfo
}

type encrypter struct{}

// NewEncrypter creates a new SAML encrypter
func NewEncrypter() Encrypter {
	return &encrypter{}
}

// Encrypt encrypts a SAML assertion and returns a full SAML Response
func (e *encrypter) Encrypt(plaintextXML []byte, publicKey *rsa.PublicKey, opts EncryptOptions) ([]byte, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("%w: public key is nil", ErrEncryptionFailed)
	}

	// Set defaults
	targetNode := opts.TargetNode
	if targetNode == "" {
		targetNode = "saml:Assertion"
	}

	keyTransport := opts.KeyTransport
	if keyTransport == "" {
		keyTransport = "rsa-oaep"
	}

	payloadCipher := opts.PayloadCipher
	if payloadCipher == "" {
		payloadCipher = "aes128-cbc"
	}

	// Parse the XML document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plaintextXML); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedXML, err)
	}

	// Find target node
	targetElement := findElement(doc.Root(), targetNode)
	if targetElement == nil {
		// Try without namespace prefix
		targetElement = findElement(doc.Root(), strings.TrimPrefix(targetNode, "saml:"))
	}
	if targetElement == nil {
		return nil, fmt.Errorf("%w: target node '%s' not found", ErrMalformedXML, targetNode)
	}

	// Serialize the target element to string
	targetDoc := etree.NewDocument()
	targetDoc.SetRoot(targetElement.Copy())
	targetXML, err := targetDoc.WriteToString()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to serialize target: %v", ErrEncryptionFailed, err)
	}

	// Generate random symmetric key
	symKey, cipherURI, err := generateSymmetricKey(payloadCipher)
	if err != nil {
		return nil, err
	}

	// Encrypt the symmetric key with RSA
	encryptedKey, keyTransportURI, err := encryptKey(symKey, keyTransport, publicKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext with the symmetric key
	encryptedData, err := encryptPayload([]byte(targetXML), payloadCipher, symKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Build EncryptedAssertion XML
	encryptedAssertion := buildEncryptedAssertion(
		cipherURI,
		keyTransportURI,
		base64.StdEncoding.EncodeToString(encryptedKey),
		base64.StdEncoding.EncodeToString(encryptedData),
		opts.Certificate,
	)

	// Replace target element with EncryptedAssertion
	parent := targetElement.Parent()
	if parent == nil {
		// Target is root element, wrap in Response
		return wrapInResponse(encryptedAssertion, doc.Root()), nil
	}

	// Parse encrypted assertion as etree element
	encDoc := etree.NewDocument()
	if err := encDoc.ReadFromString(encryptedAssertion); err != nil {
		return nil, fmt.Errorf("%w: failed to parse encrypted assertion: %v", ErrEncryptionFailed, err)
	}

	// Replace the target element
	parent.RemoveChild(targetElement)
	parent.AddChild(encDoc.Root())

	// Check if we're already in a Response
	if isInResponse(doc.Root()) {
		// Update the document
		result, err := doc.WriteToBytes()
		if err != nil {
			return nil, fmt.Errorf("%w: failed to serialize result: %v", ErrEncryptionFailed, err)
		}
		return result, nil
	}

	// Wrap in SAML Response
	return wrapInResponse(encryptedAssertion, doc.Root()), nil
}

func findElement(root *etree.Element, name string) *etree.Element {
	if root == nil {
		return nil
	}
	// Try with various namespace prefixes
	paths := []string{
		"//" + name,
		"//saml:" + name,
		"//saml2:" + name,
	}

	for _, path := range paths {
		if el := root.FindElement(path); el != nil {
			return el
		}
	}

	return nil
}

func generateSymmetricKey(cipher string) ([]byte, string, error) {
	switch cipher {
	case "aes128-cbc":
		key := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, "", fmt.Errorf("%w: failed to generate key: %v", ErrEncryptionFailed, err)
		}
		return key, "http://www.w3.org/2001/04/xmlenc#aes128-cbc", nil
	case "aes256-cbc":
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, "", fmt.Errorf("%w: failed to generate key: %v", ErrEncryptionFailed, err)
		}
		return key, "http://www.w3.org/2001/04/xmlenc#aes256-cbc", nil
	case "aes128-gcm":
		key := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, "", fmt.Errorf("%w: failed to generate key: %v", ErrEncryptionFailed, err)
		}
		return key, "http://www.w3.org/2009/xmlenc11#aes128-gcm", nil
	case "aes256-gcm":
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, "", fmt.Errorf("%w: failed to generate key: %v", ErrEncryptionFailed, err)
		}
		return key, "http://www.w3.org/2009/xmlenc11#aes256-gcm", nil
	default:
		return nil, "", fmt.Errorf("%w: unsupported cipher: %s", ErrUnsupportedAlgorithm, cipher)
	}
}

func encryptKey(symKey []byte, transport string, pubKey *rsa.PublicKey) ([]byte, string, error) {
	switch transport {
	case "rsa-oaep":
		hash := sha1.New()
		encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, symKey, nil)
		if err != nil {
			return nil, "", fmt.Errorf("%w: RSA-OAEP encryption failed: %v", ErrEncryptionFailed, err)
		}
		return encrypted, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", nil
	case "rsa-pkcs1":
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, symKey)
		if err != nil {
			return nil, "", fmt.Errorf("%w: RSA-PKCS1 encryption failed: %v", ErrEncryptionFailed, err)
		}
		return encrypted, "http://www.w3.org/2001/04/xmlenc#rsa-1_5", nil
	default:
		return nil, "", fmt.Errorf("%w: unsupported key transport: %s", ErrUnsupportedAlgorithm, transport)
	}
}

func encryptPayload(plaintext []byte, cipher string, key []byte) ([]byte, error) {
	switch cipher {
	case "aes128-cbc", "aes256-cbc":
		return encryptAESCBC(plaintext, key)
	case "aes128-gcm", "aes256-gcm":
		return encryptAESGCM(plaintext, key)
	default:
		return nil, fmt.Errorf("%w: unsupported cipher: %s", ErrUnsupportedAlgorithm, cipher)
	}
}

func encryptAESCBC(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Pad plaintext
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Prepend IV
	return append(iv, ciphertext...), nil
}

func encryptAESGCM(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and seal (returns nonce + ciphertext + tag)
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func buildEncryptedAssertion(cipherURI, keyTransportURI, encryptedKeyB64, encryptedDataB64 string, cert *x509.Certificate) string {
	var keyInfo string
	if cert != nil {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		// Extract just the base64 content
		certB64 := strings.TrimSpace(string(certPEM))
		certB64 = strings.TrimPrefix(certB64, "-----BEGIN CERTIFICATE-----")
		certB64 = strings.TrimSuffix(certB64, "-----END CERTIFICATE-----")
		certB64 = strings.ReplaceAll(certB64, "\n", "")

		keyInfo = fmt.Sprintf(`
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:X509Data>
            <ds:X509Certificate>%s</ds:X509Certificate>
          </ds:X509Data>
        </ds:KeyInfo>`, certB64)
	}

	return fmt.Sprintf(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
    <xenc:EncryptionMethod Algorithm="%s"/>
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xenc:EncryptedKey>
        <xenc:EncryptionMethod Algorithm="%s"/>%s
        <xenc:CipherData>
          <xenc:CipherValue>%s</xenc:CipherValue>
        </xenc:CipherData>
      </xenc:EncryptedKey>
    </ds:KeyInfo>
    <xenc:CipherData>
      <xenc:CipherValue>%s</xenc:CipherValue>
    </xenc:CipherData>
  </xenc:EncryptedData>
</saml:EncryptedAssertion>`,
		cipherURI,
		keyTransportURI,
		keyInfo,
		encryptedKeyB64,
		encryptedDataB64,
	)
}

func isInResponse(root *etree.Element) bool {
	// Check if root or any ancestor is a Response
	for el := root; el != nil; el = el.Parent() {
		if el.Tag == "Response" || el.Tag == "samlp:Response" {
			return true
		}
	}
	return false
}

func wrapInResponse(encryptedAssertion string, originalRoot *etree.Element) []byte {
	// Try to extract issuer from original
	var issuer string
	if el := originalRoot.FindElement("//saml:Issuer"); el != nil {
		issuer = el.Text()
	} else if el := originalRoot.FindElement("//Issuer"); el != nil {
		issuer = el.Text()
	}
	if issuer == "" {
		issuer = "https://issuer.example.com"
	}

	responseID := "_enc-response-" + generateID()
	timestamp := time.Now().UTC().Format(time.RFC3339)

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="%s"
                Version="2.0"
                IssueInstant="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  %s
</samlp:Response>`,
		responseID,
		timestamp,
		issuer,
		encryptedAssertion,
	)

	return []byte(response)
}

func generateID() string {
	// Generate a simple unique ID without external dependency
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
