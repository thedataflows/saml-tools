// Package key provides private key loading and parsing functionality.
// It auto-detects between PEM file paths and base64-encoded key strings.
package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrInvalidKey         = errors.New("invalid private key format")
	ErrKeyNotFound        = errors.New("private key file not found")
	ErrEmptyKey           = errors.New("empty key input")
	ErrPasswordProtected  = errors.New("password-protected key requires password")
	ErrWrongPassword      = errors.New("incorrect password for encrypted key")
	ErrUnsupportedKeyType = errors.New("unsupported key type")
)

// Loader provides methods to load cryptographic private keys from various sources.
type Loader interface {
	Load(source string) (crypto.PrivateKey, error)
	LoadWithPassword(source string, password string) (crypto.PrivateKey, error)
}

type loader struct{}

// NewLoader creates a new key loader that auto-detects input format.
func NewLoader() Loader {
	return &loader{}
}

// Load detects whether the source is a file path or base64-encoded key,
// then parses and returns the private key.
// For password-protected keys, returns ErrPasswordProtected.
func (l *loader) Load(source string) (crypto.PrivateKey, error) {
	return l.LoadWithPassword(source, "")
}

// LoadWithPassword detects whether the source is a file path or base64-encoded key,
// then parses and returns the private key using the provided password if needed.
func (l *loader) LoadWithPassword(source string, password string) (crypto.PrivateKey, error) {
	if source == "" {
		return nil, ErrEmptyKey
	}

	// Check if it looks like a file path first
	// File paths typically have directory separators or extensions
	// Base64 strings are typically much longer and don't have common path chars
	isLikelyFilePath := strings.Contains(source, string(os.PathSeparator)) ||
		strings.Contains(source, ".pem") ||
		strings.Contains(source, ".key")

	if isLikelyFilePath {
		data, err := os.ReadFile(source)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, ErrKeyNotFound
			}
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return parsePEM(data, password)
	}

	// Try base64 decoding (for strings that look like base64)
	// Base64 strings are typically long and contain base64 alphabet
	if looksLikeBase64(source) {
		if data, err := base64.StdEncoding.DecodeString(source); err == nil {
			return parsePEM(data, password)
		}
	}

	// As a fallback, try as file path anyway (in case it's a simple filename)
	if data, err := os.ReadFile(source); err == nil {
		return parsePEM(data, password)
	} else if os.IsNotExist(err) {
		// File doesn't exist, and base64 decoding failed
		return nil, ErrInvalidKey
	}

	return nil, ErrInvalidKey
}

// looksLikeBase64 checks if a string looks like base64 encoded data
func looksLikeBase64(s string) bool {
	// Base64 strings should be at least a certain length
	if len(s) < 20 {
		return false
	}

	// Should only contain base64 alphabet characters
	for _, r := range s {
		if !isBase64Char(r) {
			return false
		}
	}

	return true
}

func isBase64Char(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '+' || r == '/' || r == '='
}

// parsePEM parses PEM-encoded private key data and returns the key.
// If the key is password-protected and no password is provided, returns ErrPasswordProtected.
func parsePEM(data []byte, password string) (crypto.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidKey
	}

	// Check if there's more data after the PEM block (multiple keys not supported)
	if len(rest) > 0 {
		// Try to decode rest - if it's also a valid PEM, we have multiple keys
		if nextBlock, _ := pem.Decode(rest); nextBlock != nil {
			return nil, ErrInvalidKey
		}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		// Legacy PKCS#1 format - may be encrypted with PEM encryption
		if x509.IsEncryptedPEMBlock(block) {
			if password == "" {
				return nil, ErrPasswordProtected
			}
			// Decrypt the block
			decryptedBytes, err := x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				return nil, ErrWrongPassword
			}
			block.Bytes = decryptedBytes
		}
		return parseRSAPrivateKey(block.Bytes)

	case "ENCRYPTED PRIVATE KEY":
		// PKCS#8 encrypted format - not supported yet
		return nil, ErrPasswordProtected

	case "PRIVATE KEY":
		// Unencrypted PKCS#8 format
		return parsePKCS8PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		return nil, ErrUnsupportedKeyType

	default:
		return nil, ErrInvalidKey
	}
}

func parseRSAPrivateKey(der []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return key, nil
}

func parsePKCS8PrivateKey(der []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	// Check if it's an RSA key
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return nil, ErrUnsupportedKeyType
	default:
		return nil, ErrUnsupportedKeyType
	}
}
