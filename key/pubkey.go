// Package key provides public key loading functionality for encryption.
package key

import (
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
	ErrInvalidPublicKey   = errors.New("invalid public key format")
	ErrInvalidCertificate = errors.New("invalid X.509 certificate")
	ErrEmptyPublicKey     = errors.New("empty public key input")
)

// PublicKeyLoader provides methods to load RSA public keys from various sources.
// It can load from X.509 certificates or raw RSA public keys, from files or base64 strings.
type PublicKeyLoader interface {
	LoadPublicKey(source string) (*rsa.PublicKey, *x509.Certificate, error)
	// Returns both the public key and optional certificate (if source was a certificate)
}

type publicKeyLoader struct{}

// NewPublicKeyLoader creates a new public key loader with auto-detection.
func NewPublicKeyLoader() PublicKeyLoader {
	return &publicKeyLoader{}
}

// LoadPublicKey detects whether the source is a file path or base64-encoded key/cert,
// then parses and returns the RSA public key and optional certificate.
func (l *publicKeyLoader) LoadPublicKey(source string) (*rsa.PublicKey, *x509.Certificate, error) {
	if source == "" {
		return nil, nil, ErrEmptyPublicKey
	}

	// Check if it looks like a file path
	isLikelyFilePath := strings.Contains(source, string(os.PathSeparator)) ||
		strings.Contains(source, ".pem") ||
		strings.Contains(source, ".cert") ||
		strings.Contains(source, ".crt") ||
		strings.Contains(source, ".der")

	if isLikelyFilePath {
		data, err := os.ReadFile(source)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil, fmt.Errorf("%w: file not found", ErrInvalidPublicKey)
			}
			return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
		}
		return l.parsePublicKey(data)
	}

	// Try base64 decoding
	if looksLikeBase64(source) {
		if data, err := base64.StdEncoding.DecodeString(source); err == nil {
			return l.parsePublicKey(data)
		}
	}

	// As a fallback, try as file path anyway
	if data, err := os.ReadFile(source); err == nil {
		return l.parsePublicKey(data)
	} else if os.IsNotExist(err) {
		// File doesn't exist and base64 decoding failed
		return nil, nil, ErrInvalidPublicKey
	}

	return nil, nil, ErrInvalidPublicKey
}

// parsePublicKey parses PEM-encoded public key or certificate data.
func (l *publicKeyLoader) parsePublicKey(data []byte) (*rsa.PublicKey, *x509.Certificate, error) {
	// Try to decode as PEM
	block, rest := pem.Decode(data)
	if block == nil {
		// Try as raw DER-encoded certificate
		if cert, err := x509.ParseCertificate(data); err == nil {
			if rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				return rsaPubKey, cert, nil
			}
			return nil, nil, fmt.Errorf("%w: certificate contains non-RSA key", ErrUnsupportedKeyType)
		}
		return nil, nil, ErrInvalidPublicKey
	}

	// Check if there's more data after the PEM block
	if len(rest) > 0 {
		if nextBlock, _ := pem.Decode(rest); nextBlock != nil {
			return nil, nil, fmt.Errorf("%w: multiple PEM blocks found", ErrInvalidPublicKey)
		}
	}

	switch block.Type {
	case "CERTIFICATE":
		return l.parseCertificate(block.Bytes)
	case "PUBLIC KEY":
		return l.parseRSAPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		// PKCS#1 format
		return l.parsePKCS1PublicKey(block.Bytes)
	default:
		return nil, nil, fmt.Errorf("%w: unknown PEM type: %s", ErrInvalidPublicKey, block.Type)
	}
}

func (l *publicKeyLoader) parseCertificate(der []byte) (*rsa.PublicKey, *x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: certificate contains non-RSA key", ErrUnsupportedKeyType)
	}

	return rsaPubKey, cert, nil
}

func (l *publicKeyLoader) parseRSAPublicKey(der []byte) (*rsa.PublicKey, *x509.Certificate, error) {
	pubKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: not an RSA public key", ErrUnsupportedKeyType)
	}

	return rsaPubKey, nil, nil
}

func (l *publicKeyLoader) parsePKCS1PublicKey(der []byte) (*rsa.PublicKey, *x509.Certificate, error) {
	pubKey, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	return pubKey, nil, nil
}
