// Package format provides input format detection for SAML data.
// It can detect raw XML, base64-encoded data, and HTTP-POST binding formats.
package format

import (
	"bytes"
	"encoding/base64"
	"strings"
)

// Type represents the detected input format
type Type int

const (
	FormatUnknown Type = iota
	FormatRawXML
	FormatBase64
	FormatHTTPPost
)

// Detector provides methods to detect the format of SAML input data
type Detector interface {
	Detect(data []byte) Type
}

type detector struct{}

// NewDetector creates a new format detector
func NewDetector() Detector {
	return &detector{}
}

// Detect analyzes the input data and returns the detected format type
func (d *detector) Detect(data []byte) Type {
	if len(data) == 0 {
		return FormatUnknown
	}

	// Check for HTTP POST binding first (highest priority)
	if isHTTPPost(data) {
		return FormatHTTPPost
	}

	// Check for raw XML with SAML content
	if isRawXML(data) {
		return FormatRawXML
	}

	// Check for base64 encoded data
	if isBase64Encoded(data) {
		return FormatBase64
	}

	return FormatUnknown
}

// isHTTPPost checks if data looks like HTTP POST form data with SAMLResponse
func isHTTPPost(data []byte) bool {
	// Look for SAMLResponse= in the data
	if bytes.Contains(data, []byte("SAMLResponse=")) {
		return true
	}
	return false
}

// isRawXML checks if data is XML containing SAML encrypted assertion
func isRawXML(data []byte) bool {
	// Check if it looks like XML
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return false
	}

	// Must start with <?xml or <
	if !bytes.HasPrefix(trimmed, []byte("<?xml")) && !bytes.HasPrefix(trimmed, []byte("<")) {
		return false
	}

	// Check for SAML EncryptedAssertion content
	content := string(trimmed)
	if strings.Contains(content, "EncryptedAssertion") ||
		strings.Contains(content, "EncryptedData") {
		return true
	}

	return false
}

// isBase64Encoded checks if data appears to be base64 encoded SAML content
func isBase64Encoded(data []byte) bool {
	// Try to decode as base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return false
	}

	// Check if decoded content looks like SAML XML
	if isRawXML(decoded) {
		return true
	}

	return false
}
