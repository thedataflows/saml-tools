package format_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thedataflows/saml-tools/format"
)

func TestDetector_Detect_RawXML(t *testing.T) {
	detector := format.NewDetector()

	cases := []struct {
		name     string
		input    string
		expected format.Type
	}{
		{
			name: "EncryptedAssertion XML",
			input: `<?xml version="1.0"?>
<saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <xenc:EncryptedData/>
</saml2:EncryptedAssertion>`,
			expected: format.FormatRawXML,
		},
		{
			name: "Response with EncryptedAssertion",
			input: `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:EncryptedAssertion/>
</samlp:Response>`,
			expected: format.FormatRawXML,
		},
		{
			name:     "Plain XML without SAML",
			input:    `<?xml version="1.0"?><root/>`,
			expected: format.FormatUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Detect([]byte(tc.input))
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDetector_Detect_Base64(t *testing.T) {
	detector := format.NewDetector()

	// Valid SAML response base64 encoded
	samlResponse := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:EncryptedAssertion/>
</samlp:Response>`
	base64Response := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	cases := []struct {
		name     string
		input    string
		expected format.Type
	}{
		{
			name:     "Base64 encoded SAML Response",
			input:    base64Response,
			expected: format.FormatBase64,
		},
		{
			name:     "Base64 encoded EncryptedAssertion",
			input:    base64.StdEncoding.EncodeToString([]byte(`<saml2:EncryptedAssertion/>`)),
			expected: format.FormatBase64,
		},
		{
			name:     "Invalid base64",
			input:    "!@#$%^&*()",
			expected: format.FormatUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Detect([]byte(tc.input))
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDetector_Detect_HTTPPost(t *testing.T) {
	detector := format.NewDetector()

	samlResponse := `<samlp:Response><saml:EncryptedAssertion/></samlp:Response>`
	base64Response := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	cases := []struct {
		name     string
		input    string
		expected format.Type
	}{
		{
			name:     "HTTP POST form data",
			input:    "SAMLResponse=" + base64Response,
			expected: format.FormatHTTPPost,
		},
		{
			name:     "URL encoded POST data",
			input:    "RelayState=abc&SAMLResponse=" + base64Response,
			expected: format.FormatHTTPPost,
		},
		{
			name:     "POST without SAMLResponse",
			input:    "foo=bar&baz=qux",
			expected: format.FormatUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Detect([]byte(tc.input))
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDetector_Detect_EdgeCases(t *testing.T) {
	detector := format.NewDetector()

	cases := []struct {
		name     string
		input    []byte
		expected format.Type
	}{
		{
			name:     "Empty input",
			input:    []byte{},
			expected: format.FormatUnknown,
		},
		{
			name:     "Binary garbage",
			input:    []byte{0x00, 0x01, 0x02, 0x03, 0xff},
			expected: format.FormatUnknown,
		},
		{
			name:     "Malformed XML",
			input:    []byte("<broken>"),
			expected: format.FormatUnknown,
		},
		{
			name:     "Plain text",
			input:    []byte("This is just plain text"),
			expected: format.FormatUnknown,
		},
		{
			name:     "Whitespace only",
			input:    []byte("   \n\t  "),
			expected: format.FormatUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Detect(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDetector_Detect_Priority(t *testing.T) {
	detector := format.NewDetector()

	// When input matches multiple patterns, should return the most specific

	// Raw XML should take precedence over base64
	// (though base64 of valid XML wouldn't look like valid XML)
	xmlInput := []byte(`<saml2:EncryptedAssertion/>`)
	result := detector.Detect(xmlInput)
	assert.Equal(t, format.FormatRawXML, result)
}
