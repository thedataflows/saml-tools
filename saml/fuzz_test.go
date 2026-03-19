package saml_test

import (
	"testing"

	"github.com/thedataflows/saml-tools/saml"
	"github.com/thedataflows/saml-tools/testutil"
)

func FuzzDecrypt(f *testing.F) {
	// Generate a key for the fuzz tests
	key, _ := testutil.GenerateRSAKey(2048)

	// Seed with valid encrypted assertions
	plaintext := "<Assertion>Test</Assertion>"
	encrypted, _ := testutil.GenerateEncryptedAssertion(plaintext, key, "rsa-oaep", "aes128-cbc")

	f.Add(encrypted)
	f.Add([]byte("<saml2:EncryptedAssertion></saml2:EncryptedAssertion>"))
	f.Add([]byte("<xml>"))
	f.Add([]byte("not xml at all"))
	f.Add([]byte{})

	decrypter := saml.NewDecrypter(saml.Config{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic
		decrypter.Decrypt(data, key)
	})
}
