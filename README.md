# SAML Decrypt

A CLI tool for decrypting SAML 2.0 encrypted assertions using RSA private keys.

## Features

- **Auto-detection**: Automatically detects input format (raw XML, Base64, HTTP-POST)
- **Flexible key input**: Accepts PEM files or base64-encoded keys
- **Multiple encryption algorithms**:
  - Key transport: RSA-OAEP, RSA-PKCS1
  - Payload: AES-128-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM
- **Output options**: Stdout or file output, with pretty-printing

## Installation

```bash
go build -o saml-decrypt ./cmd/saml-decrypt
```

## Usage

```bash
saml-decrypt --key <private-key> [<input-file>] [flags]
```

### Flags

- `-k, --key` (required): Private key (PEM file path or base64 string)
- `-o, --output`: Output file (default: stdout)
- `-p, --pretty`: Pretty-print XML output
- `-v, --verbose`: Enable verbose logging
- `-h, --help`: Show help

### Examples

#### Decrypt from file with PEM key file

```bash
saml-decrypt encrypted.xml --key private.pem
```

#### Decrypt from file with base64 key

```bash
saml-decrypt encrypted.xml --key "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ..."
```

#### Decrypt from stdin

```bash
cat encrypted.xml | saml-decrypt --key private.pem
```

#### Output to file with pretty-printing

```bash
saml-decrypt encrypted.xml --key private.pem --output decrypted.xml --pretty
```

#### Decrypt base64-encoded SAML response

```bash
saml-decrypt saml-response.b64 --key private.pem
```

#### Decrypt HTTP-POST binding data

```bash
echo "SAMLResponse=PHNhbWxwOlJlc3BvbnNl..." | saml-decrypt --key private.pem
```

## Supported Formats

The tool auto-detects the following input formats:

1. **Raw XML**: Files containing `<saml2:EncryptedAssertion>` or `<EncryptedAssertion>`
2. **Base64**: Base64-encoded SAML XML
3. **HTTP-POST**: URL-encoded form data with `SAMLResponse` parameter

## Error Messages

The tool provides clear, actionable error messages:

- `invalid private key format`: Key is malformed or unsupported
- `private key file not found`: PEM file doesn't exist
- `password-protected keys not supported`: Encrypted PEM files are not supported
- `unsupported key type`: Only RSA keys are supported (not ECDSA)
- `malformed XML`: Input is not valid SAML XML
- `missing encryption key`: EncryptedKey element not found
- `decryption failed`: Wrong key or corrupted data
- `unsupported encryption algorithm`: Algorithm not yet implemented

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Run fuzz tests
go test -fuzz=FuzzLoadKey -fuzztime=10s ./key/...
go test -fuzz=FuzzDecrypt -fuzztime=10s ./saml/...
```

### Test Coverage

| Module | Coverage |
| ------ | -------- |
| key    | 84%      |
| format | 96%      |
| saml   | 78%      |

## License

[MIT License](LICENSE)

## Security Notes

- This tool handles cryptographic keys. Keep your private keys secure.
- Password-protected PEM files are not supported for security reasons.
- Only RSA keys are supported (2048+ bits recommended).
- The tool does not validate SAML signatures, only decrypts encrypted assertions.
