# SAML Tools

A CLI tool for encrypting and decrypting SAML 2.0 assertions using RSA keys.

## Features

- **Auto-detection**: Automatically detects input format (raw XML, Base64, HTTP-POST)
- **Flexible key input**: Accepts PEM files or base64-encoded keys
- **Multiple encryption algorithms**:
  - Key transport: RSA-OAEP, RSA-PKCS1
  - Payload: AES-128-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM
- **Output options**: Stdout or file output, with pretty-printing
- **Full round-trip**: Encrypt assertions and decrypt them with matching key pairs

## Installation

```bash
go build -o saml-tools .
```

## Usage

```bash
./saml-tools <command> [flags]
```

### Commands

- `version`: Print the application version
- `decrypt`: Decrypt a SAML assertion
- `encrypt`: Encrypt a SAML assertion

### Global Flags

- `--log-level`: Log level. Default: `info`
- `--log-format`: Log format. Default: `console`
- `-t, --timeout`: Request timeout. Default: `5s` (not used yet)
- `-h, --help`: Show help

### Decrypt Usage

```bash
./saml-tools decrypt --key <private-key> [<input-file>] [flags]
```

#### Decrypt Flags

- `-k, --key` (required): Private key (PEM file path or base64 string)
- `-o, --output`: Output file (default: stdout)
- `-p, --pretty`: Pretty-print XML output
- `-v, --verbose`: Enable verbose logging

### Encrypt Usage

```bash
./saml-tools encrypt --key <public-key> [<input-file>] [flags]
```

#### Encrypt Flags

- `-k, --key` (required): Public key or X.509 certificate (PEM file path or base64 string)
- `--target-node`: Target XML node to encrypt. Default: `saml:Assertion`
- `-a, --algorithm`: Key transport algorithm (`rsa-oaep`, `rsa-pkcs1`). Default: `rsa-oaep`
- `-c, --cipher`: Payload cipher (`aes128-cbc`, `aes256-cbc`, `aes128-gcm`, `aes256-gcm`). Default: `aes128-cbc`
- `-i, --include-cert`: Include certificate in KeyInfo. Default: `true`
- `-o, --output`: Output file (default: stdout)
- `-p, --pretty`: Pretty-print XML output

### Environment Variables

- `ST_LOG_LEVEL`: Same as `--log-level`
- `ST_LOG_FORMAT`: Same as `--log-format`
- `ST_TIMEOUT`: Same as `--timeout`

#### Decrypt Environment Variables

- `ST_KEY`: Same as `--key`
- `ST_OUTPUT`: Same as `--output`
- `ST_PRETTY`: Same as `--pretty`
- `ST_VERBOSE`: Same as `--verbose`

#### Encrypt Environment Variables

- `ST_KEY`: Same as `--key`
- `ST_OUTPUT`: Same as `--output`
- `ST_TARGET_NODE`: Same as `--target-node`
- `ST_ALGORITHM`: Same as `--algorithm`
- `ST_CIPHER`: Same as `--cipher`
- `ST_PRETTY`: Same as `--pretty`
- `ST_INCLUDE_CERT`: Same as `--include-cert`

### Examples

#### Show version

```bash
./saml-tools version
```

#### Decrypt from file with PEM key file

```bash
./saml-tools decrypt encrypted.xml --key private.pem
```

#### Decrypt from file with base64 key

```bash
./saml-tools decrypt encrypted.xml --key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCg..."
```

#### Decrypt from stdin

```bash
cat encrypted.xml | ./saml-tools decrypt --key private.pem
```

#### Output to decrypted file with pretty-printing

```bash
./saml-tools decrypt encrypted.xml --key private.pem --output decrypted.xml --pretty
```

#### Decrypt base64-encoded SAML response

```bash
./saml-tools decrypt saml-response.b64 --key private.pem
```

#### Decrypt HTTP-POST binding data

```bash
echo "SAMLResponse=PHNhbWxwOlJlc3BvbnNl..." | ./saml-tools decrypt --key private.pem
```

#### Use JSON logs

```bash
./saml-tools --log-format json decrypt encrypted.xml --key private.pem
```

### Encrypt Examples

#### Encrypt with X.509 certificate

```bash
./saml-tools encrypt assertion.xml --key certificate.pem
```

#### Encrypt with public key (no certificate in output)

```bash
./saml-tools encrypt assertion.xml --key public.pem --include-cert=false
```

#### Encrypt from stdin

```bash
cat assertion.xml | ./saml-tools encrypt --key certificate.pem
```

#### Encrypt with custom algorithms

```bash
./saml-tools encrypt assertion.xml --key cert.pem --cipher aes256-gcm --algorithm rsa-pkcs1
```

#### Encrypt a custom XML node

```bash
./saml-tools encrypt response.xml --key cert.pem --target-node Assertion
```

#### Output to encrypted file with pretty-printing

```bash
./saml-tools encrypt assertion.xml --key certificate.pem --output encrypted.xml --pretty
```

#### Full round-trip: encrypt then decrypt

```bash
./saml-tools encrypt assertion.xml --key public.pem | ./saml-tools decrypt --key private.pem
```

**Note**: The public and private keys must be a matching pair. Logs are written to stderr, so piping works correctly.

## Key Management

When using both `encrypt` and `decrypt` commands, ensure you use **matching RSA key pairs**:

- **Encrypt**: Use the recipient's **public key** (or X.509 certificate)
- **Decrypt**: Use your **private key** that corresponds to the public key used for encryption

To generate a matching key pair:

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem

# Or create a self-signed certificate
openssl req -new -x509 -key private.pem -out certificate.pem -days 365
```

## Supported Formats

The tool auto-detects the following input formats:

1. **Raw XML**: Files containing `<saml2:EncryptedAssertion>` or `<EncryptedAssertion>`
2. **Base64**: Base64-encoded SAML XML
3. **HTTP-POST**: URL-encoded form data with `SAMLResponse` parameter

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
| key    | 88%      |
| format | 96%      |
| saml   | 85%      |
| cmd    | 8%       |

## License

[MIT License](LICENSE)

## Security Notes

- This tool handles cryptographic keys. Keep your private keys secure.
- Password-protected PEM files are not supported for security reasons.
- Only RSA keys are supported (2048+ bits recommended).
- The tool does not validate SAML signatures, only decrypts encrypted assertions.
- When encrypting, the default algorithm is RSA-OAEP which is more secure than RSA-PKCS1.
- X.509 certificates can be included in the encrypted output to help recipients identify the encryption key.
