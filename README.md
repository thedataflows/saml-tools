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
./Usage: saml-tools <command> [flags]

A toolkit for working with SAML assertions

Flags:
  -h, --help                    Show context-sensitive help.
      --log-level="info"        Log level (trace,debug,info,warn,error) ($ST_LOG_LEVEL)
      --log-format="console"    Log format (console,json) ($ST_LOG_FORMAT)
  -t, --timeout=5s              Request timeout duration ($ST_TIMEOUT)

Commands:
  version [flags]
    Show version information

  decrypt --key=STRING [<input>] [flags]
    Decrypt SAML assertions

  encrypt --key=STRING [<input>] [flags]
    Encrypt SAML assertions

Run "saml-tools <command> --help" for more information on a command.
```

### Decrypt Usage

```bash
./saml-tools decrypt --key=STRING [<input>] [flags]

Decrypt SAML assertions

Arguments:
  [<input>]    SAML assertion file (or stdin if omitted)

Flags:
  -h, --help                    Show context-sensitive help.
      --log-level="info"        Log level (trace,debug,info,warn,error) ($ST_LOG_LEVEL)
      --log-format="console"    Log format (console,json) ($ST_LOG_FORMAT)
  -t, --timeout=5s              Request timeout duration ($ST_TIMEOUT)

  -k, --key=STRING              Private key (PEM file path or base64 string) ($ST_KEY)
      --key-password=STRING     Password for encrypted private key (will prompt interactively if needed and TTY is available) ($ST_KEY_PASSWORD)
  -o, --output=STRING           Output file (default: stdout) ($ST_OUTPUT)
  -p, --pretty                  Pretty-print XML output ($ST_PRETTY)
  -v, --verbose                 Enable verbose logging ($ST_VERBOSE)
```

### Encrypt Usage

```bash
./saml-tools encrypt --key=STRING [<input>] [flags]

Encrypt SAML assertions

Arguments:
  [<input>]    Input XML file (or stdin)

Flags:
  -h, --help                            Show context-sensitive help.
      --log-level="info"                Log level (trace,debug,info,warn,error) ($ST_LOG_LEVEL)
      --log-format="console"            Log format (console,json) ($ST_LOG_FORMAT)
  -t, --timeout=5s                      Request timeout duration ($ST_TIMEOUT)
  -k, --key=STRING                      Public key or X.509 certificate (PEM file or base64) ($ST_KEY)
  -o, --output=STRING                   Output file (default: stdout) ($ST_OUTPUT)
      --target-node="saml:Assertion"    Target XML node to encrypt ($ST_TARGET_NODE)
  -a, --algorithm="rsa-oaep"            Key transport algorithm ($ST_ALGORITHM)
  -c, --cipher="aes128-cbc"             Payload cipher ($ST_CIPHER)
  -i, --include-cert                    Include certificate in KeyInfo ($ST_INCLUDE_CERT)
  -p, --pretty                          Pretty-print XML output ($ST_PRETTY)
```

### Examples

#### Show version

```bash
./saml-tools version
```

#### Decrypt from file with PEM key file

```bash
./saml-tools decrypt encrypted.xml --key private.pem
```

#### Decrypt with password-protected key

```bash
# Using --key-password flag
./saml-tools decrypt encrypted.xml --key private.pem --key-password mypassword

# Using environment variable
ST_KEY_PASSWORD=mypassword ./saml-tools decrypt encrypted.xml --key private.pem

# Interactive prompt (when TTY available)
./saml-tools decrypt encrypted.xml --key private.pem
# Enter key password: [hidden input]
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

### Password-Protected Keys

The `decrypt` command supports password-protected private keys (legacy PEM format). If a password is required and not provided via flag or environment variable, the tool will prompt interactively when a TTY is available.

```bash
# Generate password-protected private key (legacy PKCS#1 format)
openssl genrsa -aes256 -passout pass:mypassword -traditional -out private.pem 2048

# Extract public key (requires password)
openssl rsa -in private.pem -passin pass:mypassword -pubout -out public.pem
```

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

To generate a password-protected key:

```bash
# Generate password-protected private key
openssl genrsa -aes256 -passout pass:mypassword -traditional -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -passin pass:mypassword -pubout -out public.pem
```

## Supported Formats

The tool auto-detects the following input formats:

1. **Raw XML**: Files containing either `<saml:EncryptedAssertion>`, `<saml2:EncryptedAssertion>` or `<EncryptedAssertion>`
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
- Only RSA keys are supported (2048+ bits recommended).
- The tool does not validate SAML signatures, only decrypts encrypted assertions.
- When encrypting, the default algorithm is RSA-OAEP which is more secure than RSA-PKCS1.
- X.509 certificates can be included in the encrypted output to help recipients identify the encryption key.
