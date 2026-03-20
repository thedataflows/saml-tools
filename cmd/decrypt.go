package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/beevik/etree"
	log "github.com/thedataflows/go-lib-log"
	"github.com/thedataflows/saml-tools/format"
	"github.com/thedataflows/saml-tools/key"
	"github.com/thedataflows/saml-tools/saml"
	"golang.org/x/term"
)

type DecryptCmd struct {
	Input       string `arg:"" optional:"" help:"SAML assertion file (or stdin if omitted)" type:"existingfile"`
	Key         string `short:"k" required:"" help:"Private key (PEM file path or base64 string)"`
	KeyPassword string `env:"ST_KEY_PASSWORD" help:"Password for encrypted private key (will prompt interactively if needed and TTY is available)"`
	Output      string `short:"o" help:"Output file (default: stdout)" type:"path"`
	Pretty      bool   `short:"p" help:"Pretty-print XML output"`
	Verbose     bool   `short:"v" help:"Enable verbose logging"`
}

func (d *DecryptCmd) Run() error {
	log.Logger().Info().Msg("Starting saml decrypt")

	// Create services
	keyLoader := key.NewLoader()
	formatDetector := format.NewDetector()
	decrypter := saml.NewDecrypter(saml.Config{})
	log.Logger().Debug().Msg("Services initialized")

	// Load private key
	log.Logger().Debug().Str("key_source", maskKey(d.Key)).Msg("Loading private key")
	privateKey, err := d.loadPrivateKey(keyLoader)
	if err != nil {
		log.Logger().Error().
			Err(err).
			Str("key_source", maskKey(d.Key)).
			Msg("Failed to load private key")
		return fmt.Errorf("failed to load private key: %w", err)
	}
	log.Logger().Debug().Msg("Private key loaded successfully")

	// Read input data
	var inputData []byte
	if d.Input == "" {
		log.Logger().Debug().Msg("Reading input from stdin")
		inputData, err = readStdin()
		if err != nil {
			log.Logger().Error().Err(err).Msg("Failed to read from stdin")
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		log.Logger().Debug().Int("bytes_read", len(inputData)).Msg("Read data from stdin")
	} else {
		log.Logger().Debug().Str("file", d.Input).Msg("Reading input from file")
		inputData, err = os.ReadFile(d.Input)
		if err != nil {
			log.Logger().Error().
				Err(err).
				Str("file", d.Input).
				Msg("Failed to read input file")
			return fmt.Errorf("failed to read input file: %w", err)
		}
		log.Logger().Debug().Int("bytes_read", len(inputData)).Msg("Read data from file")
	}

	if len(inputData) == 0 {
		log.Logger().Error().Msg("No input data provided")
		return fmt.Errorf("no input data provided")
	}

	// Detect format and decode if necessary
	log.Logger().Debug().Msg("Detecting input format")
	detectedFormat := formatDetector.Detect(inputData)
	log.Logger().Debug().Int("format", int(detectedFormat)).Msg("Format detected")

	var encryptedData []byte

	switch detectedFormat {
	case format.FormatRawXML:
		log.Logger().Debug().Msg("Input format: Raw XML")
		encryptedData = inputData
	case format.FormatBase64:
		log.Logger().Debug().Msg("Input format: Base64")
		decoded, err := decodeBase64(inputData)
		if err != nil {
			log.Logger().Error().Err(err).Msg("Failed to decode base64")
			return fmt.Errorf("failed to decode base64: %w", err)
		}
		log.Logger().Debug().Int("decoded_bytes", len(decoded)).Msg("Base64 decoded successfully")
		encryptedData = decoded
	case format.FormatHTTPPost:
		log.Logger().Debug().Msg("Input format: HTTP POST")
		response, err := extractSAMLResponse(inputData)
		if err != nil {
			log.Logger().Error().Err(err).Msg("Failed to extract SAML response")
			return fmt.Errorf("failed to extract SAML response: %w", err)
		}
		log.Logger().Debug().Int("extracted_bytes", len(response)).Msg("SAML response extracted")
		encryptedData = response
	default:
		log.Logger().Error().Int("format", int(detectedFormat)).Msg("Unable to detect input format")
		return fmt.Errorf("unable to detect input format")
	}

	// Decrypt
	log.Logger().Debug().Msg("Starting decryption")
	decrypted, err := decrypter.Decrypt(encryptedData, privateKey)
	if err != nil {
		log.Logger().Error().Err(err).Msg("Decryption failed")
		return fmt.Errorf("decryption failed: %w", err)
	}
	log.Logger().Debug().Int("decrypted_bytes", len(decrypted)).Msg("Decryption successful")

	// Pretty print if requested
	output := decrypted
	if d.Pretty {
		log.Logger().Debug().Msg("Pretty-printing XML output")
		output = prettyPrintXML(decrypted)
		log.Logger().Debug().Int("output_bytes", len(output)).Msg("XML pretty-printed")
	}

	// Write output
	if d.Output == "" {
		log.Logger().Debug().Msg("Writing output to stdout")
		fmt.Print(string(output))
	} else {
		log.Logger().Debug().Str("file", d.Output).Msg("Writing output to file")
		if err := os.WriteFile(d.Output, output, 0600); err != nil {
			log.Logger().Error().
				Err(err).
				Str("file", d.Output).
				Msg("Failed to write output file")
			return fmt.Errorf("failed to write output file: %w", err)
		}
		log.Logger().Debug().Msg("Output written successfully")
	}

	log.Logger().Debug().Msg("saml-decrypt completed successfully")
	return nil
}

// loadPrivateKey loads the private key, prompting for password if needed and TTY is available
func (d *DecryptCmd) loadPrivateKey(loader key.Loader) (interface{}, error) {
	// First try without password
	privateKey, err := loader.Load(d.Key)
	if err == nil {
		return privateKey, nil
	}

	// If it's not a password issue, return the error
	if !errors.Is(err, key.ErrPasswordProtected) {
		return nil, err
	}

	// Key is password-protected
	password := d.KeyPassword

	// If no password provided, try to prompt interactively
	if password == "" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprint(os.Stderr, "Enter key password: ")
			passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %w", err)
			}
			password = string(passwordBytes)
		} else {
			return nil, fmt.Errorf("password-protected key requires --key-password flag or ST_KEY_PASSWORD environment variable (no TTY available for interactive prompt)")
		}
	}

	// Try loading with the password
	privateKey, err = loader.LoadWithPassword(d.Key, password)
	if err != nil {
		if errors.Is(err, key.ErrWrongPassword) {
			return nil, fmt.Errorf("incorrect password for private key")
		}
		return nil, err
	}

	return privateKey, nil
}

func maskKey(k string) string {
	if len(k) > 20 {
		return k[:10] + "..." + k[len(k)-10:]
	}
	return "[masked]"
}

func readStdin() ([]byte, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Mode()&os.ModeCharDevice != 0 {
		return nil, fmt.Errorf("no data provided on stdin")
	}

	data := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
	}
	return data, nil
}

func decodeBase64(data []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(data))
}

func extractSAMLResponse(data []byte) ([]byte, error) {
	content := string(data)
	if idx := strings.Index(content, "SAMLResponse="); idx != -1 {
		value := content[idx+len("SAMLResponse="):]
		if ampIdx := strings.Index(value, "&"); ampIdx != -1 {
			value = value[:ampIdx]
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return nil, err
		}
		return decodeBase64([]byte(decoded))
	}
	return nil, fmt.Errorf("SAMLResponse not found")
}

func prettyPrintXML(data []byte) []byte {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return data
	}
	doc.Indent(2)
	result, err := doc.WriteToBytes()
	if err != nil {
		return data
	}
	return result
}
