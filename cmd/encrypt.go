// Package cmd provides CLI commands for the SAML tools.
package cmd

import (
	"fmt"
	"os"

	log "github.com/thedataflows/go-lib-log"
	"github.com/thedataflows/saml-tools/key"
	"github.com/thedataflows/saml-tools/saml"
)

// EncryptCmd provides the encrypt subcommand
type EncryptCmd struct {
	Input       string `arg:"" optional:"" help:"Input XML file (or stdin)" type:"existingfile"`
	Key         string `short:"k" required:"" help:"Public key or X.509 certificate (PEM file or base64)"`
	Output      string `short:"o" help:"Output file (default: stdout)" type:"path"`
	Algorithm   string `short:"a" help:"Key transport algorithm" enum:"rsa-oaep,rsa-pkcs1" default:"rsa-oaep"`
	Cipher      string `short:"c" help:"Payload cipher" enum:"aes128-cbc,aes256-cbc,aes128-gcm,aes256-gcm" default:"aes128-cbc"`
	IncludeCert bool   `short:"i" help:"Include certificate in KeyInfo" default:"true"`
	Pretty      bool   `short:"p" help:"Pretty-print XML output"`
}

// Run executes the encrypt command
func (e *EncryptCmd) Run() error {
	log.Logger().Info().Msg("Starting saml encrypt")

	// Create services
	keyLoader := key.NewPublicKeyLoader()
	encrypter := saml.NewEncrypter()
	log.Logger().Debug().Msg("Services initialized")

	// Load public key
	log.Logger().Debug().Str("key_source", maskKey(e.Key)).Msg("Loading public key")
	pubKey, cert, err := keyLoader.LoadPublicKey(e.Key)
	if err != nil {
		log.Logger().Error().
			Err(err).
			Str("key_source", maskKey(e.Key)).
			Msg("Failed to load public key")
		return fmt.Errorf("failed to load public key: %w", err)
	}
	log.Logger().Debug().
		Bool("has_certificate", cert != nil).
		Msg("Public key loaded successfully")

	// Read input data
	var inputData []byte
	if e.Input == "" {
		log.Logger().Debug().Msg("Reading input from stdin")
		inputData, err = readStdin()
		if err != nil {
			log.Logger().Error().Err(err).Msg("Failed to read from stdin")
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		log.Logger().Debug().Int("bytes_read", len(inputData)).Msg("Read data from stdin")
	} else {
		log.Logger().Debug().Str("file", e.Input).Msg("Reading input from file")
		inputData, err = os.ReadFile(e.Input)
		if err != nil {
			log.Logger().Error().
				Err(err).
				Str("file", e.Input).
				Msg("Failed to read input file")
			return fmt.Errorf("failed to read input file: %w", err)
		}
		log.Logger().Debug().Int("bytes_read", len(inputData)).Msg("Read data from file")
	}

	if len(inputData) == 0 {
		log.Logger().Error().Msg("No input data provided")
		return fmt.Errorf("no input data provided")
	}

	// Build encryption options
	opts := saml.EncryptOptions{
		KeyTransport:  e.Algorithm,
		PayloadCipher: e.Cipher,
	}

	// Include certificate if available and requested
	if e.IncludeCert && cert != nil {
		opts.Certificate = cert
		log.Logger().Debug().Msg("Including certificate in KeyInfo")
	}

	// Encrypt
	log.Logger().Debug().
		Str("algorithm", e.Algorithm).
		Str("cipher", e.Cipher).
		Msg("Starting encryption")

	encrypted, err := encrypter.Encrypt(inputData, pubKey, opts)
	if err != nil {
		log.Logger().Error().Err(err).Msg("Encryption failed")
		return fmt.Errorf("encryption failed: %w", err)
	}
	log.Logger().Debug().Int("encrypted_bytes", len(encrypted)).Msg("Encryption successful")

	// Pretty print if requested
	output := encrypted
	if e.Pretty {
		log.Logger().Debug().Msg("Pretty-printing XML output")
		output = prettyPrintXML(encrypted)
		log.Logger().Debug().Int("output_bytes", len(output)).Msg("XML pretty-printed")
	}

	// Write output
	if e.Output == "" {
		log.Logger().Debug().Msg("Writing output to stdout")
		fmt.Print(string(output))
	} else {
		log.Logger().Debug().Str("file", e.Output).Msg("Writing output to file")
		if err := os.WriteFile(e.Output, output, 0600); err != nil {
			log.Logger().Error().
				Err(err).
				Str("file", e.Output).
				Msg("Failed to write output file")
			return fmt.Errorf("failed to write output file: %w", err)
		}
		log.Logger().Debug().Msg("Output written successfully")
	}

	log.Logger().Debug().Msg("saml encrypt completed successfully")
	return nil
}
