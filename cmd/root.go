package cmd

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/joho/godotenv"
	log "github.com/thedataflows/go-lib-log"
)

const (
	PKG_CMD  = "cmd"
	APP_NAME = "saml-tools"
)

type Globals struct {
	LogLevel  string        `help:"Log level (trace,debug,info,warn,error)" default:"info"`
	LogFormat string        `help:"Log format (console,json)" default:"console"`
	Timeout   time.Duration `short:"t" help:"Request timeout duration" default:"5s"`
}

// CLI represents the main CLI structure
type CLI struct {
	Globals `kong:"embed"`
	Version VersionCmd `cmd:"" help:"Show version information"`
	Decrypt DecryptCmd `cmd:"" help:"Decrypt SAML assertions"`
}

// AfterApply is called after Kong parses the CLI but before the command runs
func (cli *CLI) AfterApply(ctx *kong.Context) error {
	// Skip initialization for version command
	if ctx.Command() == "version" || slices.Contains(ctx.Args, "--help") || slices.Contains(ctx.Args, "-h") {
		return nil
	}

	// Set log level and format
	if err := log.SetGlobalLoggerLogLevel(cli.LogLevel); err != nil {
		return fmt.Errorf("set log level: %w", err)
	}

	if err := log.SetGlobalLoggerLogFormat(cli.LogFormat); err != nil {
		return fmt.Errorf("set log format: %w", err)
	}

	return nil
}

// CreateContextWithTimeout creates a context with the configured timeout
func (g *Globals) CreateContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), g.effectiveTimeout())
}

func (g *Globals) effectiveTimeout() time.Duration {
	if g.Timeout <= 0 {
		return 5 * time.Second
	}
	if g.Timeout < time.Second {
		return g.Timeout * time.Second
	}
	return g.Timeout
}

// Run executes the CLI with the given version
func Run(version string, args []string) error {
	// Optionally load .env file if it exists
	_ = godotenv.Load(
		".env",             // Current directory
		".local.env",       // Local overrides (common in web development)
		".development.env", // Development environment
	)

	var cli CLI

	parser, err := kong.New(&cli,
		kong.Name(APP_NAME),
		kong.Description("A toolkit for working with SAML assertions"),
		kong.Configuration(kongyaml.Loader),
		kong.UsageOnError(),
		kong.DefaultEnvars(""),
	)
	if err != nil {
		return fmt.Errorf("create CLI parser: %w", err)
	}

	ctx, err := parser.Parse(args)
	if slices.Contains(args, "--help") || slices.Contains(args, "-h") {
		return nil
	}
	if err != nil {
		parser.FatalIfErrorf(err)
		return err
	}

	// Check if this is the version command - handle it specially without logging/config
	if ctx.Command() == "version" {
		return ctx.Run(version)
	}

	log.Logger().Info().Str(log.KEY_PKG, PKG_CMD).Str("app", ctx.Model.Name).Str("version", version).Msg("Starting application")

	return ctx.Run(ctx, &cli)
}
