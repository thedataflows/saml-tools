package main

import (
	"os"

	log "github.com/thedataflows/go-lib-log"
	"github.com/thedataflows/saml-tools/cmd"
)

var version = "dev"

func main() {
	log.SetGlobalLogger(log.GlobalLoggerBuilder().WithoutBuffering().Build())
	defer log.Close()
	err := cmd.Run(version, os.Args[1:])
	if err != nil {
		log.Errorf("main", err, "Command failed")
		os.Exit(1)
	}
}
