package main

import (
	"fmt"
	"os"

	"github.com/KatrielMoses/PhoneAccess/internal/cli"
	"github.com/KatrielMoses/PhoneAccess/internal/modules"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	root := cli.NewRootCommand(version, buildDate, modules.Registry())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
