//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
)

func main() {
	if err := phase6fdloader.Launch(); err != nil {
		// Only a fixed stage code is emitted; startup input, secrets, token and
		// container-bound identifiers never appear in diagnostics.
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
