// control-pin prepares only the independently supplied public-key commitment.
// It never reads a Profile, runtime environment pin or private signing key.
package main

import (
	"fmt"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	b, e := secretfile.Read(os.Args[1], 32)
	if e != nil || len(b) != 32 {
		fmt.Fprintln(os.Stderr, "independent mode-0600 public key required")
		os.Exit(1)
	}
	fmt.Print(controldelivery.Digest(b))
}
