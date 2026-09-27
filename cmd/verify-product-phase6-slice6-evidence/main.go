package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-product-phase6-slice6-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "absolute path to the private Slice 6 manifest.json")
	bundleRoot := flags.String("bundle-root", "", "absolute path to the private receipt bundle")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *manifestPath == "" || *bundleRoot == "" {
		return errors.New("Slice 6 bundle verifier requires manifest and bundle-root arguments")
	}
	evidence, err := phase6security.VerifySlice6EvidenceBundle(*manifestPath, *bundleRoot)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "verified Slice 6 bundle consistency: run %s, %d scenarios, manifest %s; execution origin requires the trusted gate\n",
		evidence.RunID, len(evidence.Scenarios), evidence.ManifestDigest)
	return err
}
