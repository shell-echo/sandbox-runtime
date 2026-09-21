package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
)

func main() {
	path := flag.String("manifest", "", "absolute path to the observed Slice 4 evidence manifest")
	sourceRoot := flag.String("source-root", "", "absolute repository root containing the implementation revision")
	flag.Parse()
	manifest, err := productphase6evidence.VerifyFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := productphase6evidence.VerifyRepository(manifest, *sourceRoot); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("verified %s version %s manifest %s (%d roles, %d scenarios)\n", manifest.ID, manifest.Version, manifest.ManifestDigest, len(manifest.Roles), len(manifest.Scenarios))
}
