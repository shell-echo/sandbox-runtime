package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/productphase3evidence"
)

func main() {
	path := flag.String("manifest", "docs/audits/product-phase-3-standalone-evidence.json", "Product Phase 3 evidence manifest")
	flag.Parse()
	manifest, err := productphase3evidence.VerifyFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Product Phase 3 evidence passed: run=%s revision=%s scenarios=%d processes=%d tier=%s\n", manifest.RunID, manifest.SourceRevision, len(manifest.Scenarios), len(manifest.Processes), manifest.EvidenceTier)
}
