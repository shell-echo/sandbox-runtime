package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/productphase4evidence"
)

func main() {
	manifestPath := flag.String("manifest", "docs/audits/product-phase-4-browser-evidence.json", "Product Phase 4 Browser evidence manifest")
	flag.Parse()
	manifest, err := productphase4evidence.VerifyFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify Product Phase 4 evidence: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Product Phase 4 Browser evidence passed: run=%s revision=%s scenarios=%d processes=%d tier=%s\n", manifest.RunID, manifest.SourceRevision, len(manifest.Scenarios), len(manifest.Processes), manifest.EvidenceTier)
}
