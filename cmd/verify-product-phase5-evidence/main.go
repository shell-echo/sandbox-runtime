package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/productphase5evidence"
)

func main() {
	manifestPath := flag.String("manifest", "docs/audits/product-phase-5-desktop-evidence.json", "Product Phase 5 Desktop evidence manifest")
	flag.Parse()
	manifest, err := productphase5evidence.VerifyFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify Product Phase 5 evidence: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Product Phase 5 Desktop evidence passed: run=%s revision=%s scenarios=%d processes=%d tier=%s\n", manifest.RunID, manifest.SourceRevision, len(manifest.Scenarios), len(manifest.Processes), manifest.EvidenceTier)
}
