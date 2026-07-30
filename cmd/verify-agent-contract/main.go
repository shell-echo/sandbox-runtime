package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
)

func main() {
	os.Exit(run())
}

func run() int {
	lockPath := flag.String("lock", "compatibility/agent-platform/contract.lock.json", "path to the local Contract lock")
	sourceRoot := flag.String("source-root", "", "path to a read-only agent-blueprints checkout")
	flag.Parse()
	if *sourceRoot == "" {
		fmt.Fprintln(os.Stderr, "verify Agent Contract: -source-root is required")
		return 2
	}
	lock, err := contractlock.Load(*lockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify Agent Contract: %v\n", err)
		return 1
	}
	report, err := contractlock.Verify(context.Background(), lock, *sourceRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify Agent Contract: %v\n", err)
		return 1
	}
	fmt.Printf("verified Agent Contract revision %s\n", report.LockedRevision)
	fmt.Printf("checkout HEAD: %s\n", report.CheckoutHead)
	fmt.Printf("Contract tree: %s\n", report.ContractTree)
	fmt.Printf("Contract manifest: %s\n", report.ManifestDigest)
	fmt.Printf("Provider OpenAPI: %s\n", report.OpenAPISHA256)
	fmt.Printf("Sandbox Suite: %s\n", report.SuiteDigest)
	return 0
}
