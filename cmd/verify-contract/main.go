// Command verify-contract validates the repository-owned Provider Contract
// lock and its immutable resource tree.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
)

func main() {
	lockPath := flag.String("lock", "compatibility/sandbox-runtime/contract.lock.json", "path to the local Provider Contract lock")
	sourceRoot := flag.String("source-root", ".", "path to the repository containing the locked Contract tree")
	flag.Parse()

	lock, err := contractlock.Load(*lockPath)
	if err != nil {
		fail("load Provider Contract lock", err)
	}
	report, err := contractlock.Verify(context.Background(), lock, *sourceRoot)
	if err != nil {
		fail("verify Provider Contract", err)
	}
	fmt.Printf("verified local Provider Contract namespace %s version %s at revision %s (tree %s)\n", lock.Contract.Namespace, lock.Contract.Version, report.LockedRevision, report.ContractTree)
}

func fail(operation string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
