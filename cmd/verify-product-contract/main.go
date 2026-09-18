// Command verify-product-contract validates the repository-owned Product
// Contract content lock and document structure.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/productcontract"
)

func main() {
	sourceRoot := flag.String("source-root", ".", "path to the repository containing the Product Contract")
	flag.Parse()
	report, err := productcontract.Verify(*sourceRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify Product Contract: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("verified Product Contract namespace %s version %s (%d resources; %d operations; tree %s)\n",
		report.Namespace, report.Version, report.ResourceCount, report.OperationCount, report.TreeDigest)
}
