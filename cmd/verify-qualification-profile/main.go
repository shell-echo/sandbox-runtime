// Command verify-qualification-profile verifies the locked P2.7a definition.
// It does not validate an execution report or claim that an external caller ran.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

func main() {
	sourceRoot := flag.String("source-root", ".", "path to the repository containing the qualification profile and locked Contract")
	flag.Parse()

	report, err := qualificationprofile.VerifyCodingShellV1(context.Background(), *sourceRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify P2.7a qualification profile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"verified P2.7a definition lock %s@%s (%s; schema %s; %d+%d cases; %d interactions); no external-caller result claimed\n",
		report.ProfileID, report.ProfileVersion, report.ProfileDigest, report.SchemaDigest,
		report.InitialCases, report.RestartCases, report.Interactions,
	)
}
