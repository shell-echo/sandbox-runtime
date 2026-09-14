// Command verify-qualification-report validates one bounded external-caller
// evidence root and writes its non-overwriting validator receipt.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

var verifyQualificationReport = qualificationreport.Verify

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-qualification-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var sourceRoot string
	var evidenceRoot string
	flags.StringVar(&sourceRoot, "source-root", ".", "repository source root containing the locked qualification definition")
	flags.StringVar(&evidenceRoot, "evidence-root", "", "required path to the complete sanitized qualification evidence root")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-report: positional arguments are not supported")
		return 2
	}
	if strings.TrimSpace(evidenceRoot) == "" {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-report: -evidence-root is required")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := verifyQualificationReport(ctx, evidenceRoot, sourceRoot)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-report:", err)
		return 1
	}
	if _, err := fmt.Fprintf(
		stdout,
		"verified qualification report %s (%s; payload %s; run %s; %d files; %d bytes); validation %s; receipt %s\n",
		result.ReportID,
		result.ReportDigest,
		result.PayloadInventory,
		result.RunOutcome,
		result.FileCount,
		result.TotalBytes,
		result.ValidationOutcome,
		result.ReceiptFile,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-report: result_write_failed")
		return 1
	}
	return 0
}
