// Command verify-qualification-archive independently verifies one retained
// external-caller qualification checkpoint, evidence archive, and result envelope.
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

	"github.com/shell-echo/sandbox-runtime/internal/qualificationarchive"
)

var verifyQualificationBundle = qualificationarchive.VerifyBundle

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-qualification-archive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var sourceRoot, checkpointPath, archivePath, envelopePath string
	flags.StringVar(&sourceRoot, "source-root", ".", "repository source root containing the locked qualification definition")
	flags.StringVar(&checkpointPath, "checkpoint", "", "absolute execution checkpoint path")
	flags.StringVar(&archivePath, "archive", "", "absolute qualification evidence archive path")
	flags.StringVar(&envelopePath, "envelope", "", "absolute qualification result envelope path")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-archive: positional arguments are not supported")
		return 2
	}
	if strings.TrimSpace(checkpointPath) == "" || strings.TrimSpace(archivePath) == "" || strings.TrimSpace(envelopePath) == "" {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-archive: -checkpoint, -archive, and -envelope are required")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := verifyQualificationBundle(ctx, sourceRoot, checkpointPath, archivePath, envelopePath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-archive:", err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "verified qualification bundle %s (archive %s; report %s; run %s; validation %s; %d files; %d bytes)\n",
		result.EnvelopeDigest, result.ArchiveDigest, result.Evidence.ReportDigest, result.Evidence.RunOutcome,
		result.Evidence.ValidationOutcome, result.Evidence.FileCount, result.Evidence.TotalBytes); err != nil {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-archive: result_write_failed")
		return 1
	}
	return 0
}
