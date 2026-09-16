// Command verify-qualification-adapter-protocol verifies the locked P2.7c
// process-protocol and transcript-projection definitions. It does not execute
// or qualify a caller.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var verifyAdapterProtocol = qualificationadapterprotocol.VerifyDefinition

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-qualification-adapter-protocol", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var sourceRoot string
	flags.StringVar(&sourceRoot, "source-root", ".", "repository source root containing the locked qualification definition")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-adapter-protocol: positional arguments are not supported")
		return 2
	}
	report, err := verifyAdapterProtocol(context.Background(), sourceRoot)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "verify P2.7c qualification adapter protocol definitions:", err)
		return 1
	}
	if _, err := fmt.Fprintf(
		stdout,
		"verified P2.7c adapter protocol %s@%s (schema %s; semantics %s; transcript projection schema %s); no process execution or external-caller result claimed\n",
		report.ProtocolID,
		report.ProtocolVersion,
		report.SchemaDigest,
		report.SemanticsDigest,
		report.TranscriptSchemaDigest,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, "verify-qualification-adapter-protocol: result_write_failed")
		return 1
	}
	return 0
}
