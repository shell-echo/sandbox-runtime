package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/conformance"
)

func main() {
	var sourceRoot string
	var race bool
	var shuffle bool
	flag.StringVar(&sourceRoot, "source-root", ".", "repository source root")
	flag.BoolVar(&race, "race", false, "run each Suite case with the race detector")
	flag.BoolVar(&shuffle, "shuffle", false, "shuffle each Suite case")
	flag.Parse()

	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := conformance.Run(ctx, conformance.Options{
		SourceRoot: root, Race: race, Shuffle: shuffle,
	}, os.Stdout, os.Stderr)
	if err != nil {
		fail(err)
	}
	fmt.Printf(
		"executed local Provider Conformance Suite %s@%s/%s (%s, %s): %d cases; runner %s; toolchain %s; race=%t; shuffle=%t\n",
		report.SuiteID, report.SuiteVersion, report.ProfileID, report.SuiteDigestProfile, report.SuiteDigest, len(report.Cases),
		report.RunnerRevision, report.GoToolchain, report.Race, report.Shuffle,
	)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "run-conformance: %v\n", err)
	os.Exit(1)
}
