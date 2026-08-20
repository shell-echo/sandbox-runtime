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
	var lockPath string
	var race bool
	var shuffle bool
	flag.StringVar(&sourceRoot, "source-root", ".", "repository source root")
	flag.StringVar(&lockPath, "lock", "compatibility/sandbox-runtime/contract.lock.json", "relative or absolute Contract lock path")
	flag.BoolVar(&race, "race", false, "run each Suite case with the race detector")
	flag.BoolVar(&shuffle, "shuffle", false, "shuffle each Suite case")
	flag.Parse()

	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		fail(err)
	}
	if !filepath.IsAbs(lockPath) {
		lockPath = filepath.Join(root, lockPath)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := conformance.Run(ctx, conformance.Options{
		SourceRoot: root, LockPath: lockPath, Race: race, Shuffle: shuffle,
	}, os.Stdout, os.Stderr)
	if err != nil {
		fail(err)
	}
	fmt.Printf("executed local Provider Conformance Suite %s/%s: %d cases\n", report.SuiteID, report.ProfileID, len(report.Cases))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "run-conformance: %v\n", err)
	os.Exit(1)
}
