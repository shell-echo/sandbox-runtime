package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/orchestrator"
)

func main() {
	check := flag.Bool("check", false, "verify the downstream-fencing lock and current Provider identity")
	providerRoot := flag.String("provider-root", "..", "parent sandbox-runtime checkout")
	evidenceRoot := flag.String("evidence-root", "evidence/downstream-fencing", "downstream-fencing evidence output root")
	flag.Parse()
	if flag.NArg() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}

	provider, err := filepath.Abs(*providerRoot)
	platform := "linux/" + runtime.GOARCH
	if err == nil {
		err = lock.VerifyDownstreamFencing(provider, platform)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		locked, err := lock.LoadDownstreamFencing(provider, platform)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("provider=%s harness_baseline=%s contract=%s tree=%s suite_cases=%d suite_exercised=%t profile=%s platform=%s browser=%s valkey=%s scenarios=%d runner_entrypoint_present=true\n",
			locked.Sources.ProviderRevision, locked.Sources.HarnessBaseline, locked.Contract.Revision, locked.Contract.Tree,
			locked.Contract.SuiteCases, locked.Contract.SuiteExercised, locked.EvidenceProfile, platform,
			locked.BrowserImage.IndexDigest, locked.Valkey.IndexDigest, len(locked.Scenarios))
		return
	}

	moduleRoot, err := filepath.Abs(".")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	result, err := orchestrator.RunDownstreamFencing(ctx, orchestrator.Options{
		ModuleRoot: moduleRoot, ProviderRoot: provider, EvidenceRoot: *evidenceRoot,
	})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("evidence=%s platform=%s scenarios=%d\n", result.EvidenceDirectory, result.Platform, result.Scenarios)
}
