package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
)

func main() {
	check := flag.Bool("check", false, "verify the downstream-fencing lock and current Provider identity")
	providerRoot := flag.String("provider-root", "..", "parent sandbox-runtime checkout")
	flag.Parse()
	if flag.NArg() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if !*check {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing runner is not implemented; use -check to verify the lock only")
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
	locked, err := lock.LoadDownstreamFencing(provider, platform)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("provider=%s harness_baseline=%s contract=%s tree=%s suite_cases=%d suite_exercised=%t profile=%s platform=%s browser=%s valkey=%s scenarios=%d runner_implemented=false\n",
		locked.Sources.ProviderRevision, locked.Sources.HarnessBaseline, locked.Contract.Revision, locked.Contract.Tree,
		locked.Contract.SuiteCases, locked.Contract.SuiteExercised, locked.EvidenceProfile, platform,
		locked.BrowserImage.IndexDigest, locked.Valkey.IndexDigest, len(locked.Scenarios))
}
