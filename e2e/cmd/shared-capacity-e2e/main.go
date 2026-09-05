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
	check := flag.Bool("check", false, "verify the locked Provider and shared-capacity inputs and exit")
	providerRoot := flag.String("provider-root", "..", "parent sandbox-runtime checkout")
	evidenceRoot := flag.String("evidence-root", "evidence/shared-capacity", "ignored shared-capacity evidence output root")
	flag.Parse()

	provider, err := filepath.Abs(*providerRoot)
	platform := "linux/" + runtime.GOARCH
	if err == nil {
		err = lock.VerifySharedCapacity(provider, platform)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		locked, err := lock.LoadSharedCapacity(provider, platform)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("provider=%s contract=%s tree=%s suite_cases=%d profile=%s platform=%s valkey=%s scenarios=%d\n",
			lock.ProviderCommit, lock.ContractRevision, lock.ContractTree, lock.SuiteCases,
			locked.EvidenceProfile, platform, locked.Valkey.IndexDigest, len(locked.Scenarios))
		return
	}

	moduleRoot, err := filepath.Abs(".")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	result, err := orchestrator.RunSharedCapacity(ctx, orchestrator.Options{
		ModuleRoot: moduleRoot, ProviderRoot: provider, EvidenceRoot: *evidenceRoot,
	})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("evidence=%s platform=%s scenarios=%d\n", result.EvidenceDirectory, result.Platform, result.Scenarios)
}
