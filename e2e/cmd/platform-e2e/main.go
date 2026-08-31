// Command platform-e2e runs the candidate Agent Platform caller against the
// same independently launched Provider reference stack used by the E2E lock.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/orchestrator"
)

func main() {
	check := flag.Bool("check", false, "verify the locked Provider checkout and exit")
	providerRoot := flag.String("provider-root", "..", "parent sandbox-runtime checkout")
	evidenceRoot := flag.String("evidence-root", "evidence", "ignored evidence output root")
	sourceImage := flag.String("source-image", "docker.io/library/alpine:3.23", "multi-platform runtime image to pull")
	flag.Parse()

	provider, err := filepath.Abs(*providerRoot)
	if err == nil {
		err = lock.Verify(provider)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		fmt.Printf("provider=%s contract=%s tree=%s suite_cases=%d caller_kind=%s\n", lock.ProviderCommit, lock.ContractRevision, lock.ContractTree, lock.SuiteCases, orchestrator.CallerPlatformCandidate)
		return
	}

	moduleRoot, err := filepath.Abs(".")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := orchestrator.Run(ctx, orchestrator.Options{
		ModuleRoot: moduleRoot, ProviderRoot: provider, EvidenceRoot: *evidenceRoot,
		SourceImage: *sourceImage, CallerKind: orchestrator.CallerPlatformCandidate,
	})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("evidence=%s image=%s initial_scenarios=%d resume_scenarios=%d caller_kind=%s\n", result.EvidenceDirectory, result.RuntimeImage, result.InitialScenarios, result.ResumeScenarios, orchestrator.CallerPlatformCandidate)
}
