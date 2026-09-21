package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profile"
)

func main() {
	path := flag.String("profile", "", "absolute mode-0600 Phase 6 release profile JSON")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "-profile is required")
		os.Exit(2)
	}
	profile, err := phase6profile.VerifyFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Phase 6 release profile rejected: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Phase 6 release profile passed: revision=%s profile_digest=%s roles=%d\n", profile.Revision, profile.ProfileDigest, len(profile.Roles))
}
