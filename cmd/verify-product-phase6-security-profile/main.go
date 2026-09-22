package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func main() {
	profilePath := flag.String("profile", "", "absolute mode-0600 Phase 6 security profile JSON")
	flag.Parse()
	if *profilePath == "" {
		fmt.Fprintln(os.Stderr, "-profile is required")
		os.Exit(2)
	}
	profile, err := phase6security.VerifyFile(*profilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Phase 6 security profile rejected")
		os.Exit(1)
	}
	fmt.Printf("verified %s revision %s digest %s (%d principals, %d trust edges, %d egress policies)\n",
		profile.Protocol, profile.Revision, profile.ProfileDigest, len(profile.Principals), len(profile.TrustEdges), len(profile.EgressPolicies))
}
