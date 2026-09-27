package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/phase6slice6admission"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-product-phase6-slice6-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "absolute path to the private Slice 6 manifest.json")
	bundleRoot := flags.String("bundle-root", "", "absolute path to the private receipt bundle")
	sourceRoot := flags.String("source-root", "", "absolute path to the clean source checkout")
	roleCandidateDir := flags.String("role-candidate-dir", "", "absolute path to the private role candidate directory")
	desktopCandidate := flags.String("desktop-candidate", "", "absolute path to the private current Desktop candidate manifest")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *manifestPath == "" || *bundleRoot == "" ||
		*sourceRoot == "" || *roleCandidateDir == "" || *desktopCandidate == "" {
		return errors.New("Slice 6 admission requires manifest, bundle-root, source-root, role-candidate-dir and desktop-candidate")
	}
	evidence, err := phase6slice6admission.Verify(context.Background(), phase6slice6admission.CandidateInputs{
		SourceRoot: *sourceRoot, RoleCandidateDir: *roleCandidateDir,
		DesktopCandidatePath: *desktopCandidate, ManifestPath: *manifestPath, BundleRoot: *bundleRoot,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "verified Slice 6 artifact and receipt admission: run %s, %d scenarios, manifest %s; execution origin still requires the trusted gate\n",
		evidence.RunID, len(evidence.Scenarios), evidence.ManifestDigest)
	return err
}
