package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	slice5evidence "github.com/shell-echo/sandbox-runtime/internal/productphase6slice5evidence"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-product-phase6-slice5-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "finalization", "verification mode: finalization, closure, or retained")
	manifestPath := flags.String("manifest", "", "absolute path to the observed Slice 5 evidence manifest")
	sourceRoot := flags.String("source-root", "", "absolute repository root containing the bound revisions")
	slice := flags.String("slice", "", "explicit retained slice ID")
	closureRecordPath := flags.String("closure-record", "", "absolute path to the retained Slice 5 closure record")
	artifactPath := flags.String("artifact-path", "", "repository-relative path of the archived Slice 5 manifest")
	closureArtifactPath := flags.String("closure-artifact-path", "", "repository-relative path of the Slice 5 closure record")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *manifestPath == "" || *sourceRoot == "" {
		return errors.New("Slice 5 evidence verifier requires absolute manifest and source-root arguments")
	}
	if *mode == "finalization" && (*slice != "" || *closureRecordPath != "" || *artifactPath != "" || *closureArtifactPath != "") {
		return errors.New("closure and retained flags are forbidden in finalization mode")
	}
	if *mode == "closure" && (*slice != "" || *closureRecordPath != "" || *artifactPath == "" || *closureArtifactPath == "") {
		return errors.New("closure mode requires artifact and closure-artifact paths only")
	}
	if *mode == slice5evidence.RetainedMode && (*slice != slice5evidence.ManifestID || *closureRecordPath == "" || *artifactPath != "" || *closureArtifactPath != "") {
		return errors.New("retained mode requires the explicit Slice 5 identity and closure record")
	}
	if *mode != "finalization" && *mode != "closure" && *mode != slice5evidence.RetainedMode {
		return errors.New("unsupported Slice 5 evidence verification mode")
	}
	manifest, err := slice5evidence.VerifyFile(*manifestPath)
	if err != nil {
		return err
	}
	if *mode == slice5evidence.RetainedMode {
		record, err := slice5evidence.VerifyClosureRecordFile(*closureRecordPath)
		if err != nil {
			return err
		}
		result, err := slice5evidence.VerifyRetainedRepository(manifest, record, *slice, *sourceRoot, *manifestPath, *closureRecordPath)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(result)
	}
	if err := productphase6evidence.VerifyRepository(manifest.RuntimeGate, *sourceRoot); err != nil {
		return err
	}
	if *mode == "closure" {
		relative, err := filepath.Rel(*sourceRoot, *manifestPath)
		if err != nil || filepath.ToSlash(relative) != *artifactPath {
			return errors.New("Slice 5 closure artifact path does not bind the manifest")
		}
		command := exec.Command("git", "rev-parse", "HEAD")
		command.Dir = *sourceRoot
		document, err := command.Output()
		if err != nil {
			return errors.New("read Slice 5 closure revision")
		}
		manifestDocument, err := os.ReadFile(*manifestPath)
		if err != nil {
			return errors.New("read Slice 5 closure manifest")
		}
		record, err := slice5evidence.NewClosureRecord(manifestDocument, manifest, strings.TrimSpace(string(document)), *artifactPath, *closureArtifactPath)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(record)
	}
	_, err = fmt.Fprintf(output, "verified %s version %s manifest %s (6 roles, 2 real gates)\n", manifest.ID, manifest.Version, manifest.ManifestDigest)
	return err
}
