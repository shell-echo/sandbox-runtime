package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-product-phase6-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "absolute path to the observed Slice 4 evidence manifest")
	sourceRoot := flags.String("source-root", "", "absolute repository root containing the implementation revision")
	mode := flags.String("mode", "finalization", "verification mode: finalization or retained")
	slice := flags.String("slice", "", "explicit retained slice ID")
	closureRecordPath := flags.String("closure-record", "", "absolute path to the retained slice closure record")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid Phase 6 evidence verifier arguments")
	}
	if *mode != "finalization" && *mode != productphase6evidence.RetainedMode {
		return errors.New("invalid Phase 6 evidence verification mode")
	}
	if *mode == "finalization" && (*slice != "" || *closureRecordPath != "") {
		return errors.New("retained flags are forbidden in finalization mode")
	}
	if *mode == productphase6evidence.RetainedMode && (*slice == "" || *manifestPath == "" || *closureRecordPath == "" || *sourceRoot == "") {
		return errors.New("retained mode requires explicit slice, manifest, closure record, and source root")
	}
	if *mode == productphase6evidence.RetainedMode && *slice != productphase6evidence.ManifestID {
		return errors.New("unsupported Phase 6 retained slice")
	}
	manifest, err := productphase6evidence.VerifyFile(*manifestPath)
	if err != nil {
		return err
	}
	if *mode == "finalization" {
		if err := productphase6evidence.VerifyRepository(manifest, *sourceRoot); err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "verified %s version %s manifest %s (%d roles, %d scenarios)\n", manifest.ID, manifest.Version, manifest.ManifestDigest, len(manifest.Roles), len(manifest.Scenarios))
		return err
	}
	record, err := productphase6evidence.VerifyClosureRecordFile(*closureRecordPath)
	if err != nil {
		return err
	}
	result, err := productphase6evidence.VerifyRetainedRepository(manifest, record, *slice, *sourceRoot, *manifestPath, *closureRecordPath)
	if err != nil {
		return err
	}
	document, err := json.Marshal(result)
	if err != nil {
		return errors.New("encode Phase 6 retained verification result")
	}
	_, err = fmt.Fprintln(output, string(document))
	return err
}
