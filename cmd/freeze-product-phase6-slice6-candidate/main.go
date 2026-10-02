// freeze-product-phase6-slice6-candidate writes a source-bound desired
// security profile. It does not launch roles or produce Slice 6 evidence.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const inputSchema = "sandbox-runtime.phase6-slice6-composition.v3"

var errInvalidInput = errors.New("invalid Phase 6 Slice 6 candidate input")

type compositionFile struct {
	SchemaVersion            string                                   `json:"schema_version"`
	Images                   phase6profilebuilder.ImageDraftInputs    `json:"images"`
	TrustAnchors             map[string]string                        `json:"trust_anchors"`
	ExternalImages           phase6profilebuilder.ExternalImageInputs `json:"external_images"`
	DNSClientCA              phase6profilebuilder.DNSClientCAInput    `json:"dns_client_ca"`
	EgressKeys               map[string]string                        `json:"egress_keys"`
	CertificateKeys          map[string]string                        `json:"certificate_keys"`
	CredentialKeys           map[string]string                        `json:"credential_keys"`
	BreakGlassKeys           map[string]string                        `json:"break_glass_keys"`
	BreakGlassOperatorBinary string                                   `json:"break_glass_operator_binary"`
}

func main() {
	input := flag.String("input", "", "absolute private canonical composition input")
	output := flag.String("output", "", "absolute new private candidate profile")
	flag.Parse()
	if err := run(context.Background(), *input, *output, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "Phase 6 Slice 6 candidate freeze rejected:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, inputPath, outputPath string, now time.Time) error {
	if !cleanAbsolute(inputPath) || !cleanAbsolute(outputPath) || inputPath == outputPath ||
		!privateParent(inputPath) || !privateParent(outputPath) {
		return errInvalidInput
	}
	document, err := secretfile.Read(inputPath, 256<<10)
	if err != nil {
		return errInvalidInput
	}
	defer clear(document)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var input compositionFile
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.SchemaVersion != inputSchema {
		return errInvalidInput
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(canonical, document) {
		return errInvalidInput
	}
	candidate, err := phase6profilebuilder.ComposeSlice6CandidateProfile(ctx,
		phase6profilebuilder.CompositionInputs{Images: input.Images, TrustAnchors: input.TrustAnchors,
			ExternalImages: input.ExternalImages, DNSClientCA: input.DNSClientCA, EgressKeys: input.EgressKeys,
			CertificateKeys: input.CertificateKeys, CredentialKeys: input.CredentialKeys,
			BreakGlassKeys: input.BreakGlassKeys, BreakGlassOperatorBinary: input.BreakGlassOperatorBinary}, now)
	if err != nil {
		return err
	}
	if candidate.VerifySources(ctx, now) != nil {
		return phase6profilebuilder.ErrInvalidComposition
	}
	current, err := secretfile.Read(inputPath, 256<<10)
	if err != nil || !bytes.Equal(document, current) {
		clear(current)
		return errInvalidInput
	}
	clear(current)
	profileBytes, err := json.Marshal(candidate.Profile)
	if err != nil || len(profileBytes) > 2<<20 {
		return errInvalidInput
	}
	if _, err := phase6security.Decode(profileBytes); err != nil {
		return errInvalidInput
	}
	if err := writeExclusive(outputPath, profileBytes); err != nil {
		return err
	}
	fmt.Printf("candidate-only profile=%s revision=%s principals=%d; no live evidence or release acceptance\n",
		candidate.Profile.ProfileDigest, candidate.Profile.Revision, len(candidate.Profile.Principals))
	return nil
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func privateParent(path string) bool {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0o700 {
		return false
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Getuid())
}

func writeExclusive(path string, document []byte) error {
	if !cleanAbsolute(path) || !privateParent(path) {
		return errInvalidInput
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errInvalidInput
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(document); err != nil {
		_ = file.Close()
		return errInvalidInput
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errInvalidInput
	}
	if err := file.Close(); err != nil {
		return errInvalidInput
	}
	if _, err := phase6security.VerifyFile(path); err != nil {
		return errInvalidInput
	}
	complete = true
	return nil
}
