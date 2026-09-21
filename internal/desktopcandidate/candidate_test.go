package desktopcandidate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCandidateBindsCurrentSourceAndRoundTripsCanonically(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	candidate, err := New(root, "linux/arm64/v8", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.VerifySource(root); err != nil {
		t.Fatal(err)
	}
	committedDigest, err := SourceTreeDigestAtRevision(root, candidate.SourceRevision)
	if err != nil {
		t.Fatal(err)
	}
	// A dirty working tree is intentionally distinct from the immutable
	// revision, but a clean checkout must reproduce the same digest.
	if status, statusErr := gitOutput(root, "status", "--porcelain"); statusErr == nil && status == "" && committedDigest != candidate.SourceTreeDigest {
		t.Fatalf("committed tree digest = %s, working tree digest = %s", committedDigest, candidate.SourceTreeDigest)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "candidate.json")
	if err := Save(path, candidate); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded != candidate {
		t.Fatalf("loaded candidate differs: err=%v", err)
	}
	loaded.Classification = "production"
	if !errors.Is(loaded.Validate(), ErrInvalidCandidate) {
		t.Fatal("candidate was promoted to production classification")
	}
}

func TestCandidateRejectsUnknownDuplicateAndBroadFiles(t *testing.T) {
	for name, document := range map[string]string{
		"unknown":   `{"schema_version":"x","unknown":true}`,
		"duplicate": `{"schema_version":"x","schema_version":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "candidate.json")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); !errors.Is(err, ErrInvalidCandidate) {
				t.Fatalf("unsafe document error = %v", err)
			}
		})
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("broad candidate error = %v", err)
	}
}
