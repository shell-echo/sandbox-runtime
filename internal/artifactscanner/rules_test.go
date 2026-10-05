package artifactscanner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These deliberately tiny files exercise only our snapshot binding. They are
// not ClamAV rules or evidence that a daemon loaded official signatures.
func testRuleSnapshot(t *testing.T) (*RuleVerifier, RuleManifest, string) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "rules")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := RuleManifest{Protocol: RuleSnapshotProtocol,
		EngineImageDigest: scanDigest([]byte("image")), EngineConfigDigest: scanDigest([]byte("config")),
		TrustedCheckAt:       time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		CurrentReceiptDigest: scanDigest([]byte("operator receipt"))}
	for _, family := range []string{"bytecode", "daily", "main"} {
		name := family + ".cvd"
		content := []byte("test-only:" + family)
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, RuleFile{Name: name, Version: 1,
			SizeBytes: int64(len(content)), Digest: scanDigest(content)})
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	writeTestRuleManifest(t, manifestPath, manifest)
	verifier, err := NewRuleVerifier(RuleVerifierConfig{ManifestPath: manifestPath, RulesDirectory: directory,
		ExpectedRuleSet:     scanDigest(payload),
		ExpectedEngineImage: manifest.EngineImageDigest, ExpectedEngineConfig: manifest.EngineConfigDigest,
		VersionFloor: RuleVersionFloor{Main: 1, Daily: 1, Bytecode: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return verifier, manifest, directory
}

func writeTestRuleManifest(t *testing.T, path string, manifest RuleManifest) {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRuleVerifierBindsProfileSnapshotAndActualBytes(t *testing.T) {
	verifier, _, directory := testRuleSnapshot(t)
	if digest, err := verifier.Verify(context.Background(), time.Now().UTC()); err != nil || digest != verifier.config.ExpectedRuleSet {
		t.Fatalf("verified snapshot = %q, %v", digest, err)
	}
	if err := os.WriteFile(filepath.Join(directory, "daily.cvd"), []byte("test-only:DAILY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), time.Now().UTC()); !errors.Is(err, ErrRulesUnavailable) {
		t.Fatalf("mutated rule bytes = %v", err)
	}
}

func TestRuleVerifierRejectsFreshnessManifestAndDirectoryDrift(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		verifier, _, _ := testRuleSnapshot(t)
		if _, err := verifier.Verify(context.Background(), time.Now().Add(RuleMaxAge+2*time.Hour)); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("stale profile check = %v", err)
		}
	})
	t.Run("future", func(t *testing.T) {
		verifier, _, _ := testRuleSnapshot(t)
		if _, err := verifier.Verify(context.Background(), time.Now().Add(-2*time.Hour)); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("future profile check = %v", err)
		}
	})
	t.Run("manifest profile digest", func(t *testing.T) {
		verifier, manifest, _ := testRuleSnapshot(t)
		manifest.CurrentReceiptDigest = scanDigest([]byte("unreviewed replacement"))
		writeTestRuleManifest(t, verifier.config.ManifestPath, manifest)
		if _, err := verifier.Verify(context.Background(), time.Now()); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("unreviewed manifest = %v", err)
		}
	})
	t.Run("clock rollback", func(t *testing.T) {
		verifier, _, _ := testRuleSnapshot(t)
		now := time.Now().UTC()
		if _, err := verifier.Verify(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(context.Background(), now.Add(-time.Second)); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("rollback = %v", err)
		}
		if _, err := verifier.Verify(context.Background(), now.Add(time.Second)); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("rollback latch = %v", err)
		}
	})
	t.Run("extra", func(t *testing.T) {
		verifier, _, directory := testRuleSnapshot(t)
		if err := os.WriteFile(filepath.Join(directory, "extra.ndb"), []byte("unreviewed"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(context.Background(), time.Now()); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("extra rule = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		verifier, _, directory := testRuleSnapshot(t)
		original := filepath.Join(directory, "main.cvd")
		moved := filepath.Join(t.TempDir(), "main.cvd")
		if err := os.Rename(original, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, original); err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(context.Background(), time.Now()); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("symlink rule = %v", err)
		}
	})
	t.Run("manifest permissions", func(t *testing.T) {
		verifier, _, _ := testRuleSnapshot(t)
		if err := os.Chmod(verifier.config.ManifestPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(context.Background(), time.Now()); !errors.Is(err, ErrRulesUnavailable) {
			t.Fatalf("public manifest = %v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		verifier, _, _ := testRuleSnapshot(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := verifier.Verify(ctx, time.Now()); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled verification = %v", err)
		}
	})
}
