package productphase6slice5evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
)

type slice5RetainedFixture struct {
	root             string
	manifestPath     string
	recordPath       string
	manifestDocument []byte
	recordDocument   []byte
	manifest         Manifest
	record           ClosureRecord
}

func TestVerifyRetainedRepositoryPreservesHistoricalSlice5Claim(t *testing.T) {
	fixture := newSlice5RetainedFixture(t, false)
	result, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != RetainedMode || result.ClaimScope != RetainedClaimScope || result.CurrentHEADCovered || result.ManifestDigest != fixture.manifest.ManifestDigest {
		t.Fatalf("unexpected retained result: %#v", result)
	}
}

func TestVerifyRetainedRepositoryRejectsIllegalHistoryAndMutation(t *testing.T) {
	t.Run("runtime closure diff", func(t *testing.T) {
		fixture := newSlice5RetainedFixture(t, true)
		if _, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath); err == nil {
			t.Fatal("runtime closure transition accepted")
		}
	})
	t.Run("manifest mutation", func(t *testing.T) {
		fixture := newSlice5RetainedFixture(t, false)
		if err := os.WriteFile(fixture.manifestPath, append(fixture.manifestDocument, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath); err == nil {
			t.Fatal("mutated retained manifest accepted")
		}
	})
	t.Run("closure mutation", func(t *testing.T) {
		fixture := newSlice5RetainedFixture(t, false)
		if err := os.WriteFile(fixture.recordPath, append(fixture.recordDocument, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath); err == nil {
			t.Fatal("mutated retained closure record accepted")
		}
	})
}

func TestSlice5ClosureRecordRejectsNonCanonicalAndUnsafePaths(t *testing.T) {
	fixture := newSlice5RetainedFixture(t, false)
	duplicate := append([]byte(`{"id":"product-v1-phase-6-slice-5-closure",`), fixture.recordDocument[1:]...)
	if _, err := VerifyClosureRecord(duplicate); err == nil {
		t.Fatal("duplicate closure record member accepted")
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, fixture.recordDocument, "", "  ") != nil {
		t.Fatal("indent closure record")
	}
	if _, err := VerifyClosureRecord(pretty.Bytes()); err == nil {
		t.Fatal("non-canonical closure record accepted")
	}
	for _, candidate := range []string{"/tmp/evidence.json", "../evidence.json", `docs\\audits\\evidence.json`, "evidence.json"} {
		record := fixture.record
		record.RecordDigest = ""
		record.ArtifactPath = candidate
		if _, err := SealClosureRecord(record); err == nil {
			t.Fatalf("unsafe closure path %q accepted", candidate)
		}
	}
}

func newSlice5RetainedFixture(t *testing.T, illegalClosureDiff bool) slice5RetainedFixture {
	t.Helper()
	root := t.TempDir()
	runSlice5Git(t, root, "init", "-q")
	runSlice5Git(t, root, "config", "user.name", "Slice 5 Gate")
	runSlice5Git(t, root, "config", "user.email", "slice5@example.invalid")
	writeSlice5RepositoryFile(t, root, "implementation.go", "package implementation\n")
	writeSlice5RepositoryFile(t, root, "internal/productphase6slice5evidence/verify_test.go", "package productphase6slice5evidence\n")
	runSlice5Git(t, root, "add", ".")
	runSlice5Git(t, root, "commit", "-q", "-m", "runtime")
	runtimeRevision := runSlice5Git(t, root, "rev-parse", "HEAD")
	runtimeTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, runtimeRevision)
	if err != nil {
		t.Fatal(err)
	}
	writeSlice5RepositoryFile(t, root, "internal/productphase6slice5evidence/verify_test.go", "package productphase6slice5evidence\n\n// evidence-only regression\n")
	runSlice5Git(t, root, "add", ".")
	runSlice5Git(t, root, "commit", "-q", "-m", "evidence tool")
	evidenceRevision := runSlice5Git(t, root, "rev-parse", "HEAD")
	evidenceTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, evidenceRevision)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest(t)
	runtimeGate := manifest.RuntimeGate
	runtimeGate.Identity.RuntimeImplementationRevision = runtimeRevision
	runtimeGate.Identity.RuntimeImplementationTreeDigest = runtimeTree
	runtimeGate.Identity.EvidenceToolRevision = evidenceRevision
	runtimeGate.Identity.EvidenceToolTreeDigest = evidenceTree
	runtimeGate.ManifestDigest = ""
	runtimeGate, err = productphase6evidence.Seal(runtimeGate)
	if err != nil {
		t.Fatal(err)
	}
	manifest.RuntimeGate = runtimeGate
	manifest.RecordingTransitAdapter.RuntimeImplementationRevision = runtimeRevision
	manifest.RecordingTransitAdapter.RuntimeImplementationTreeDigest = runtimeTree
	manifest.RecordingTransitAdapter.EvidenceToolRevision = evidenceRevision
	manifest.RecordingTransitAdapter.EvidenceToolTreeDigest = evidenceTree
	manifest.RecordingTransitAdapter.EvidenceDigest = RecordingEvidenceDigest(manifest.RecordingTransitAdapter)
	manifest.ManifestDigest = ""
	manifest, err = Seal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDocument, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := "docs/audits/product-phase-6-slice-5-evidence.json"
	recordRelativePath := "docs/audits/product-phase-6-slice-5-closure.json"
	writeSlice5RepositoryFile(t, root, artifactPath, string(manifestDocument))
	writeSlice5RepositoryFile(t, root, "README.md", "Slice 5 closed\n")
	if illegalClosureDiff {
		writeSlice5RepositoryFile(t, root, "closure-runtime.go", "package implementation\n")
	}
	runSlice5Git(t, root, "add", ".")
	runSlice5Git(t, root, "commit", "-q", "-m", "close Slice 5")
	closureRevision := runSlice5Git(t, root, "rev-parse", "HEAD")
	record, err := NewClosureRecord(manifestDocument, manifest, closureRevision, artifactPath, recordRelativePath)
	if err != nil {
		t.Fatal(err)
	}
	recordDocument, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeSlice5RepositoryFile(t, root, recordRelativePath, string(recordDocument))
	runSlice5Git(t, root, "add", ".")
	runSlice5Git(t, root, "commit", "-q", "-m", "register Slice 5 closure")
	writeSlice5RepositoryFile(t, root, "successor.go", "package implementation\n")
	runSlice5Git(t, root, "add", ".")
	runSlice5Git(t, root, "commit", "-q", "-m", "successor source")
	manifestPath := filepath.Join(root, filepath.FromSlash(artifactPath))
	if err := os.Chmod(manifestPath, 0o600); err != nil {
		t.Fatal(err)
	}
	return slice5RetainedFixture{
		root: root, manifestPath: manifestPath, recordPath: filepath.Join(root, filepath.FromSlash(recordRelativePath)),
		manifestDocument: manifestDocument, recordDocument: recordDocument, manifest: manifest, record: record,
	}
}

func writeSlice5RepositoryFile(t *testing.T, root, name, value string) {
	t.Helper()
	filePath := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runSlice5Git(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	document, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, document)
	}
	return strings.TrimSpace(string(document))
}
