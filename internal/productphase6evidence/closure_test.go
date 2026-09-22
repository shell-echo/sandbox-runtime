package productphase6evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
)

type retainedFixtureOptions struct {
	illegalToolDiff    bool
	illegalClosureDiff bool
}

type retainedFixture struct {
	root             string
	manifestPath     string
	recordPath       string
	manifestDocument []byte
	recordDocument   []byte
	manifest         Manifest
	record           ClosureRecord
	runtimeRevision  string
	toolRevision     string
	closureRevision  string
}

func TestVerifyRetainedRepositoryPreservesOnlyHistoricalClaim(t *testing.T) {
	fixture := newRetainedFixture(t, retainedFixtureOptions{})
	if err := VerifyRepository(fixture.manifest, fixture.root); err == nil {
		t.Fatal("default finalization accepted successor source")
	}
	result, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != RetainedMode || result.ClaimScope != RetainedClaimScope || result.CoveredRevision != fixture.closureRevision || result.CurrentHEADCovered || result.EvaluatedHEAD == result.CoveredRevision || result.ManifestDigest != fixture.manifest.ManifestDigest {
		t.Fatalf("unexpected retained result: %#v", result)
	}
}

func TestVerifyRetainedRepositoryRejectsIllegalHistory(t *testing.T) {
	for name, options := range map[string]retainedFixtureOptions{
		"runtime to tool": {illegalToolDiff: true},
		"tool to closure": {illegalClosureDiff: true},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRetainedFixture(t, options)
			if _, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath); err == nil {
				t.Fatal("illegal retained history was accepted")
			}
		})
	}
}

func TestVerifyRetainedRepositoryRejectsMissingOrNonAncestorRevisions(t *testing.T) {
	t.Run("missing commit", func(t *testing.T) {
		fixture := newRetainedFixture(t, retainedFixtureOptions{})
		record := fixture.record
		record.RecordDigest = ""
		record.ClosureRevision = strings.Repeat("f", 40)
		record, err := SealClosureRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRetainedRepository(fixture.manifest, record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath); err == nil {
			t.Fatal("missing closure commit was accepted")
		}
	})
	t.Run("head before closure", func(t *testing.T) {
		fixture := newRetainedFixture(t, retainedFixtureOptions{})
		runGit(t, fixture.root, "checkout", "-q", "-b", "pre-closure", fixture.runtimeRevision)
		writeRepositoryFile(t, fixture.root, "docs/audits/product-phase-6-slice-4-evidence.json", string(fixture.manifestDocument))
		writeRepositoryFile(t, fixture.root, "docs/audits/product-phase-6-slice-4-closure.json", string(fixture.recordDocument))
		runGit(t, fixture.root, "add", ".")
		runGit(t, fixture.root, "commit", "-q", "-m", "unrelated historical files")
		if _, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath); err == nil {
			t.Fatal("HEAD outside the closure ancestry was accepted")
		}
	})
}

func TestVerifyRetainedRepositoryRejectsArtifactDrift(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, retainedFixture){
		"manifest changed": func(t *testing.T, fixture retainedFixture) {
			writeRepositoryFile(t, fixture.root, "docs/audits/product-phase-6-slice-4-evidence.json", string(fixture.manifestDocument)+"x")
			runGit(t, fixture.root, "add", ".")
			runGit(t, fixture.root, "commit", "-q", "-m", "change manifest")
		},
		"manifest changed then restored": func(t *testing.T, fixture retainedFixture) {
			writeRepositoryFile(t, fixture.root, "docs/audits/product-phase-6-slice-4-evidence.json", string(fixture.manifestDocument)+"x")
			runGit(t, fixture.root, "add", ".")
			runGit(t, fixture.root, "commit", "-q", "-m", "change manifest")
			writeRepositoryFile(t, fixture.root, "docs/audits/product-phase-6-slice-4-evidence.json", string(fixture.manifestDocument))
			runGit(t, fixture.root, "add", ".")
			runGit(t, fixture.root, "commit", "-q", "-m", "restore manifest")
		},
		"manifest deleted": func(t *testing.T, fixture retainedFixture) {
			runGit(t, fixture.root, "rm", "-q", "docs/audits/product-phase-6-slice-4-evidence.json")
			runGit(t, fixture.root, "commit", "-q", "-m", "delete manifest")
		},
		"closure record changed then restored": func(t *testing.T, fixture retainedFixture) {
			writeRepositoryFile(t, fixture.root, "docs/audits/product-phase-6-slice-4-closure.json", string(fixture.recordDocument)+"x")
			runGit(t, fixture.root, "add", ".")
			runGit(t, fixture.root, "commit", "-q", "-m", "change closure record")
			writeRepositoryFile(t, fixture.root, "docs/audits/product-phase-6-slice-4-closure.json", string(fixture.recordDocument))
			runGit(t, fixture.root, "add", ".")
			runGit(t, fixture.root, "commit", "-q", "-m", "restore closure record")
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRetainedFixture(t, retainedFixtureOptions{})
			mutate(t, fixture)
			if _, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.manifestPath, fixture.recordPath); err == nil {
				t.Fatal("retained artifact drift was accepted")
			}
		})
	}
}

func TestClosureRecordRejectsDriftAndUnsafePaths(t *testing.T) {
	fixture := newRetainedFixture(t, retainedFixtureOptions{})
	if _, err := VerifyClosureRecord(fixture.recordDocument); err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"id":"product-v1-phase-6-slice-closure",`), fixture.recordDocument[1:]...)
	if _, err := VerifyClosureRecord(duplicate); err == nil {
		t.Fatal("duplicate closure record member was accepted")
	}
	changed := append([]byte(nil), fixture.recordDocument...)
	changed[len(changed)-2] ^= 1
	if _, err := VerifyClosureRecord(changed); err == nil {
		t.Fatal("one-byte closure record mutation was accepted")
	}
	for _, candidate := range []string{"../evidence.json", "docs/audits/../evidence.json", "/docs/audits/evidence.json", `docs\audits\evidence.json`, "docs/audits/evidence.txt"} {
		record := fixture.record
		record.RecordDigest = ""
		record.ArtifactPath = candidate
		sealed, err := SealClosureRecord(record)
		if err == nil {
			t.Fatalf("unsafe closure path %q sealed as %#v", candidate, sealed)
		}
	}
	if _, err := VerifyRetainedRepository(fixture.manifest, fixture.record, ManifestID, fixture.root, fixture.recordPath, fixture.manifestPath); err == nil {
		t.Fatal("swapped retained paths were accepted")
	}
}

func newRetainedFixture(t *testing.T, options retainedFixtureOptions) retainedFixture {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.name", "Phase 6 Gate")
	runGit(t, root, "config", "user.email", "phase6@example.invalid")
	writeRepositoryFile(t, root, "implementation.go", "package implementation\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "implementation")
	runtimeRevision := runGit(t, root, "rev-parse", "HEAD")
	runtimeTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, runtimeRevision)
	if err != nil {
		t.Fatal(err)
	}
	writeRepositoryFile(t, root, "internal/productphase6evidence/verify.go", "package productphase6evidence\n")
	writeRepositoryFile(t, root, "productphase6gate/common_test.go", "package productphase6gate\n")
	if options.illegalToolDiff {
		writeRepositoryFile(t, root, "runtime-change.go", "package implementation\n")
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "evidence tools")
	toolRevision := runGit(t, root, "rev-parse", "HEAD")
	toolTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, toolRevision)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	manifest.Identity.RuntimeImplementationRevision = runtimeRevision
	manifest.Identity.RuntimeImplementationTreeDigest = runtimeTree
	manifest.Identity.EvidenceToolRevision = toolRevision
	manifest.Identity.EvidenceToolTreeDigest = toolTree
	manifest.ManifestDigest = digestWithoutSelf(manifest)
	manifestDocument, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeRepositoryFile(t, root, "docs/audits/product-phase-6-slice-4-evidence.json", string(manifestDocument))
	writeRepositoryFile(t, root, "README.md", "historical evidence\n")
	if options.illegalClosureDiff {
		writeRepositoryFile(t, root, "closure-runtime.go", "package implementation\n")
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "close slice")
	closureRevision := runGit(t, root, "rev-parse", "HEAD")
	record, err := SealClosureRecord(ClosureRecord{
		SliceID: ManifestID, ManifestSchemaVersion: ManifestVersion,
		RuntimeRevision: runtimeRevision, EvidenceToolRevision: toolRevision, ClosureRevision: closureRevision,
		ManifestRawSHA256: rawSHA256(manifestDocument), ManifestSealedDigest: manifest.ManifestDigest,
		ArtifactPath:      "docs/audits/product-phase-6-slice-4-evidence.json",
		ClosureRecordPath: "docs/audits/product-phase-6-slice-4-closure.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	recordDocument, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeRepositoryFile(t, root, "docs/audits/product-phase-6-slice-4-closure.json", string(recordDocument))
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "register closure")
	writeRepositoryFile(t, root, "slice5.go", "package implementation\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "successor source")
	manifestPath := filepath.Join(root, "docs/audits/product-phase-6-slice-4-evidence.json")
	recordPath := filepath.Join(root, "docs/audits/product-phase-6-slice-4-closure.json")
	if err := os.Chmod(manifestPath, 0o600); err != nil {
		t.Fatal(err)
	}
	return retainedFixture{
		root: root, manifestPath: manifestPath, recordPath: recordPath,
		manifestDocument: manifestDocument, recordDocument: recordDocument,
		manifest: manifest, record: record, runtimeRevision: runtimeRevision,
		toolRevision: toolRevision, closureRevision: closureRevision,
	}
}

func TestRetainedResultUsesCanonicalMachineReadableJSON(t *testing.T) {
	result := RetainedResult{Mode: RetainedMode, ClaimScope: RetainedClaimScope, SliceID: ManifestID, CoveredRevision: strings.Repeat("a", 40), EvaluatedHEAD: strings.Repeat("b", 40), ManifestDigest: "sha256:" + strings.Repeat("c", 64), NonClaim: "retained evidence does not verify current HEAD or any successor slice"}
	document, err := json.Marshal(result)
	if err != nil || bytes.Contains(document, []byte("true")) || !bytes.Contains(document, []byte(`"current_head_covered":false`)) {
		t.Fatalf("retained result = %s, %v", document, err)
	}
}
