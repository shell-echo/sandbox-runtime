package productphase6evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
)

func validManifest() Manifest {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	manifest := Manifest{ID: ManifestID, Version: ManifestVersion, Identity: Identity{SourceRevision: strings.Repeat("a", 40), SourceTreeDigest: digest("tree"), ConfigDigest: digest("config"), ObservedAt: now, CandidateClassification: "local-candidate-non-release", DesktopCandidateManifestDigest: digest("candidate-manifest"), DesktopCandidateImageDigest: digest("candidate-image"), DesktopCandidatePlatform: "linux/arm64/v8"}, NonClaims: []string{"deployment", "production readiness", "hostile multi-tenant isolation", "local-candidate OCI is not a published or signed artifact", "local-candidate evidence is not production release qualification", "evidence proves role boundaries and internal executor data paths only", "complete Product-to-Gateway-to-Provider public E2E remains unproven", "production readiness remains unproven"}}
	for _, role := range []string{"product", "gateway", "provider", "guest", "browser", "desktop"} {
		manifest.Roles = append(manifest.Roles, Role{Name: role, Command: "sandbox-runtime " + role + " serve", ImageDigest: digest(role), ProcessIdentity: role + "-process", StartedAt: now, FinishedAt: now, EvidenceDigest: digest(role + "-evidence"), Ready: true})
	}
	for _, name := range ScenarioNames() {
		manifest.Scenarios = append(manifest.Scenarios, Scenario{Name: name, Outcome: "passed", Roles: []string{"provider", "desktop"}, EvidenceDigest: digest(name)})
	}
	manifest.Cleanup = Cleanup{ZeroResources: true, Teardown: []Resource{{Name: "postgres", Count: 0}, {Name: "desktop-runtime", Count: 0}}, EvidenceDigest: digest("cleanup")}
	manifest.ManifestDigest = digestWithoutSelf(manifest)
	return manifest
}

func digest(value string) string {
	return "sha256:" + strings.Repeat("a", 64)
}

func TestVerifyRejectsEvidenceDrift(t *testing.T) {
	valid := validManifest()
	document, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(document); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Manifest){
		"unknown field": func(value *Manifest) { value.NonClaims = append(value.NonClaims, "x") },
		"role exit":     func(value *Manifest) { value.Roles[0].ExitCode = 1 },
		"cleanup count": func(value *Manifest) { value.Cleanup.Teardown[0].Count = 1 },
		"scenario":      func(value *Manifest) { value.Scenarios[0].Outcome = "failed" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if name == "unknown field" {
				document, err := json.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
				document = append(document[:len(document)-1], []byte(`,"unexpected":true}`)...)
				if _, err := Verify(document); err == nil {
					t.Fatal("unknown evidence field accepted")
				}
				return
			}
			candidate.ManifestDigest = digestWithoutSelf(candidate)
			document, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(document); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestVerifyRejectsDuplicateAndNonCanonicalJSON(t *testing.T) {
	valid := validManifest()
	document, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"id":"product-v1-phase-6-slice-4",`), document[1:]...)
	if _, err := Verify(duplicate); err == nil {
		t.Fatal("duplicate evidence member accepted")
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, document, "", "  "); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify([]byte(pretty.String())); err == nil {
		t.Fatal("non-canonical evidence JSON accepted")
	}
}

func TestSealBindsAndVerifiesObservedManifest(t *testing.T) {
	manifest := validManifest()
	manifest.ID = ""
	manifest.Version = ""
	manifest.ManifestDigest = ""
	sealed, err := Seal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.ID != ManifestID || sealed.Version != ManifestVersion || sealed.ManifestDigest == "" {
		t.Fatalf("sealed manifest=%#v", sealed)
	}
	if _, err := Seal(sealed); err == nil {
		t.Fatal("already sealed evidence accepted")
	}
}

func TestVerifyRepositoryAllowsOnlyCleanDocumentationAfterImplementation(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.name", "Phase 6 Gate")
	runGit(t, root, "config", "user.email", "phase6@example.invalid")
	writeRepositoryFile(t, root, "implementation.go", "package implementation\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "implementation")
	revision := runGit(t, root, "rev-parse", "HEAD")
	treeDigest, err := desktopcandidate.SourceTreeDigestAtRevision(root, revision)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	manifest.Identity.SourceRevision = revision
	manifest.Identity.SourceTreeDigest = treeDigest
	if err := VerifyRepository(manifest, root); err != nil {
		t.Fatalf("implementation revision rejected: %v", err)
	}

	writeRepositoryFile(t, root, "docs/evidence.md", "verified\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "evidence")
	if err := VerifyRepository(manifest, root); err != nil {
		t.Fatalf("documentation-only evidence commit rejected: %v", err)
	}

	writeRepositoryFile(t, root, "implementation.go", "package implementation\nvar changed = true\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "source drift")
	if err := VerifyRepository(manifest, root); err == nil {
		t.Fatal("post-implementation source change accepted")
	}
	writeRepositoryFile(t, root, "docs/dirty.md", "dirty\n")
	if err := VerifyRepository(manifest, root); err == nil {
		t.Fatal("dirty evidence worktree accepted")
	}
}

func runGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	document, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, document)
	}
	return strings.TrimSpace(string(document))
}

func writeRepositoryFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
