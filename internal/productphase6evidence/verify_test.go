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
	stress := StressMeasurements{Harness: "phase6-desktop-mux-stress-v2", Runs50: 50, Runs100: 100, TotalRuns: 150, InputsPerRun: 5, TotalInputs: 750, TerminalCauses: []string{}}
	stress.CommandDigest = StressCommandDigest(stress)
	stress.EvidenceDigest = StressEvidenceDigest(stress)
	media := DesktopMediaMeasurements{Harness: "phase6-desktop-media-v2", Sessions: 20, FirstFrameP95Microseconds: 150_000, FirstFrameMaxMicroseconds: 200_000, FirstFrameLimitMilliseconds: 30_000, WindowMilliseconds: 2_000, RTPPackets: 1_200, RTPMarkerFrames: 1_180, RTPBytes: 120_000, FPSLimitMilli: 30_000, MaxFPSMilli: 30_000, MaxBitrateBPS: 30_000, BitrateLimitBPS: 2_000_000, ConcurrentInputs: 201, MaxInputRoundtripMicroseconds: 5_000, InputProcessDeadlineMilliseconds: 1_000, BackpressureStage: "media_reader", BackpressureCause: "backpressure_limit", Recovery: true, GoroutineBoundary: SteadyStateGoroutineBoundary, GoroutinesBaseline: 2, GoroutinesFinal: 2}
	media.CommandDigest = DesktopMediaCommandDigest(media)
	media.EvidenceDigest = DesktopMediaEvidenceDigest(media)
	manifest := Manifest{ID: ManifestID, Version: ManifestVersion, Identity: Identity{RuntimeImplementationRevision: strings.Repeat("a", 40), RuntimeImplementationTreeDigest: digest("runtime-tree"), EvidenceToolRevision: strings.Repeat("b", 40), EvidenceToolTreeDigest: digest("evidence-tree"), ConfigDigest: digest("config"), ObservedAt: now, CandidateClassification: "local-candidate-non-release", DesktopCandidateManifestDigest: digest("candidate-manifest"), DesktopCandidateImageDigest: digest("candidate-image"), DesktopCandidatePlatform: "linux/arm64/v8"}, Stress: stress, DesktopMedia: media, NonClaims: []string{"deployment", "production readiness", "hostile multi-tenant isolation", "local-candidate OCI is not a published or signed artifact", "local-candidate evidence is not production release qualification", "evidence proves role boundaries and internal executor data paths only", "complete Product-to-Gateway-to-Provider public E2E remains unproven", "production readiness remains unproven", "measured bitrate upper-bound does not prove visual quality", "thirty-second first-frame limit is a test safety bound, not a production SLO"}}
	for _, role := range []string{"product", "gateway", "provider", "guest", "browser", "desktop"} {
		manifest.Roles = append(manifest.Roles, Role{Name: role, Command: "sandbox-runtime " + role + " serve", ImageDigest: digest(role), ProcessIdentity: role + "-process", StartedAt: now, FinishedAt: now, EvidenceDigest: digest(role + "-evidence"), Ready: true})
	}
	for _, name := range ScenarioNames() {
		manifest.Scenarios = append(manifest.Scenarios, Scenario{Name: name, Outcome: "passed", Roles: []string{"provider", "desktop"}, EvidenceDigest: digest(name)})
	}
	manifest.Cleanup = Cleanup{ZeroResources: true, Boundary: TopologyCleanupBoundary, Teardown: []Resource{{Name: "role_processes", Count: 0}, {Name: "executor_backend_processes", Count: 0}, {Name: "desktop_namespace_containers", Count: 0}, {Name: "desktop_namespace_networks", Count: 0}, {Name: "postgres_and_chromium_containers", Count: 0}, {Name: "desktop_broker_socket", Count: 0}, {Name: "browser_gateway_image", Count: 0}, {Name: "guest_fixture_listener", Count: 0}}}
	manifest.Cleanup.EvidenceDigest = CleanupEvidenceDigest(manifest.Cleanup)
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
		"unknown field":      func(value *Manifest) { value.NonClaims = append(value.NonClaims, "x") },
		"role exit":          func(value *Manifest) { value.Roles[0].ExitCode = 1 },
		"cleanup count":      func(value *Manifest) { value.Cleanup.Teardown[0].Count = 1 },
		"cleanup resource":   func(value *Manifest) { value.Cleanup.Teardown[0].Name = "unknown" },
		"scenario":           func(value *Manifest) { value.Scenarios[0].Outcome = "failed" },
		"stress input":       func(value *Manifest) { value.Stress.InputTimeouts = 1 },
		"media first frame":  func(value *Manifest) { value.DesktopMedia.FirstFrameMaxMicroseconds = 30_000_001 },
		"media sequence gap": func(value *Manifest) { value.DesktopMedia.RTPSequenceGaps = 1 },
		"media goroutine":    func(value *Manifest) { value.DesktopMedia.GoroutinesFinal++ },
		"media boundary":     func(value *Manifest) { value.DesktopMedia.GoroutineBoundary = "ambiguous" },
		"cleanup boundary":   func(value *Manifest) { value.Cleanup.Boundary = "ambiguous" },
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

func TestCleanupEvidenceDigestBindsBothCleanupBoundaries(t *testing.T) {
	baseline := validManifest().Cleanup
	want := CleanupEvidenceDigest(baseline)
	for name, mutate := range map[string]func(*Cleanup){
		"topology boundary": func(value *Cleanup) { value.Boundary = "ambiguous" },
		"resource identity": func(value *Cleanup) { value.Teardown[0].Name = "unknown" },
		"resource count":    func(value *Cleanup) { value.Teardown[0].Count = 1 },
		"zero claim":        func(value *Cleanup) { value.ZeroResources = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := baseline
			candidate.Teardown = append([]Resource(nil), baseline.Teardown...)
			mutate(&candidate)
			if got := CleanupEvidenceDigest(candidate); got == want {
				t.Fatalf("cleanup mutation retained digest %s", got)
			}
		})
	}
}

func TestVerifyRepositoryAllowsOnlyClosedEvidenceToolsAndThenDocumentation(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.name", "Phase 6 Gate")
	runGit(t, root, "config", "user.email", "phase6@example.invalid")
	writeRepositoryFile(t, root, "implementation.go", "package implementation\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "implementation")
	runtimeRevision := runGit(t, root, "rev-parse", "HEAD")
	runtimeTreeDigest, err := desktopcandidate.SourceTreeDigestAtRevision(root, runtimeRevision)
	if err != nil {
		t.Fatal(err)
	}
	writeRepositoryFile(t, root, "internal/productphase6evidence/verify.go", "package productphase6evidence\n")
	writeRepositoryFile(t, root, "productphase6gate/common_test.go", "package productphase6gate\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "evidence tools")
	evidenceRevision := runGit(t, root, "rev-parse", "HEAD")
	evidenceTreeDigest, err := desktopcandidate.SourceTreeDigestAtRevision(root, evidenceRevision)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	manifest.Identity.RuntimeImplementationRevision = runtimeRevision
	manifest.Identity.RuntimeImplementationTreeDigest = runtimeTreeDigest
	manifest.Identity.EvidenceToolRevision = evidenceRevision
	manifest.Identity.EvidenceToolTreeDigest = evidenceTreeDigest
	if err := VerifyRepository(manifest, root); err != nil {
		t.Fatalf("evidence-tool revision rejected: %v", err)
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
