//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6PreflightEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PREFLIGHT"

type slice6GateInput struct {
	profilePath           string
	sourceRoot            string
	sourceRevision        string
	desktopCandidatePath  string
	profile               phase6security.Profile
	desktopCandidateImage string
}

// loadSlice6GateInput performs only admission checks. It does not observe a
// running role, produce a manifest or turn a component probe into gate proof.
// The eventual single-run harness must call this before any side effects.
func loadSlice6GateInput(ctx context.Context, profilePath, sourceRoot, sourceRevision, candidatePath string) (slice6GateInput, error) {
	if ctx == nil || ctx.Err() != nil || !absoluteCleanSlice6Path(profilePath) ||
		!absoluteCleanSlice6Path(sourceRoot) || !absoluteCleanSlice6Path(candidatePath) ||
		len(sourceRevision) != 40 || !lowerHexSlice6(sourceRevision) || runtime.Version() != "go1.26.8" {
		return slice6GateInput{}, errors.New("Slice 6 gate inputs are unavailable")
	}
	info, err := os.Lstat(sourceRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return slice6GateInput{}, errors.New("Slice 6 source checkout is unavailable")
	}
	profile, err := phase6security.VerifyFile(profilePath)
	if err != nil || validateSlice6ScenarioRoutes(profile, slice6ScenarioRoutes) != nil {
		return slice6GateInput{}, errors.New("Slice 6 complete security profile is unavailable")
	}
	if err := verifyCleanSlice6Source(ctx, sourceRoot, sourceRevision); err != nil {
		return slice6GateInput{}, err
	}
	candidate, err := desktopcandidate.LoadCurrent(candidatePath)
	if err != nil || candidate.SourceRevision != sourceRevision || candidate.VerifySource(sourceRoot) != nil {
		return slice6GateInput{}, errors.New("Slice 6 Desktop candidate is not bound to source")
	}
	matched := false
	for _, principal := range profile.Principals {
		if principal.Name == "desktop-sandbox-runtime" {
			matched = principal.ImageLocation == "local" && principal.ImageDigest == candidate.ImageDigest &&
				principal.ImagePlatform == candidate.Platform
		}
	}
	if !matched {
		return slice6GateInput{}, errors.New("Slice 6 Desktop candidate does not match profile")
	}
	return slice6GateInput{profilePath: profilePath, sourceRoot: sourceRoot, sourceRevision: sourceRevision,
		desktopCandidatePath: candidatePath, profile: profile, desktopCandidateImage: candidate.ImageDigest}, nil
}

func verifyCleanSlice6Source(ctx context.Context, sourceRoot, revision string) error {
	status, err := exec.CommandContext(ctx, "git", "-C", sourceRoot, "status", "--porcelain", "--untracked-files=all").Output()
	if err != nil || len(status) != 0 {
		return errors.New("Slice 6 source checkout is not clean")
	}
	head, err := exec.CommandContext(ctx, "git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(head)) != revision {
		return errors.New("Slice 6 source revision does not match HEAD")
	}
	return nil
}

func absoluteCleanSlice6Path(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/"
}

func lowerHexSlice6(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// This opt-in preflight is a diagnostic milestone, never the release gate.
// The full gate will reuse its input and then run the actual complete topology.
func TestPhase6Slice6TopologyPreflight(t *testing.T) {
	if os.Getenv(slice6PreflightEnv) != "1" {
		t.Skip("set " + slice6PreflightEnv + "=1 for strict Slice 6 input preflight")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	input, err := loadSlice6GateInput(ctx, os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_PROFILE"),
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT"),
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION"),
		os.Getenv("SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, principal := range input.profile.Principals {
		if principal.ImageLocation != "local" || seen[principal.ImageDigest] {
			continue
		}
		seen[principal.ImageDigest] = true
		if output, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", principal.ImageDigest).CombinedOutput(); err != nil || len(strings.TrimSpace(string(output))) == 0 {
			t.Fatalf("Slice 6 local role image is not loaded for %s", principal.Name)
		}
	}
	if len(seen) == 0 {
		t.Fatal("Slice 6 profile has no local role candidates")
	}
}

func TestSlice6GateInputRejectsMissingAuthority(t *testing.T) {
	if _, err := loadSlice6GateInput(t.Context(), "", "", "", ""); err == nil {
		t.Fatal("empty Slice 6 gate inputs admitted")
	}
	if absoluteCleanSlice6Path("relative/profile.json") || absoluteCleanSlice6Path("/tmp/../tmp/profile.json") ||
		lowerHexSlice6(strings.Repeat("g", 40)) || !lowerHexSlice6(strings.Repeat("a", 40)) {
		t.Fatal("Slice 6 path or revision guard drifted")
	}
}
