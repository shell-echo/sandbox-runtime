//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	if err != nil || validateSlice6ScenarioRoutes(profile, slice6ScenarioRoutes) != nil ||
		phase6security.VerifySlice6DesiredNetworks(profile) != nil ||
		phase6security.VerifySlice6DesiredPrincipalIDs(profile) != nil ||
		phase6security.VerifySlice6DesiredEdgeAddresses(profile) != nil ||
		phase6security.VerifySlice6DesiredExternalServices(profile) != nil ||
		phase6security.VerifySlice6DesiredEgressPolicies(profile) != nil ||
		phase6security.VerifySlice6DesiredTrustAnchors(profile) != nil ||
		phase6security.VerifySlice6DesiredTLSIdentities(profile) != nil ||
		phase6security.VerifySlice6DesiredIngress(profile) != nil {
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
		if principal.ImageLocation != "local" || seen[principal.ImageDigest+"/"+principal.ImagePlatform] {
			continue
		}
		seen[principal.ImageDigest+"/"+principal.ImagePlatform] = true
		output, err := exec.CommandContext(ctx, "docker", "image", "inspect", principal.ImageDigest).Output()
		if err != nil || verifyLoadedSlice6Image(principal, output) != nil {
			t.Fatalf("Slice 6 exact local role image identity is unavailable for %s", principal.Name)
		}
	}
	if len(seen) == 0 {
		t.Fatal("Slice 6 profile has no local role candidates")
	}
}

// This checks only the loaded store object's exact identity. A live gate must
// additionally bind the container-selected manifest, raw OCI bytes and layers.
func verifyLoadedSlice6Image(principal phase6security.Principal, document []byte) error {
	if principal.ImageLocation != "local" || principal.ImageReference != principal.ImageDigest || len(document) == 0 || len(document) > 2<<20 {
		return errors.New("Slice 6 local image identity is invalid")
	}
	var images []struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Variant      string `json:"Variant"`
		Descriptor   *struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"Descriptor"`
	}
	if json.Unmarshal(document, &images) != nil || len(images) != 1 || images[0].ID != principal.ImageDigest || images[0].OS != "linux" {
		return errors.New("Slice 6 Docker store identity differs from profile")
	}
	platform := "linux/" + images[0].Architecture
	if images[0].Variant != "" {
		platform += "/" + images[0].Variant
	}
	if platform != principal.ImagePlatform && !(platform == "linux/arm64" && principal.ImagePlatform == "linux/arm64/v8") &&
		!(platform == "linux/arm64/v8" && principal.ImagePlatform == "linux/arm64") {
		return errors.New("Slice 6 Docker image platform differs from profile")
	}
	if principal.ImageIdentityKind == phase6security.ImageIdentityLocalConfig {
		if images[0].Descriptor != nil {
			return errors.New("Slice 6 local config has a store descriptor")
		}
		return nil
	}
	if images[0].Descriptor == nil || images[0].Descriptor.Digest != principal.ImageDigest {
		return errors.New("Slice 6 Docker descriptor differs from profile")
	}
	mediaTypes := []string{"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
	if principal.ImageIdentityKind == phase6security.ImageIdentityOCIIndex {
		mediaTypes = []string{"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
	} else if principal.ImageIdentityKind != phase6security.ImageIdentityOCIManifest {
		return errors.New("Slice 6 local image kind is invalid")
	}
	if !slices.Contains(mediaTypes, images[0].Descriptor.MediaType) {
		return errors.New("Slice 6 Docker descriptor kind differs from profile")
	}
	return nil
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

func TestSlice6LoadedImagePreflightRejectsIdentityAndPlatformDrift(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	principal := phase6security.Principal{ImageLocation: "local", ImageReference: digest, ImageDigest: digest,
		ImageIdentityKind: phase6security.ImageIdentityOCIManifest, ImagePlatform: "linux/arm64/v8"}
	document := func(id, osName, architecture, variant, mediaType, descriptorDigest string) []byte {
		value := map[string]any{"Id": id, "Os": osName, "Architecture": architecture, "Variant": variant,
			"Descriptor": map[string]any{"mediaType": mediaType, "digest": descriptorDigest}}
		encoded, err := json.Marshal([]any{value})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	manifestMediaType := "application/vnd.oci.image.manifest.v1+json"
	valid := document(digest, "linux", "arm64", "v8", manifestMediaType, digest)
	if err := verifyLoadedSlice6Image(principal, valid); err != nil {
		t.Fatalf("exact loaded image rejected: %v", err)
	}
	for name, candidate := range map[string][]byte{
		"wrong store ID":         document("sha256:"+strings.Repeat("b", 64), "linux", "arm64", "v8", manifestMediaType, digest),
		"wrong descriptor":       document(digest, "linux", "arm64", "v8", manifestMediaType, "sha256:"+strings.Repeat("b", 64)),
		"wrong platform":         document(digest, "linux", "amd64", "", manifestMediaType, digest),
		"wrong operating system": document(digest, "windows", "arm64", "v8", manifestMediaType, digest),
		"wrong object kind":      document(digest, "linux", "arm64", "v8", "application/vnd.oci.image.index.v1+json", digest),
		"ambiguous inspection":   append(append([]byte("["), valid[1:len(valid)-1]...), append([]byte(","), valid[1:]...)...),
	} {
		if err := verifyLoadedSlice6Image(principal, candidate); err == nil {
			t.Errorf("%s admitted", name)
		}
	}
	if err := verifyLoadedSlice6Image(principal, []byte("not json")); err == nil {
		t.Fatal("invalid Docker inspection admitted")
	}
	index := principal
	index.ImageIdentityKind = phase6security.ImageIdentityOCIIndex
	if err := verifyLoadedSlice6Image(index, valid); err == nil {
		t.Fatal("index profile admitted a manifest descriptor")
	}
	config := principal
	config.ImageIdentityKind = phase6security.ImageIdentityLocalConfig
	if err := verifyLoadedSlice6Image(config, valid); err == nil {
		t.Fatal("local config profile admitted a descriptor")
	}
	if err := verifyLoadedSlice6Image(config, []byte(`[{"Id":"`+digest+`","Os":"linux","Architecture":"arm64"}]`)); err != nil {
		t.Fatalf("local config without descriptor rejected: %v", err)
	}
}

func TestSlice6SourceCheckpointRejectsDirtyOrMismatchedRevision(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("initialize disposable source: %v: %.512s", err, output)
	}
	path := filepath.Join(root, "fixture.txt")
	if err := os.WriteFile(path, []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"-C", root, "add", "fixture.txt"},
		{"-C", root, "-c", "user.name=Slice6 Test", "-c", "user.email=slice6@example.invalid", "commit", "-q", "-m", "fixture"},
	} {
		if output, err := exec.CommandContext(t.Context(), "git", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("commit disposable source: %v: %.512s", err, output)
		}
	}
	head, err := exec.CommandContext(t.Context(), "git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.TrimSpace(string(head))
	if err := verifyCleanSlice6Source(t.Context(), root, revision); err != nil {
		t.Fatalf("clean source checkpoint rejected: %v", err)
	}
	if verifyCleanSlice6Source(t.Context(), root, strings.Repeat("0", 40)) == nil {
		t.Fatal("mismatched source revision admitted")
	}
	if err := os.WriteFile(path, []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if verifyCleanSlice6Source(t.Context(), root, revision) == nil {
		t.Fatal("dirty source checkpoint admitted")
	}
}
