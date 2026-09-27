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
	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

const slice6PreflightEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PREFLIGHT"

type slice6GateInput struct {
	profilePath           string
	sourceRoot            string
	sourceRevision        string
	desktopCandidatePath  string
	profile               phase6security.Profile
	desktopCandidateImage string
	roleCandidates        []phase6rolecandidate.Manifest
}

// loadSlice6GateInput performs only admission checks. It does not observe a
// running role, produce a manifest or turn a component probe into gate proof.
// The eventual single-run harness must call this before any side effects.
func loadSlice6GateInput(ctx context.Context, profilePath, sourceRoot, sourceRevision, candidatePath, roleCandidateDir string) (slice6GateInput, error) {
	if ctx == nil || ctx.Err() != nil || !absoluteCleanSlice6Path(profilePath) ||
		!absoluteCleanSlice6Path(sourceRoot) || !absoluteCleanSlice6Path(candidatePath) ||
		!absoluteCleanSlice6Path(roleCandidateDir) ||
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
		phase6security.VerifySlice6DesiredImageLocations(profile) != nil ||
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
	roleCandidates, err := loadSlice6RoleCandidateDir(ctx, sourceRoot, roleCandidateDir, profile, sourceRevision)
	if err != nil {
		return slice6GateInput{}, err
	}
	return slice6GateInput{profilePath: profilePath, sourceRoot: sourceRoot, sourceRevision: sourceRevision,
		desktopCandidatePath: candidatePath, profile: profile, desktopCandidateImage: candidate.ImageDigest,
		roleCandidates: roleCandidates}, nil
}

// loadSlice6RoleCandidateDir admits exactly one retained source/archive pair
// per unique local role image. The 58 deployments may share binaries, but
// every deployment's selected image must have an exact reviewed target.
func loadSlice6RoleCandidateDir(ctx context.Context, sourceRoot, directory string,
	profile phase6security.Profile, sourceRevision string) ([]phase6rolecandidate.Manifest, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || !isOutsideSlice6Source(sourceRoot, directory) {
		return nil, errors.New("Slice 6 local role candidate directory is unavailable")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 || len(entries) > 64 {
		return nil, errors.New("Slice 6 local role candidate inventory is unavailable")
	}
	paths := make(map[string]bool, len(entries))
	var manifests []phase6rolecandidate.Manifest
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "" || paths[entry.Name()] {
			return nil, errors.New("Slice 6 local role candidate directory is invalid")
		}
		paths[entry.Name()] = true
		if strings.HasSuffix(entry.Name(), ".json") {
			manifest, err := phase6rolecandidate.LoadCurrent(ctx, sourceRoot, filepath.Join(directory, entry.Name()))
			if err != nil {
				return nil, errors.New("Slice 6 local role candidate is not source/archive bound")
			}
			manifests = append(manifests, manifest)
		}
	}
	if len(manifests) == 0 || len(entries) != len(manifests)*2 {
		return nil, errors.New("Slice 6 local role candidate pairs are incomplete")
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			if !paths[entry.Name()+".oci.tar"] {
				return nil, errors.New("Slice 6 local role candidate archive is missing")
			}
		} else if !strings.HasSuffix(entry.Name(), ".json.oci.tar") ||
			!paths[strings.TrimSuffix(entry.Name(), ".oci.tar")] {
			return nil, errors.New("Slice 6 local role candidate directory has an unreviewed file")
		}
	}
	if err := matchSlice6RoleCandidates(profile, manifests, sourceRevision); err != nil {
		return nil, err
	}
	return manifests, nil
}

type slice6RoleImageKey struct{ digest, platform string }

func matchSlice6RoleCandidates(profile phase6security.Profile, manifests []phase6rolecandidate.Manifest, revision string) error {
	type expectedRoleImage struct {
		kind, selected, config, target string
		deployments                    map[string]bool
	}
	expected := make(map[slice6RoleImageKey]expectedRoleImage)
	for _, principal := range profile.Principals {
		if principal.ImageLocation != "local" || principal.Name == "desktop-sandbox-runtime" {
			continue
		}
		target, err := phase6security.Slice6DesiredImageTarget(principal.Name)
		if err != nil || target == phase6security.Slice6BrowserPublishedImage ||
			target == phase6security.Slice6DesktopCandidateImage {
			return errors.New("Slice 6 local role image target is invalid")
		}
		key := slice6RoleImageKey{principal.ImageDigest, principal.ImagePlatform}
		value, found := expected[key]
		if !found {
			value = expectedRoleImage{kind: principal.ImageIdentityKind,
				selected: principal.ImageSelectedManifestDigest, config: principal.ImageConfigDigest,
				target: target, deployments: make(map[string]bool)}
		} else if value.kind != principal.ImageIdentityKind || value.selected != principal.ImageSelectedManifestDigest ||
			value.config != principal.ImageConfigDigest || value.target != target {
			return errors.New("Slice 6 role deployments alias incompatible images")
		}
		value.deployments[principal.Name] = true
		expected[key] = value
	}
	if len(expected) == 0 || len(expected) != len(manifests) {
		return errors.New("Slice 6 local role image candidate coverage is incomplete")
	}
	seen := make(map[slice6RoleImageKey]bool, len(manifests))
	for _, manifest := range manifests {
		key := slice6RoleImageKey{manifest.RuntimeStoreImageID, manifest.Source.Platform}
		value, found := expected[key]
		selected := manifest.SelectedManifestDescriptor.Digest
		if manifest.ImageIdentityKind == phase6security.ImageIdentityOCIManifest {
			selected = ""
		}
		if !found || seen[key] || manifest.Source.SourceRevision != revision ||
			!value.deployments[manifest.Source.Deployment] || manifest.Source.BuildTarget != value.target ||
			manifest.ImageIdentityKind != value.kind || selected != value.selected ||
			manifest.OCIConfigDigest != value.config ||
			manifest.RuntimeStoreDescriptor.Digest != key.digest {
			return errors.New("Slice 6 local role candidate differs from reviewed profile")
		}
		seen[key] = true
	}
	return nil
}

func isOutsideSlice6Source(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
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
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	input, err := loadSlice6GateInput(ctx, os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_PROFILE"),
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT"),
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION"),
		os.Getenv("SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST"),
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_ROLE_CANDIDATES"))
	if err != nil {
		t.Fatal(err)
	}
	inspections := make(map[string][]byte)
	for _, principal := range input.profile.Principals {
		if principal.ImageLocation != "local" && principal.Name != "browser-sandbox-runtime" {
			continue
		}
		key := principal.ImageReference + "/" + principal.ImagePlatform
		output, found := inspections[key]
		if !found {
			var err error
			output, err = exec.CommandContext(ctx, "docker", "image", "inspect", principal.ImageReference).Output()
			if err != nil {
				t.Fatalf("Slice 6 exact role image is unavailable for %s", principal.Name)
			}
			inspections[key] = output
		}
		if verifyLoadedSlice6Image(principal, output) != nil ||
			(principal.ImageLocation == "local" && principal.Name != "desktop-sandbox-runtime" &&
				phase6security.VerifySlice6LocalRoleImageInspect(principal, input.sourceRevision, output) != nil) {
			t.Fatalf("Slice 6 exact role image identity is unavailable for %s", principal.Name)
		}
	}
	if len(inspections) == 0 {
		t.Fatal("Slice 6 profile has no local role candidates")
	}
}

// This checks only the loaded store object's exact identity, including the
// named registry reference when used. A live gate must additionally bind the
// signed provenance, container-selected manifest, raw OCI bytes and layers.
func verifyLoadedSlice6Image(principal phase6security.Principal, document []byte) error {
	if (principal.ImageLocation != "local" && principal.ImageLocation != "registry") ||
		(principal.ImageLocation == "local" && principal.ImageReference != principal.ImageDigest) ||
		len(document) == 0 || len(document) > 2<<20 {
		return errors.New("Slice 6 image identity is invalid")
	}
	var images []struct {
		ID           string   `json:"Id"`
		OS           string   `json:"Os"`
		Architecture string   `json:"Architecture"`
		Variant      string   `json:"Variant"`
		RepoDigests  []string `json:"RepoDigests"`
		Descriptor   *struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"Descriptor"`
	}
	if json.Unmarshal(document, &images) != nil || len(images) != 1 || images[0].ID != principal.ImageDigest || images[0].OS != "linux" {
		return errors.New("Slice 6 Docker store identity differs from profile")
	}
	if principal.ImageLocation == "registry" && !slices.Contains(images[0].RepoDigests, principal.ImageReference) {
		return errors.New("Slice 6 registry image reference is absent from Docker store")
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
		if principal.ImageLocation != "local" || images[0].Descriptor != nil {
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
	if _, err := loadSlice6GateInput(t.Context(), "", "", "", "", ""); err == nil {
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

func TestSlice6LoadedBrowserPublicationRejectsStoreSubstitution(t *testing.T) {
	publication := browserimage.LockedPublication()
	principal := phase6security.Principal{
		Name: "browser-sandbox-runtime", ImageReference: publication.Image(),
		ImageDigest: publication.Digest, ImageLocation: "registry",
		ImageIdentityKind: phase6security.ImageIdentityOCIIndex,
		ImagePlatform:     "linux/arm64/v8", ImageSelectedManifestDigest: browserimage.PublishedARM64Manifest,
	}
	document := func(id, reference, architecture, mediaType string) []byte {
		value, err := json.Marshal([]any{map[string]any{
			"Id": id, "Os": "linux", "Architecture": architecture,
			"RepoDigests": []string{reference},
			"Descriptor":  map[string]any{"mediaType": mediaType, "digest": publication.Digest},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	const indexType = "application/vnd.oci.image.index.v1+json"
	if err := verifyLoadedSlice6Image(principal, document(publication.Digest, publication.Image(), "arm64", indexType)); err != nil {
		t.Fatalf("locked Browser store index rejected: %v", err)
	}
	for name, value := range map[string][]byte{
		"wrong store ID":   document("sha256:"+strings.Repeat("b", 64), publication.Image(), "arm64", indexType),
		"wrong repository": document(publication.Digest, "ghcr.io/other/browser@"+publication.Digest, "arm64", indexType),
		"wrong platform":   document(publication.Digest, publication.Image(), "amd64", indexType),
		"wrong kind":       document(publication.Digest, publication.Image(), "arm64", "application/vnd.oci.image.manifest.v1+json"),
	} {
		if err := verifyLoadedSlice6Image(principal, value); err == nil {
			t.Errorf("%s admitted", name)
		}
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

func TestSlice6RoleCandidateCoverageRejectsAliasAndTargetDrift(t *testing.T) {
	revision := strings.Repeat("a", 40)
	coreID := "sha256:" + strings.Repeat("b", 64)
	backendID := "sha256:" + strings.Repeat("c", 64)
	coreConfig := "sha256:" + strings.Repeat("d", 64)
	backendConfig := "sha256:" + strings.Repeat("e", 64)
	principal := func(name, image, config string) phase6security.Principal {
		return phase6security.Principal{Name: name, ImageLocation: "local", ImageReference: image,
			ImageDigest: image, ImageIdentityKind: phase6security.ImageIdentityOCIManifest,
			ImagePlatform: "linux/arm64/v8", ImageConfigDigest: config}
	}
	profile := phase6security.Profile{Principals: []phase6security.Principal{
		principal("product-runtime", coreID, coreConfig), principal("gateway-runtime", coreID, coreConfig),
		principal("browser-executor-backend", backendID, backendConfig),
	}}
	manifest := func(deployment, target, image, config string) phase6rolecandidate.Manifest {
		return phase6rolecandidate.Manifest{
			Source: phase6rolecandidate.SourceInputs{Deployment: deployment, BuildTarget: target,
				Platform: "linux/arm64/v8", SourceRevision: revision},
			ImageIdentityKind:   phase6security.ImageIdentityOCIManifest,
			RuntimeStoreImageID: image, RuntimeStoreDescriptor: phase6security.ImageDescriptor{Digest: image},
			SelectedManifestDescriptor: phase6security.ImageDescriptor{Digest: image}, OCIConfigDigest: config,
		}
	}
	values := []phase6rolecandidate.Manifest{
		manifest("product-runtime", "core", coreID, coreConfig),
		manifest("browser-executor-backend", "browser-executor-backend", backendID, backendConfig),
	}
	if err := matchSlice6RoleCandidates(profile, values, revision); err != nil {
		t.Fatalf("shared core candidate was rejected: %v", err)
	}
	for name, change := range map[string]func([]phase6rolecandidate.Manifest){
		"wrong target":     func(v []phase6rolecandidate.Manifest) { v[1].Source.BuildTarget = "core" },
		"wrong deployment": func(v []phase6rolecandidate.Manifest) { v[0].Source.Deployment = "guest-runtime" },
		"wrong config":     func(v []phase6rolecandidate.Manifest) { v[0].OCIConfigDigest = backendConfig },
		"duplicate image":  func(v []phase6rolecandidate.Manifest) { v[1] = v[0] },
		"revision drift":   func(v []phase6rolecandidate.Manifest) { v[0].Source.SourceRevision = strings.Repeat("f", 40) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]phase6rolecandidate.Manifest(nil), values...)
			change(candidate)
			if matchSlice6RoleCandidates(profile, candidate, revision) == nil {
				t.Fatal("drifted candidate inventory admitted")
			}
		})
	}
	if matchSlice6RoleCandidates(profile, values[:1], revision) == nil {
		t.Fatal("missing image candidate admitted")
	}
	crossTarget := profile
	crossTarget.Principals = append([]phase6security.Principal(nil), profile.Principals...)
	crossTarget.Principals[2].ImageDigest = coreID
	crossTarget.Principals[2].ImageReference = coreID
	crossTarget.Principals[2].ImageConfigDigest = coreConfig
	if matchSlice6RoleCandidates(crossTarget, values[:1], revision) == nil {
		t.Fatal("same image reused for conflicting role targets")
	}
}
