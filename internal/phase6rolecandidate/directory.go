package phase6rolecandidate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidDirectory = errors.New("invalid Phase 6 local role candidate directory")

type VerifiedArtifact struct {
	Manifest     Manifest
	ManifestPath string
}

// VerifyDirectory reopens exactly one private manifest/archive pair per
// distinct local role image in the reviewed profile. It verifies bytes and
// clean source, not merely filenames or caller-provided digest projections.
// Desktop and the signed historical Browser publication have separate inputs.
func VerifyDirectory(ctx context.Context, sourceRoot, directory string,
	profile phase6security.Profile, sourceRevision string) ([]Manifest, error) {
	artifacts, err := VerifyDirectoryArtifacts(ctx, sourceRoot, directory, profile, sourceRevision)
	if err != nil {
		return nil, err
	}
	manifests := make([]Manifest, 0, len(artifacts))
	for _, artifact := range artifacts {
		manifests = append(manifests, artifact.Manifest)
	}
	return manifests, nil
}

// VerifyDirectoryArtifacts also retains each verified private path for the
// admission layer to re-read exact archive descriptor bytes.
func VerifyDirectoryArtifacts(ctx context.Context, sourceRoot, directory string,
	profile phase6security.Profile, sourceRevision string) ([]VerifiedArtifact, error) {
	artifacts, err := scanPrivateCandidateDirectory(ctx, sourceRoot, directory)
	if err != nil {
		return nil, err
	}
	manifests := make([]Manifest, 0, len(artifacts))
	for _, artifact := range artifacts {
		manifests = append(manifests, artifact.Manifest)
	}
	if MatchProfile(profile, manifests, sourceRevision) != nil {
		return nil, ErrInvalidDirectory
	}
	return artifacts, nil
}

// VerifyTargetDirectoryArtifacts opens the complete private image supply
// before a Profile exists. Each reviewed repository command target must have
// exactly one independently source/archive-verified candidate. This is a
// builder input, not a release observation; the completed profile is still
// checked by VerifyDirectoryArtifacts and the live Docker gate.
func VerifyTargetDirectoryArtifacts(ctx context.Context, sourceRoot, directory, sourceRevision string) ([]VerifiedArtifact, error) {
	artifacts, err := scanPrivateCandidateDirectory(ctx, sourceRoot, directory)
	if err != nil {
		return nil, err
	}
	manifests := make([]Manifest, 0, len(artifacts))
	for _, artifact := range artifacts {
		manifests = append(manifests, artifact.Manifest)
	}
	if matchTargetInventory(manifests, sourceRevision) != nil {
		return nil, ErrInvalidDirectory
	}
	return artifacts, nil
}

func scanPrivateCandidateDirectory(ctx context.Context, sourceRoot, directory string) ([]VerifiedArtifact, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory || directory == string(filepath.Separator) ||
		!outsideSource(sourceRoot, directory) {
		return nil, ErrInvalidDirectory
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, ErrInvalidDirectory
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 || len(entries) > 64 {
		return nil, ErrInvalidDirectory
	}
	paths := make(map[string]bool, len(entries))
	var artifacts []VerifiedArtifact
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "" || paths[entry.Name()] {
			return nil, ErrInvalidDirectory
		}
		paths[entry.Name()] = true
		if strings.HasSuffix(entry.Name(), ".json") {
			path := filepath.Join(directory, entry.Name())
			manifest, err := LoadCurrent(ctx, sourceRoot, path)
			if err != nil {
				return nil, ErrInvalidDirectory
			}
			artifacts = append(artifacts, VerifiedArtifact{Manifest: manifest, ManifestPath: path})
		}
	}
	if len(artifacts) == 0 || len(entries) != len(artifacts)*2 {
		return nil, ErrInvalidDirectory
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			if !paths[entry.Name()+".oci.tar"] {
				return nil, ErrInvalidDirectory
			}
		} else if !strings.HasSuffix(entry.Name(), ".json.oci.tar") ||
			!paths[strings.TrimSuffix(entry.Name(), ".oci.tar")] {
			return nil, ErrInvalidDirectory
		}
	}
	return artifacts, nil
}

func matchTargetInventory(manifests []Manifest, revision string) error {
	targets := phase6security.Slice6DesiredLocalRoleTargets()
	if len(manifests) != len(targets) || len(revision) != 40 {
		return ErrInvalidDirectory
	}
	expected := make(map[string]bool, len(targets))
	for _, target := range targets {
		expected[target] = true
	}
	seen := make(map[string]bool, len(targets))
	platform, tree := "", ""
	for _, manifest := range manifests {
		target, err := phase6security.Slice6DesiredImageTarget(manifest.Source.Deployment)
		if err != nil || target != manifest.Source.BuildTarget || !expected[target] || seen[target] ||
			manifest.Source.SourceRevision != revision ||
			(manifest.Source.Platform != "linux/amd64" && manifest.Source.Platform != "linux/arm64/v8") ||
			manifest.Source.SourceTreeDigest == "" {
			return ErrInvalidDirectory
		}
		if platform != "" && platform != manifest.Source.Platform ||
			tree != "" && tree != manifest.Source.SourceTreeDigest {
			return ErrInvalidDirectory
		}
		platform, tree = manifest.Source.Platform, manifest.Source.SourceTreeDigest
		seen[target] = true
	}
	if len(seen) != len(expected) {
		return ErrInvalidDirectory
	}
	return nil
}

type roleImageKey struct{ digest, platform string }

// MatchProfile is the pure coverage check used by VerifyDirectory. It does
// not reverify files or source by itself and must not qualify a candidate.
func MatchProfile(profile phase6security.Profile, manifests []Manifest, revision string) error {
	type expectedRoleImage struct {
		kind, selected, config, target string
		deployments                    map[string]bool
	}
	expected := make(map[roleImageKey]expectedRoleImage)
	for _, principal := range profile.Principals {
		if principal.ImageLocation != "local" || principal.Name == "desktop-sandbox-runtime" {
			continue
		}
		target, err := phase6security.Slice6DesiredImageTarget(principal.Name)
		if err != nil || target == phase6security.Slice6BrowserPublishedImage ||
			target == phase6security.Slice6DesktopCandidateImage {
			return ErrInvalidDirectory
		}
		key := roleImageKey{principal.ImageDigest, principal.ImagePlatform}
		value, found := expected[key]
		if !found {
			value = expectedRoleImage{kind: principal.ImageIdentityKind,
				selected: principal.ImageSelectedManifestDigest, config: principal.ImageConfigDigest,
				target: target, deployments: make(map[string]bool)}
		} else if value.kind != principal.ImageIdentityKind || value.selected != principal.ImageSelectedManifestDigest ||
			value.config != principal.ImageConfigDigest || value.target != target {
			return ErrInvalidDirectory
		}
		value.deployments[principal.Name] = true
		expected[key] = value
	}
	if len(expected) == 0 || len(expected) != len(manifests) {
		return ErrInvalidDirectory
	}
	seen := make(map[roleImageKey]bool, len(manifests))
	for _, manifest := range manifests {
		key := roleImageKey{manifest.RuntimeStoreImageID, manifest.Source.Platform}
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
			return ErrInvalidDirectory
		}
		seen[key] = true
	}
	return nil
}

func outsideSource(root, path string) bool {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
