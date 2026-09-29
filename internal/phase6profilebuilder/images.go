// Package phase6profilebuilder assembles reviewed desired configuration from
// independently verified bootstrap inputs. It never produces observations or
// a Slice 6 success manifest.
package phase6profilebuilder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

var ErrInvalidImageSupply = errors.New("invalid Phase 6 Slice 6 profile image supply")

// ImageBinding is an expected image identity, not proof of a running
// container. The candidate/source/descriptor artifacts must be re-opened by
// the final admission verifier after the complete profile is frozen.
type ImageBinding struct {
	Reference, Digest, Location, Kind, Platform string
	SelectedManifestDigest, ConfigDigest        string
}

type ImageSupply struct {
	RuntimeRevision, RuntimeTreeDigest, Platform string
	LocalRoleTargets                             map[string]ImageBinding
	Desktop, Browser                             ImageBinding
	RoleArtifacts                                []phase6rolecandidate.VerifiedArtifact
	DesktopCandidate                             desktopcandidate.Manifest
	BrowserDescriptorProofDigest                 string
}

// bindPrincipalImages fills only the image identity fields of an already
// reviewed structural draft. It cannot turn that draft into a valid profile;
// the full builder must still bind identity, network, TLS, external services
// and digests, then run every reviewed desired-inventory validator.
func (s ImageSupply) bindPrincipalImages(principals []phase6security.Principal) ([]phase6security.Principal, error) {
	names := phase6security.Slice6DesiredDeploymentNames()
	targets := phase6security.Slice6DesiredLocalRoleTargets()
	if len(principals) != len(names) || len(s.LocalRoleTargets) != len(targets) ||
		(s.Platform != "linux/amd64" && s.Platform != "linux/arm64/v8") {
		return nil, ErrInvalidImageSupply
	}
	wantedNames := make(map[string]bool, len(names))
	for _, name := range names {
		wantedNames[name] = true
	}
	wantedTargets := make(map[string]bool, len(targets))
	for _, target := range targets {
		wantedTargets[target] = true
		if _, found := s.LocalRoleTargets[target]; !found {
			return nil, ErrInvalidImageSupply
		}
	}
	for target := range s.LocalRoleTargets {
		if !wantedTargets[target] {
			return nil, ErrInvalidImageSupply
		}
	}
	bound := append([]phase6security.Principal(nil), principals...)
	seen := make(map[string]bool, len(names))
	for index := range bound {
		principal := &bound[index]
		if !wantedNames[principal.Name] || seen[principal.Name] {
			return nil, ErrInvalidImageSupply
		}
		seen[principal.Name] = true
		target, err := phase6security.Slice6DesiredImageTarget(principal.Name)
		if err != nil {
			return nil, ErrInvalidImageSupply
		}
		var image ImageBinding
		switch target {
		case phase6security.Slice6BrowserPublishedImage:
			image = s.Browser
		case phase6security.Slice6DesktopCandidateImage:
			image = s.Desktop
		default:
			image = s.LocalRoleTargets[target]
		}
		if !validImageBinding(target, s.Platform, image) {
			return nil, ErrInvalidImageSupply
		}
		principal.ImageReference = image.Reference
		principal.ImageDigest = image.Digest
		principal.ImageLocation = image.Location
		principal.ImageIdentityKind = image.Kind
		principal.ImagePlatform = image.Platform
		principal.ImageSelectedManifestDigest = image.SelectedManifestDigest
		principal.ImageConfigDigest = image.ConfigDigest
	}
	return bound, nil
}

func validImageBinding(target, platform string, image ImageBinding) bool {
	if image.Platform != platform || !validImageDigest(image.Digest) || !validImageDigest(image.ConfigDigest) {
		return false
	}
	if image.Kind == phase6security.ImageIdentityOCIIndex {
		if !validImageDigest(image.SelectedManifestDigest) {
			return false
		}
	} else if image.Kind != phase6security.ImageIdentityOCIManifest || image.SelectedManifestDigest != "" {
		return false
	}
	if target == phase6security.Slice6BrowserPublishedImage {
		publication := browserimage.LockedPublication()
		selected, err := publication.SelectedManifest(platform)
		return err == nil && image.Location == "registry" && image.Kind == phase6security.ImageIdentityOCIIndex &&
			image.Reference == publication.Image() && image.Digest == publication.Digest &&
			image.SelectedManifestDigest == selected
	}
	return image.Location == "local" && image.Reference == image.Digest
}

func validImageDigest(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") && lowerHex(strings.TrimPrefix(value, "sha256:"))
}

// LoadImageSupply is intentionally independent of a Profile, so the gate can
// construct expected image fields before calling Profile.Validate. It accepts
// no operator-authored digest map. The Browser publication is repository
// locked; the local role and Desktop bytes are independently reopened from
// clean R. Docker store/container selection remains a separate live gate.
func LoadImageSupply(ctx context.Context, sourceRoot, sourceRevision, roleDirectory,
	desktopCandidatePath, browserArchivePath string) (ImageSupply, error) {
	if ctx == nil || ctx.Err() != nil || !cleanAbsolute(sourceRoot) || !cleanAbsolute(roleDirectory) ||
		!cleanAbsolute(desktopCandidatePath) || !cleanAbsolute(browserArchivePath) ||
		len(sourceRevision) != 40 || !lowerHex(sourceRevision) ||
		!privateFileParent(browserArchivePath) ||
		!outsideSource(sourceRoot, roleDirectory) || !outsideSource(sourceRoot, desktopCandidatePath) ||
		!outsideSource(sourceRoot, browserArchivePath) {
		return ImageSupply{}, ErrInvalidImageSupply
	}
	artifacts, err := phase6rolecandidate.VerifyTargetDirectoryArtifacts(ctx, sourceRoot, roleDirectory, sourceRevision)
	if err != nil || len(artifacts) == 0 {
		return ImageSupply{}, ErrInvalidImageSupply
	}
	platform := artifacts[0].Manifest.Source.Platform
	tree := artifacts[0].Manifest.Source.SourceTreeDigest
	roles := make(map[string]ImageBinding, len(artifacts))
	for _, artifact := range artifacts {
		manifest := artifact.Manifest
		selected := ""
		if manifest.ImageIdentityKind == phase6security.ImageIdentityOCIIndex {
			selected = manifest.SelectedManifestDescriptor.Digest
		}
		roles[manifest.Source.BuildTarget] = ImageBinding{
			Reference: manifest.RuntimeStoreImageID, Digest: manifest.RuntimeStoreImageID,
			Location: "local", Kind: manifest.ImageIdentityKind, Platform: platform,
			SelectedManifestDigest: selected, ConfigDigest: manifest.OCIConfigDigest,
		}
	}
	desktop, err := desktopcandidate.LoadCurrent(desktopCandidatePath)
	if err != nil || desktop.VerifySource(sourceRoot) != nil || desktop.SourceRevision != sourceRevision ||
		desktop.SourceTreeDigest != tree || desktop.Platform != platform {
		return ImageSupply{}, ErrInvalidImageSupply
	}
	desktopSelected := ""
	if desktop.ImageIdentityKind == phase6security.ImageIdentityOCIIndex {
		desktopSelected = desktop.SelectedManifestDigest
	}
	publication := browserimage.LockedPublication()
	selected, err := publication.SelectedManifest(platform)
	if err != nil {
		return ImageSupply{}, ErrInvalidImageSupply
	}
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(browserArchivePath,
		"registry", phase6security.ImageIdentityOCIIndex, publication.Image(), publication.Digest, platform, selected)
	if err != nil || phase6security.VerifyOCIArchiveLayers(browserArchivePath, documents.Manifest, documents.Config) != nil {
		return ImageSupply{}, ErrInvalidImageSupply
	}
	return ImageSupply{RuntimeRevision: sourceRevision, RuntimeTreeDigest: tree, Platform: platform,
		LocalRoleTargets: roles, RoleArtifacts: artifacts, DesktopCandidate: desktop,
		Desktop: ImageBinding{Reference: desktop.ImageDigest, Digest: desktop.ImageDigest,
			Location: "local", Kind: desktop.ImageIdentityKind, Platform: platform,
			SelectedManifestDigest: desktopSelected, ConfigDigest: desktop.ConfigDigest},
		Browser: ImageBinding{Reference: publication.Image(), Digest: publication.Digest,
			Location: "registry", Kind: phase6security.ImageIdentityOCIIndex, Platform: platform,
			SelectedManifestDigest: selected, ConfigDigest: proof.ConfigDigest},
		BrowserDescriptorProofDigest: proof.ProofDigest,
	}, nil
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func lowerHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func privateFileParent(path string) bool {
	parent, err := os.Lstat(filepath.Dir(path))
	return err == nil && parent.IsDir() && parent.Mode()&os.ModeSymlink == 0 && parent.Mode().Perm() == 0o700
}

func outsideSource(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
