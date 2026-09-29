package phase6profilebuilder

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

func TestBindPrincipalImagesUsesExactReviewedDeploymentAndTargetInventory(t *testing.T) {
	const platform = "linux/arm64/v8"
	image := func(value string) ImageBinding {
		digest := "sha256:" + strings.Repeat(value, 64)
		return ImageBinding{Reference: digest, Digest: digest, Location: "local",
			Kind: phase6security.ImageIdentityOCIManifest, Platform: platform, ConfigDigest: digest}
	}
	supply := ImageSupply{Platform: platform, LocalRoleTargets: make(map[string]ImageBinding),
		Desktop: image("b"), Browser: ImageBinding{Reference: browserimage.LockedPublication().Image(),
			Digest: browserimage.PublishedDigest, Location: "registry", Kind: phase6security.ImageIdentityOCIIndex,
			Platform: platform, SelectedManifestDigest: browserimage.PublishedARM64Manifest,
			ConfigDigest: "sha256:" + strings.Repeat("c", 64)}}
	for _, target := range phase6security.Slice6DesiredLocalRoleTargets() {
		supply.LocalRoleTargets[target] = image("a")
	}
	names := phase6security.Slice6DesiredDeploymentNames()
	principals := make([]phase6security.Principal, 0, len(names))
	for _, name := range names {
		principals = append(principals, phase6security.Principal{Name: name})
	}
	bound, err := supply.bindPrincipalImages(principals)
	if err != nil || len(bound) != len(names) {
		t.Fatalf("reviewed image-target mapping rejected: %d, %v", len(bound), err)
	}
	for index, principal := range bound {
		target, _ := phase6security.Slice6DesiredImageTarget(principal.Name)
		wanted := supply.LocalRoleTargets[target]
		if target == phase6security.Slice6BrowserPublishedImage {
			wanted = supply.Browser
		} else if target == phase6security.Slice6DesktopCandidateImage {
			wanted = supply.Desktop
		}
		if principal.ImageDigest != wanted.Digest || principals[index].ImageDigest != "" {
			t.Fatalf("deployment %s acquired wrong image or mutated draft", principal.Name)
		}
	}
	missing := append([]phase6security.Principal(nil), principals[1:]...)
	if _, err := supply.bindPrincipalImages(missing); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("missing reviewed deployment admitted")
	}
	duplicate := append([]phase6security.Principal(nil), principals...)
	duplicate[0] = duplicate[1]
	if _, err := supply.bindPrincipalImages(duplicate); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("duplicate deployment admitted")
	}
	delete(supply.LocalRoleTargets, phase6security.Slice6DesiredLocalRoleTargets()[0])
	if _, err := supply.bindPrincipalImages(principals); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("missing local target admitted")
	}
	supply.LocalRoleTargets[phase6security.Slice6DesiredLocalRoleTargets()[0]] = image("a")
	supply.Browser.Location = "local"
	if _, err := supply.bindPrincipalImages(principals); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("published Browser was relabeled as a local image")
	}
	supply.Browser.Location = "registry"
	supply.Browser.SelectedManifestDigest = "sha256:" + strings.Repeat("d", 64)
	if _, err := supply.bindPrincipalImages(principals); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("wrong platform-selected Browser manifest admitted")
	}
	supply.Browser.SelectedManifestDigest = browserimage.PublishedARM64Manifest
	supply.Desktop.Reference = "mutable:latest"
	if _, err := supply.bindPrincipalImages(principals); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("mutable Desktop image reference admitted")
	}
}

func TestLoadImageSupplyRequiresPrivateSourceBoundArtifacts(t *testing.T) {
	if _, err := LoadImageSupply(context.Background(), "", "", "", "", ""); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("empty image supply admitted")
	}
}
