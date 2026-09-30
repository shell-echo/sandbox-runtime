package phase6profilebuilder

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

func TestImageDraftPreservesReviewedIdentityPlacementAndIssuerMounts(t *testing.T) {
	draft, err := BuildSlice6PrincipalDraft(strings.Repeat("c", 32),
		"sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	const platform = "linux/arm64/v8"
	local := ImageBinding{Reference: "sha256:" + strings.Repeat("d", 64),
		Digest: "sha256:" + strings.Repeat("d", 64), ConfigDigest: "sha256:" + strings.Repeat("e", 64),
		Location: "local", Kind: phase6security.ImageIdentityOCIManifest, Platform: platform}
	supply := ImageSupply{Platform: platform, LocalRoleTargets: make(map[string]ImageBinding), Desktop: local,
		Browser: ImageBinding{Reference: browserimage.LockedPublication().Image(),
			Digest: browserimage.PublishedDigest, ConfigDigest: "sha256:" + strings.Repeat("f", 64),
			Location: "registry", Kind: phase6security.ImageIdentityOCIIndex, Platform: platform,
			SelectedManifestDigest: browserimage.PublishedARM64Manifest}}
	for _, target := range phase6security.Slice6DesiredLocalRoleTargets() {
		supply.LocalRoleTargets[target] = local
	}
	bound, err := bindPrincipalDraftImages(draft, supply)
	if err != nil || len(bound.Principals) != 82 || len(bound.CredentialIssuerSockets) != 14 ||
		!slices.Equal(bound.CredentialIssuerSockets, draft.CredentialIssuerSockets) ||
		len(bound.ImageSupply.LocalRoleTargets) != len(supply.LocalRoleTargets) ||
		bound.ImageSupply.Browser != supply.Browser {
		t.Fatalf("complete reviewed image binding rejected: %v", err)
	}
	if bound.ImageSupply.VerifySources(context.Background()) == nil {
		t.Fatal("synthetic image binding was accepted without original source artifacts")
	}
	resourceRoot, _ := writeSyntheticResourceSupply(t)
	resources, err := LoadResourceSeccompSupply(resourceRoot, platform)
	if err != nil {
		t.Fatal(err)
	}
	hardened, _, err := resources.BindResourceSeccompDraft(bound)
	if err != nil || hardened.ImageSupply.Browser != supply.Browser ||
		len(hardened.ImageSupply.LocalRoleTargets) != len(supply.LocalRoleTargets) {
		t.Fatalf("resource layer lost image source handles: %v", err)
	}
	for index, principal := range bound.Principals {
		original := draft.Principals[index]
		if principal.Name != original.Name || principal.UID != original.UID || principal.GID != original.GID ||
			!slices.Equal(principal.Mounts, original.Mounts) || !slices.Equal(principal.Networks, original.Networks) ||
			principal.ImageDigest == "" || original.ImageDigest != "" {
			t.Fatalf("image binding changed another principal field: %s", principal.Name)
		}
	}
	prebound := draft
	prebound.Principals = append([]phase6security.Principal(nil), draft.Principals...)
	prebound.Principals[0].ImageDigest = local.Digest
	if _, err := bindPrincipalDraftImages(prebound, supply); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatal("prebound image was silently replaced")
	}
}

func TestBuildSlice6ImageDraftRejectsMissingSourceBoundArtifacts(t *testing.T) {
	if _, err := BuildSlice6ImageDraft(context.Background(), ImageDraftInputs{}); !errors.Is(err, ErrInvalidImageSupply) {
		t.Fatalf("missing exact candidate artifacts admitted: %v", err)
	}
}
