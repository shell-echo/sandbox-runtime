package phase6profilebuilder

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestExternalImageSupplyRefusesAbsentOrOperatorSubstitutedInputs(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadExternalImageSupply(context.Background(), ExternalImageInputs{
		SourceRoot: root, Platform: "linux/arm64/v8",
	}); err == nil {
		t.Fatal("missing original external image archives were accepted")
	}
	if _, err := LoadExternalImageSupply(context.Background(), ExternalImageInputs{
		SourceRoot: root, Platform: "linux/ppc64le",
	}); err == nil {
		t.Fatal("unsupported platform was accepted")
	}
	if _, err := LoadExternalImageSupply(nil, ExternalImageInputs{
		SourceRoot: root, Platform: "linux/arm64/v8",
	}); err == nil {
		t.Fatal("missing cancellation authority was accepted")
	}
}

func TestExternalArchiveCannotAliasSourceThroughAncestor(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "image.oci.tar")
	if err := os.WriteFile(archive, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	alias := filepath.Join(private, "source")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if canonicalOutsideSource(root, filepath.Join(alias, "image.oci.tar")) {
		t.Fatal("archive alias resolving into the source tree was accepted")
	}
	if canonicalOutsideSource(root, archive) {
		t.Fatal("archive inside the source tree was accepted")
	}
	separate := filepath.Join(private, "other.oci.tar")
	if err := os.WriteFile(separate, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !canonicalOutsideSource(root, separate) {
		t.Fatal("separate private archive was rejected")
	}
}

func TestExternalServiceSkeletonBindsOnlyReviewedIdentities(t *testing.T) {
	const platform = "linux/arm64/v8"
	selected := "sha256:" + strings.Repeat("a", 64)
	config := "sha256:" + strings.Repeat("b", 64)
	proof := "sha256:" + strings.Repeat("c", 64)
	references := map[string]string{
		"action-history-postgres": slice6PostgresImage,
		"capacity-valkey":         slice6ValkeyImage,
		"dns":                     slice6DNSImage,
		"postgres":                slice6PostgresImage,
		"vault":                   slice6VaultImage,
	}
	supply := ExternalImageSupply{platform: platform, bindings: map[string]ImageBinding{}, descriptorProofs: map[string]string{}}
	for name, reference := range references {
		supply.bindings[name] = ImageBinding{Reference: reference,
			Digest: reference[strings.LastIndexByte(reference, '@')+1:], Location: "registry",
			Kind: phase6security.ImageIdentityOCIIndex, Platform: platform,
			SelectedManifestDigest: selected, ConfigDigest: config}
		supply.descriptorProofs[name] = proof
	}
	services, err := supply.BindExternalServices()
	if err != nil || len(services) != len(references) {
		t.Fatalf("reviewed external skeleton rejected: %v", err)
	}
	for index, desired := range phase6security.Slice6DesiredExternalServiceSkeletons() {
		actual := services[index]
		if actual.Name != desired.Name || actual.URI != desired.URI ||
			!slices.Equal(actual.DNSNames, desired.DNSNames) ||
			!slices.Equal(actual.IngressEdges, desired.IngressEdges) ||
			actual.IdentityDigest != actual.Digest() || len(actual.Networks) != 0 {
			t.Fatalf("external identity/ingress drifted for %s", desired.Name)
		}
	}
	principalDraft, err := BuildSlice6PrincipalDraft(strings.Repeat("1", 32),
		"sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	edges, err := phase6security.BuildSlice6DesiredTrustEdges(principalDraft.Principals, services)
	if err != nil || len(edges) < 77 {
		t.Fatalf("reviewed external identities cannot bind the complete initial trust graph: %d, %v", len(edges), err)
	}
	bindings := supply.Bindings()
	bindings["vault"] = ImageBinding{}
	if supply.Bindings()["vault"].Reference != slice6VaultImage {
		t.Fatal("caller mutated retained verified image binding")
	}
	supply.bindings["vault"] = supply.bindings["dns"]
	if _, err := supply.BindExternalServices(); err == nil {
		t.Fatal("Vault image substitution was accepted")
	}
}
