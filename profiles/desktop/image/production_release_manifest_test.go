package image

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestPhase5ProductionReleaseManifestIsImmutableAndComplete(t *testing.T) {
	document, err := os.ReadFile(Phase5ProductionReleaseManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256(document)); got != Phase5ProductionReleaseManifestDigest {
		t.Fatalf("production release manifest digest = %q", got)
	}
	manifest, err := ParsePhase5ProductionRelease(document)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Packages.InstalledSetDigest != Phase5InstalledSetDigest || len(manifest.Source.Manifests) != 2 {
		t.Fatalf("production release authority = %#v", manifest)
	}
	for platform, want := range map[string]string{
		"linux/amd64":    "sha256:591fef77f3bdbac861ef71ad7cfca7ef6e86a0ac092a7c10084118af10f40097",
		"linux/arm64/v8": "sha256:28468a7b60dc3228ae95f738e7083f6c41b02d381aa1ae6f42afe8424e9a4727",
	} {
		if got := manifest.Source.Manifests[platform].PackageArchiveSetDigest; got != want {
			t.Fatalf("%s package archive set digest = %q", platform, got)
		}
	}
}

func TestProductionAndLocalCandidateManifestsRejectCrossUse(t *testing.T) {
	production, err := os.ReadFile(Phase5ProductionReleaseManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := os.ReadFile(LocalCandidateManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePhase5ProductionRelease(candidate); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("candidate accepted as production release: %v", err)
	}
	if _, err := Parse(production); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("production release accepted as local candidate: %v", err)
	}
	mutated := append([]byte(nil), production...)
	mutated[len(mutated)-2] ^= 1
	if _, err := ParsePhase5ProductionRelease(mutated); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("mutated production release accepted: %v", err)
	}
}
