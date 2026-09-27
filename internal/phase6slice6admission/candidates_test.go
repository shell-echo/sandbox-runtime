package phase6slice6admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestDescriptorPayloadRecomputesRealSemanticProof(t *testing.T) {
	encode := func(value any) []byte {
		t.Helper()
		result, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	config := encode(map[string]any{"architecture": "arm64", "os": "linux", "variant": "v8",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{hashBytes([]byte("uncompressed-layer"))}}})
	configDigest := hashBytes(config)
	manifest := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": hashBytes([]byte("compressed-layer")), "size": 17}}})
	manifestDigest := hashBytes(manifest)
	index := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest": manifestDigest, "size": len(manifest),
			"platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}}}})
	indexDigest := hashBytes(index)
	documents := phase6security.ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: config}
	proof, err := phase6security.VerifyImageDescriptorDocuments("local", phase6security.ImageIdentityOCIIndex,
		indexDigest, indexDigest, "linux/arm64/v8", manifestDigest, configDigest, documents)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := phase6security.NewSlice6DescriptorPayload("container", "desktop-sandbox-runtime", documents)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := payload.Encode()
	if err != nil || hashBytes(raw) == proof.ProofDigest {
		t.Fatal("raw content digest confused with domain-separated semantic proof")
	}
	got, err := verifiedPayload(raw, "container", "desktop-sandbox-runtime", "local",
		phase6security.ImageIdentityOCIIndex, indexDigest, indexDigest, "linux/arm64/v8",
		manifestDigest, configDigest, proof.ProofDigest)
	if err != nil || !sameDocuments(got, documents) {
		t.Fatalf("valid raw OCI payload rejected: %v", err)
	}
	for name, mutate := range map[string]func(*[]byte, *string, *string){
		"wrong proof":    func(_ *[]byte, proof, _ *string) { *proof = hashBytes([]byte("wrong-proof")) },
		"wrong platform": func(_ *[]byte, _, platform *string) { *platform = "linux/amd64" },
		"replaced document": func(raw *[]byte, _, _ *string) {
			changed := payload
			changed.Config = append(bytes.Clone(config), byte(' '))
			*raw, _ = changed.Encode()
		},
		"unknown field": func(raw *[]byte, _, _ *string) {
			*raw = bytes.Replace(*raw, []byte(`"protocol":`), []byte(`"unknown":1,"protocol":`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateRaw := bytes.Clone(raw)
			candidateProof, platform := proof.ProofDigest, "linux/arm64/v8"
			mutate(&candidateRaw, &candidateProof, &platform)
			if _, err := verifiedPayload(candidateRaw, "container", "desktop-sandbox-runtime", "local",
				phase6security.ImageIdentityOCIIndex, indexDigest, indexDigest, platform,
				manifestDigest, configDigest, candidateProof); !errors.Is(err, ErrInvalidAdmission) {
				t.Fatalf("mutated payload admitted: %v", err)
			}
		})
	}
	if _, err := verifiedPayload(raw, "external", "desktop-sandbox-runtime", "local",
		phase6security.ImageIdentityOCIIndex, indexDigest, indexDigest, "linux/arm64/v8",
		manifestDigest, configDigest, proof.ProofDigest); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatal("wrong payload kind admitted")
	}
	if sameDocuments(documents, phase6security.ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: []byte("other")}) {
		t.Fatal("archive descriptor substitution admitted")
	}
}

func TestTypedDesktopCandidateProjectionIsExact(t *testing.T) {
	desktop := desktopcandidate.Manifest{SchemaVersion: desktopcandidate.CurrentSchemaID,
		ManifestDigest: hashBytes([]byte("manifest")), ImageDigest: hashBytes([]byte("image")),
		ImageIdentityKind:      phase6security.ImageIdentityOCIManifest,
		SelectedManifestDigest: hashBytes([]byte("image")), ConfigDigest: hashBytes([]byte("config")),
		DescriptorProofDigest: hashBytes([]byte("proof")), Platform: "linux/arm64/v8",
		SourceRevision:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceTreeDigest: hashBytes([]byte("tree")), ArchiveDigest: hashBytes([]byte("archive")),
		ArchiveSize: 100, ProfileID: "desktop-profile"}
	evidence := phase6security.Slice6Evidence{
		Profile: phase6security.Profile{Principals: []phase6security.Principal{{
			Name: "desktop-sandbox-runtime", ImageLocation: "local", ImageDigest: desktop.ImageDigest,
			ImagePlatform: desktop.Platform, ImageIdentityKind: desktop.ImageIdentityKind,
			ImageConfigDigest: desktop.ConfigDigest}}},
		Candidates: []phase6security.Slice6CandidateImage{desktop.CandidateEvidence()},
	}
	if err := matchCandidates(evidence, nil, desktop); err != nil {
		t.Fatalf("exact Desktop projection rejected: %v", err)
	}
	for name, mutate := range map[string]func(*phase6security.Slice6CandidateImage){
		"schema":   func(c *phase6security.Slice6CandidateImage) { c.ManifestSchema = "legacy" },
		"kind":     func(c *phase6security.Slice6CandidateImage) { c.Kind = phase6security.Slice6CandidateRepositoryRole },
		"source":   func(c *phase6security.Slice6CandidateImage) { c.SourceTreeDigest = hashBytes([]byte("other-tree")) },
		"archive":  func(c *phase6security.Slice6CandidateImage) { c.ArchiveDigest = hashBytes([]byte("other-archive")) },
		"manifest": func(c *phase6security.Slice6CandidateImage) { c.ManifestDigest = hashBytes([]byte("other-manifest")) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := evidence
			candidate.Candidates = append([]phase6security.Slice6CandidateImage(nil), evidence.Candidates...)
			mutate(&candidate.Candidates[0])
			if err := matchCandidates(candidate, nil, desktop); !errors.Is(err, ErrInvalidAdmission) {
				t.Fatalf("candidate substitution admitted: %v", err)
			}
		})
	}
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestRuntimeAndEvidenceRevisionsAreIndependentlyVerified(t *testing.T) {
	root := t.TempDir()
	upstream := filepath.Join(root, "upstream")
	if err := os.Mkdir(upstream, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit := func(directory string, arguments ...string) string {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %.512s", arguments, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	runGit(upstream, "init", "-q")
	if err := os.WriteFile(filepath.Join(upstream, "runtime.txt"), []byte("runtime-byte-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(upstream, "add", "runtime.txt")
	runGit(upstream, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "runtime")
	runtimeRevision := runGit(upstream, "rev-parse", "HEAD")
	runtimeTree, err := desktopcandidate.SourceTreeDigest(upstream)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upstream, "evidence.txt"), []byte("verifier-byte-v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(upstream, "add", "evidence.txt")
	runGit(upstream, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "evidence")
	evidenceRevision := runGit(upstream, "rev-parse", "HEAD")
	evidenceTree, err := desktopcandidate.SourceTreeDigest(upstream)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(root, "runtime")
	command := exec.Command("git", "clone", "-q", upstream, runtimeRoot)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("clone exact runtime source: %v: %.512s", err, output)
	}
	runGit(runtimeRoot, "checkout", "-q", "--detach", runtimeRevision)
	ctx := context.Background()
	if verifySource(ctx, runtimeRoot, runtimeRevision, runtimeTree) != nil ||
		verifySource(ctx, upstream, evidenceRevision, evidenceTree) != nil {
		t.Fatal("clean R and advanced E source identities were not independently verified")
	}
	if verifySource(ctx, upstream, runtimeRevision, runtimeTree) == nil {
		t.Fatal("evidence checkout was mislabeled as old runtime source")
	}
	if verifySource(ctx, runtimeRoot, evidenceRevision, evidenceTree) == nil {
		t.Fatal("runtime checkout was mislabeled as newer evidence source")
	}
	if verifySource(ctx, runtimeRoot, runtimeRevision, hashBytes([]byte("forged-tree"))) == nil {
		t.Fatal("forged runtime tree admitted")
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "dirty.txt"), []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}
	if verifySource(ctx, runtimeRoot, runtimeRevision, runtimeTree) == nil {
		t.Fatal("dirty source view admitted")
	}
}

func TestExecutingEvidenceSourceRejectsInventedRevision(t *testing.T) {
	if verifyExecutingEvidenceSource(strings.Repeat("f", 40)) == nil {
		t.Fatal("running verifier relabeled as an invented evidence revision")
	}
}
