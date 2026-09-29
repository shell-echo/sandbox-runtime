package phase6profilebuilder

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidExternalImageSupply = errors.New("invalid Phase 6 Slice 6 external image supply")

const (
	slice6VaultImage    = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
	slice6PostgresImage = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	slice6ValkeyImage   = "ghcr.io/valkey-io/valkey@sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd"
	slice6DNSImage      = "docker.io/coredns/coredns@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"
)

// ExternalArchive is only a private original OCI archive and a platform
// manifest *hint*. The latter must be present under the fixed registry index
// and exact platform in the archive; it is not accepted as an image authority.
type ExternalArchive struct {
	Path                   string
	SelectedManifestDigest string
}

type ExternalImageInputs struct {
	SourceRoot string
	Platform   string
	Vault      ExternalArchive
	Postgres   ExternalArchive
	Valkey     ExternalArchive
	DNS        ExternalArchive
}

// ExternalImageSupply binds the complete five-service reviewed inventory to
// independently reopened OCI bytes. Two PostgreSQL service identities share
// one immutable image, but remain distinct network/TLS/SQL authorities.
// Live Docker store, selected container manifest and service behavior must be
// observed separately by the full gate.
type ExternalImageSupply struct {
	platform         string
	bindings         map[string]ImageBinding
	descriptorProofs map[string]string
}

func (s ExternalImageSupply) Bindings() map[string]ImageBinding {
	result := make(map[string]ImageBinding, len(s.bindings))
	for name, binding := range s.bindings {
		result[name] = binding
	}
	return result
}

func (s ExternalImageSupply) DescriptorProofs() map[string]string {
	result := make(map[string]string, len(s.descriptorProofs))
	for name, digest := range s.descriptorProofs {
		result[name] = digest
	}
	return result
}

func LoadExternalImageSupply(ctx context.Context, input ExternalImageInputs) (ExternalImageSupply, error) {
	if ctx == nil || ctx.Err() != nil || !cleanAbsolute(input.SourceRoot) ||
		(input.Platform != "linux/amd64" && input.Platform != "linux/arm64/v8") ||
		!slices.Equal(phase6security.Slice6DesiredExternalServiceNames(),
			[]string{"action-history-postgres", "capacity-valkey", "dns", "postgres", "vault"}) {
		return ExternalImageSupply{}, ErrInvalidExternalImageSupply
	}
	archives := []struct {
		name, reference string
		archive         ExternalArchive
	}{
		{"vault", slice6VaultImage, input.Vault},
		{"postgres", slice6PostgresImage, input.Postgres},
		{"capacity-valkey", slice6ValkeyImage, input.Valkey},
		{"dns", slice6DNSImage, input.DNS},
	}
	seenPaths := make(map[string]bool, len(archives))
	bindings := make(map[string]ImageBinding, 5)
	proofs := make(map[string]string, 5)
	for _, item := range archives {
		if ctx.Err() != nil || !cleanAbsolute(item.archive.Path) ||
			!canonicalOutsideSource(input.SourceRoot, item.archive.Path) || !privateFileParent(item.archive.Path) ||
			seenPaths[item.archive.Path] || !validImageDigest(item.archive.SelectedManifestDigest) {
			return ExternalImageSupply{}, ErrInvalidExternalImageSupply
		}
		seenPaths[item.archive.Path] = true
		binding, proof, err := verifyExternalArchive(item.archive, item.reference, input.Platform)
		if err != nil {
			return ExternalImageSupply{}, ErrInvalidExternalImageSupply
		}
		bindings[item.name] = binding
		proofs[item.name] = proof
	}
	bindings["action-history-postgres"] = bindings["postgres"]
	proofs["action-history-postgres"] = proofs["postgres"]
	if len(bindings) != 5 || len(proofs) != 5 {
		return ExternalImageSupply{}, ErrInvalidExternalImageSupply
	}
	return ExternalImageSupply{platform: input.Platform, bindings: bindings, descriptorProofs: proofs}, nil
}

// Resolve archive ancestors before comparing against the real source tree.
// A lexical outside-source check alone could accept a private-looking alias
// that resolves into the checkout. The archive file itself is separately
// required to be a regular, non-symlinked mode-0600 file by the reader.
func canonicalOutsideSource(root, path string) bool {
	if !cleanAbsolute(root) || !cleanAbsolute(path) {
		return false
	}
	canonicalRoot, rootErr := filepath.EvalSymlinks(root)
	canonicalPath, pathErr := filepath.EvalSymlinks(path)
	return rootErr == nil && pathErr == nil && outsideSource(canonicalRoot, canonicalPath)
}

// BindExternalServices is the next incomplete profile layer. It accepts only
// supply created by LoadExternalImageSupply, not a caller-authored image map.
// Separate Vault/CA identity, trust anchors, live service processes and the
// final topology gate remain mandatory.
func (s ExternalImageSupply) BindExternalServices() ([]phase6security.ExternalService, error) {
	if (s.platform != "linux/amd64" && s.platform != "linux/arm64/v8") ||
		len(s.bindings) != 5 || len(s.descriptorProofs) != 5 ||
		s.bindings["postgres"] != s.bindings["action-history-postgres"] ||
		s.descriptorProofs["postgres"] != s.descriptorProofs["action-history-postgres"] {
		return nil, ErrInvalidExternalImageSupply
	}
	templates := phase6security.Slice6DesiredExternalServiceSkeletons()
	if len(templates) != len(s.bindings) {
		return nil, ErrInvalidExternalImageSupply
	}
	for index := range templates {
		service := &templates[index]
		binding, found := s.bindings[service.Name]
		proof, proven := s.descriptorProofs[service.Name]
		reference := map[string]string{
			"action-history-postgres": slice6PostgresImage,
			"capacity-valkey":         slice6ValkeyImage,
			"dns":                     slice6DNSImage,
			"postgres":                slice6PostgresImage,
			"vault":                   slice6VaultImage,
		}[service.Name]
		if !found || !proven || !validImageDigest(proof) || reference == "" ||
			binding.Reference != reference || binding.Digest != reference[strings.LastIndexByte(reference, '@')+1:] ||
			binding.Location != "registry" || binding.Kind != phase6security.ImageIdentityOCIIndex ||
			binding.Platform != s.platform || !validImageDigest(binding.SelectedManifestDigest) ||
			!validImageDigest(binding.ConfigDigest) {
			return nil, ErrInvalidExternalImageSupply
		}
		service.ImageReference, service.ImageDigest = binding.Reference, binding.Digest
		service.ImageLocation, service.ImageIdentityKind = binding.Location, binding.Kind
		service.ImagePlatform, service.ImageSelectedManifestDigest = binding.Platform, binding.SelectedManifestDigest
		service.ImageConfigDigest = binding.ConfigDigest
		service.IdentityDigest = service.Digest()
	}
	return templates, nil
}

func verifyExternalArchive(archive ExternalArchive, reference, platform string) (ImageBinding, string, error) {
	if !cleanAbsolute(archive.Path) || !privateFileParent(archive.Path) ||
		!validImageDigest(archive.SelectedManifestDigest) ||
		!strings.Contains(reference, "@sha256:") ||
		(platform != "linux/amd64" && platform != "linux/arm64/v8") {
		return ImageBinding{}, "", ErrInvalidExternalImageSupply
	}
	digest := reference[strings.LastIndexByte(reference, '@')+1:]
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(archive.Path,
		"registry", phase6security.ImageIdentityOCIIndex, reference, digest,
		platform, archive.SelectedManifestDigest)
	if err != nil || proof.ConfigDigest == "" || proof.ProofDigest == "" ||
		phase6security.VerifyOCIArchiveLayers(archive.Path, documents.Manifest, documents.Config) != nil {
		return ImageBinding{}, "", ErrInvalidExternalImageSupply
	}
	return ImageBinding{Reference: reference, Digest: digest, Location: "registry",
		Kind: phase6security.ImageIdentityOCIIndex, Platform: platform,
		SelectedManifestDigest: archive.SelectedManifestDigest, ConfigDigest: proof.ConfigDigest}, proof.ProofDigest, nil
}
