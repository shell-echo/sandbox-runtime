package phase6rolecandidate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	ManifestSchema         = "sandbox-runtime.phase6-local-role-candidate.v1"
	ManifestClassification = "local-candidate-non-release"
	maxManifestBytes       = 32 << 10
)

var ErrInvalidManifest = errors.New("invalid Phase 6 local role candidate manifest")

// Manifest is a private, non-release record of one source-bound role image.
// It does not establish a running deployment, registry publication, signature,
// or the full Slice 6 gate. The archive sidecar is always path+.oci.tar.
type Manifest struct {
	Schema                     string                         `json:"schema"`
	Classification             string                         `json:"classification"`
	Source                     SourceInputs                   `json:"source"`
	ImageIdentityKind          string                         `json:"image_identity_kind"`
	RuntimeStoreImageID        string                         `json:"runtime_store_image_id"`
	RuntimeStoreDescriptor     phase6security.ImageDescriptor `json:"runtime_store_descriptor"`
	SelectedManifestDescriptor phase6security.ImageDescriptor `json:"selected_manifest_descriptor"`
	OCIConfigDigest            string                         `json:"oci_config_digest"`
	DescriptorProofDigest      string                         `json:"descriptor_proof_digest"`
	ArchiveDigest              string                         `json:"archive_digest"`
	ArchiveSize                int64                          `json:"archive_size"`
	RootFSChainDigest          string                         `json:"rootfs_chain_digest"`
	BinaryDigest               string                         `json:"binary_digest"`
	BuildContextDigest         string                         `json:"build_context_digest"`
	ManifestDigest             string                         `json:"manifest_digest"`
}

// NewManifest accepts only the already-observed stopped-container probe and
// source/binary proof, then independently reopens and verifies the archive and
// source. The stopped container's raw inspect receipts remain separate inputs
// to the operator gate; this manifest is not a substitute for them.
func NewManifest(ctx context.Context, sourceRoot, archivePath string, source SourceInputs,
	principal phase6security.Principal, probe phase6security.Slice6LocalRoleCandidateProbe,
	build BuildContextProof) (Manifest, error) {
	if principal.Name != source.Deployment || principal.ImageLocation != "local" ||
		principal.ImageReference != principal.ImageDigest || principal.ImagePlatform != source.Platform ||
		probe.Image.ImageReference != principal.ImageReference ||
		probe.Image.RuntimeStoreImageID != principal.ImageDigest ||
		probe.Image.RuntimePlatform != principal.ImagePlatform ||
		probe.Image.OCIConfigDigest != principal.ImageConfigDigest ||
		probe.Image.RuntimeStoreDescriptor.Digest != principal.ImageDigest ||
		probe.Image.SelectedManifestDescriptor.Digest == "" {
		return Manifest{}, ErrInvalidManifest
	}
	selected := principal.ImageDigest
	if principal.ImageIdentityKind == phase6security.ImageIdentityOCIIndex {
		selected = principal.ImageSelectedManifestDigest
	}
	if probe.Image.SelectedManifestDescriptor.Digest != selected {
		return Manifest{}, ErrInvalidManifest
	}
	m := Manifest{Schema: ManifestSchema, Classification: ManifestClassification, Source: source,
		ImageIdentityKind: principal.ImageIdentityKind, RuntimeStoreImageID: principal.ImageDigest,
		RuntimeStoreDescriptor:     probe.Image.RuntimeStoreDescriptor,
		SelectedManifestDescriptor: probe.Image.SelectedManifestDescriptor,
		OCIConfigDigest:            probe.Image.OCIConfigDigest, DescriptorProofDigest: probe.Image.DescriptorProofDigest,
		ArchiveDigest: probe.ArchiveDigest, ArchiveSize: probe.ArchiveSize,
		RootFSChainDigest: probe.RootFSChainDigest, BinaryDigest: build.BinaryDigest,
		BuildContextDigest: build.BuildContextDigest}
	m.ManifestDigest = m.digest()
	if m.VerifyArchive(ctx, sourceRoot, archivePath) != nil {
		return Manifest{}, ErrInvalidManifest
	}
	return m, nil
}

// VerifyArchive derives the immutable inputs again from a clean checkout and
// exact private OCI bytes, including an independent Go build matched to the
// executable extracted from the ordered image layers.
func (m Manifest) VerifyArchive(ctx context.Context, sourceRoot, archivePath string) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(archivePath) ||
		filepath.Clean(archivePath) != archivePath || m.Schema != ManifestSchema ||
		m.Classification != ManifestClassification || m.ManifestDigest != m.digest() ||
		m.Source.VerifySource(ctx, sourceRoot) != nil ||
		m.ImageIdentityKind != phase6security.ImageIdentityOCIManifest &&
			m.ImageIdentityKind != phase6security.ImageIdentityOCIIndex {
		return ErrInvalidManifest
	}
	selected := m.RuntimeStoreImageID
	selectedArgument := ""
	if m.ImageIdentityKind == phase6security.ImageIdentityOCIIndex {
		selected = m.SelectedManifestDescriptor.Digest
		selectedArgument = selected
	}
	if m.RuntimeStoreDescriptor.Digest != m.RuntimeStoreImageID ||
		m.SelectedManifestDescriptor.Digest != selected ||
		!validRoleDescriptorType(m.ImageIdentityKind, m.RuntimeStoreDescriptor.MediaType) ||
		!validRoleDescriptorType(phase6security.ImageIdentityOCIManifest, m.SelectedManifestDescriptor.MediaType) {
		return ErrInvalidManifest
	}
	archiveDigest, archiveSize, err := phase6security.DigestSlice6LocalRoleArchive(archivePath)
	if err != nil || archiveDigest != m.ArchiveDigest || archiveSize != m.ArchiveSize {
		return ErrInvalidManifest
	}
	documents, err := phase6security.ReadOCIArchiveDocuments(archivePath, m.ImageIdentityKind,
		m.RuntimeStoreImageID, selected, m.OCIConfigDigest)
	if err != nil {
		return ErrInvalidManifest
	}
	proof, err := phase6security.VerifyImageDescriptorDocuments("local", m.ImageIdentityKind,
		m.RuntimeStoreImageID, m.RuntimeStoreImageID, m.Source.Platform, selectedArgument,
		m.OCIConfigDigest, documents)
	if err != nil || proof.ConfigDigest != m.OCIConfigDigest || proof.ProofDigest != m.DescriptorProofDigest ||
		m.RuntimeStoreDescriptor.Size != int64(len(topRoleDocument(m.ImageIdentityKind, documents))) ||
		m.SelectedManifestDescriptor.Size != int64(len(documents.Manifest)) ||
		!validRoleConfig(documents.Config, m.Source) ||
		phase6security.VerifyOCIArchiveLayers(archivePath, documents.Manifest, documents.Config) != nil {
		return ErrInvalidManifest
	}
	chain, err := phase6security.Slice6RootFSChainDigest(documents.Config)
	if err != nil || chain != m.RootFSChainDigest {
		return ErrInvalidManifest
	}
	build, err := VerifyBuildContext(ctx, sourceRoot, m.Source, archivePath, documents.Manifest, documents.Config)
	if err != nil || build.BinaryDigest != m.BinaryDigest ||
		build.BuildContextDigest != m.BuildContextDigest {
		return ErrInvalidManifest
	}
	return nil
}

// CandidateEvidence is a projection for the Slice 6 manifest verifier. The
// caller must invoke VerifyArchive first and separately observe the final
// running container and full same-run receipt bundle.
func (m Manifest) CandidateEvidence() phase6security.Slice6CandidateImage {
	return phase6security.Slice6CandidateImage{BuildTarget: m.Source.BuildTarget,
		RuntimeStoreImageID: m.RuntimeStoreImageID, OCIConfigDigest: m.OCIConfigDigest,
		Platform: m.Source.Platform, SourceRevision: m.Source.SourceRevision,
		SourceTreeDigest: m.Source.SourceTreeDigest, BuildContextDigest: m.BuildContextDigest,
		DockerfileDigest: m.Source.DockerfileDigest, ToolchainDigest: m.Source.ToolchainDigest,
		BaseImageDigest: m.Source.BaseImageDigest, DependencyLockDigest: m.Source.DependencyLockDigest,
		BuildParametersDigest: m.Source.BuildParametersDigest, ArchiveDigest: m.ArchiveDigest,
		RootFSChainDigest: m.RootFSChainDigest}
}

// WritePrivate creates a new immutable-in-place manifest beside its archive.
// The caller owns the preexisting mode-0700 directory and archive sidecar.
func (m Manifest) WritePrivate(path string) error {
	if !validPrivateManifestPath(path) || m.ManifestDigest != m.digest() {
		return ErrInvalidManifest
	}
	document, err := json.Marshal(m)
	if err != nil || len(document) > maxManifestBytes {
		return ErrInvalidManifest
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalidManifest
	}
	count, writeErr := file.Write(document)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || count != len(document) {
		_ = os.Remove(path) // Only the O_EXCL file created above.
		return ErrInvalidManifest
	}
	return nil
}

func LoadCurrent(ctx context.Context, sourceRoot, path string) (Manifest, error) {
	if !validPrivateManifestPath(path) {
		return Manifest{}, ErrInvalidManifest
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > maxManifestBytes {
		return Manifest{}, ErrInvalidManifest
	}
	document, err := os.ReadFile(path)
	if err != nil || int64(len(document)) != info.Size() {
		return Manifest{}, ErrInvalidManifest
	}
	m, err := decodeCanonicalManifest(document)
	if err != nil || m.VerifyArchive(ctx, sourceRoot, path+".oci.tar") != nil {
		return Manifest{}, ErrInvalidManifest
	}
	return m, nil
}

func decodeCanonicalManifest(document []byte) (Manifest, error) {
	if len(document) < 1 || len(document) > maxManifestBytes {
		return Manifest{}, ErrInvalidManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var m Manifest
	if decoder.Decode(&m) != nil {
		return Manifest{}, ErrInvalidManifest
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return Manifest{}, ErrInvalidManifest
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(document, canonical) || m.ManifestDigest != m.digest() ||
		m.Schema != ManifestSchema || m.Classification != ManifestClassification {
		return Manifest{}, ErrInvalidManifest
	}
	return m, nil
}

func (m Manifest) digest() string {
	m.ManifestDigest = ""
	document, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-local-role-manifest/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func validPrivateManifestPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false
	}
	parent, err := os.Lstat(filepath.Dir(path))
	return err == nil && parent.IsDir() && parent.Mode().Perm() == 0o700 && parent.Mode()&os.ModeSymlink == 0
}

func validRoleDescriptorType(kind, mediaType string) bool {
	if kind == phase6security.ImageIdentityOCIIndex {
		return mediaType == "application/vnd.oci.image.index.v1+json" ||
			mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
	}
	return mediaType == "application/vnd.oci.image.manifest.v1+json" ||
		mediaType == "application/vnd.docker.distribution.manifest.v2+json"
}

func topRoleDocument(kind string, documents phase6security.ImageDescriptorDocuments) []byte {
	if kind == phase6security.ImageIdentityOCIIndex {
		return documents.Index
	}
	return documents.Manifest
}

func validRoleConfig(document []byte, source SourceInputs) bool {
	var config struct {
		Config struct {
			User       string            `json:"User"`
			Entrypoint []string          `json:"Entrypoint"`
			Labels     map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if json.Unmarshal(document, &config) != nil || config.Config.User != "65532:65532" ||
		len(config.Config.Entrypoint) != 1 || config.Config.Entrypoint[0] != "/usr/local/bin/phase6-role" {
		return false
	}
	labels := config.Config.Labels
	return labels["io.github.shell-echo.sandbox-runtime.phase6-candidate"] == "local-only-non-release" &&
		labels["io.github.shell-echo.sandbox-runtime.source-revision"] == source.SourceRevision &&
		labels["io.github.shell-echo.sandbox-runtime.role-target"] == source.BuildTarget &&
		labels["io.github.shell-echo.sandbox-runtime.go-version"] == "go1.26.8"
}
