package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
)

// Slice6LocalRoleCandidateProbe is a pre-freeze input observation from a
// stopped, run-owned Docker container and a retained private OCI archive. It
// is not observation of the final running role or a build-provenance receipt.
type Slice6LocalRoleCandidateProbe struct {
	Image             DockerImageObservation
	ArchiveDigest     string
	ArchiveSize       int64
	RootFSChainDigest string
}

// VerifySlice6LocalRoleCandidateProbe binds the reviewed local role target,
// loaded Docker image, selected platform manifest, config, ordered layers and
// exact retained archive. The caller owns container creation/cleanup and must
// separately establish immutable source/build inputs before profile freeze.
func VerifySlice6LocalRoleCandidateProbe(principal Principal, sourceRevision string,
	containerInspect, imageInspect []byte, archivePath string) (Slice6LocalRoleCandidateProbe, error) {
	if VerifySlice6LocalRoleImageInspect(principal, sourceRevision, imageInspect) != nil {
		return Slice6LocalRoleCandidateProbe{}, ErrInvalidImageDescriptor
	}
	selected := principal.ImageDigest
	selectedArgument := ""
	if principal.ImageIdentityKind == ImageIdentityOCIIndex {
		selected = principal.ImageSelectedManifestDigest
		selectedArgument = selected
	}
	documents, err := ReadOCIArchiveDocuments(archivePath, principal.ImageIdentityKind,
		principal.ImageDigest, selected, principal.ImageConfigDigest)
	if err != nil || VerifyOCIArchiveLayers(archivePath, documents.Manifest, documents.Config) != nil {
		return Slice6LocalRoleCandidateProbe{}, ErrInvalidImageDescriptor
	}
	image, err := ObserveDockerRuntimeImage(containerInspect, imageInspect, "local", principal.ImageIdentityKind,
		principal.ImageReference, principal.ImageDigest, principal.ImagePlatform,
		selectedArgument, principal.ImageConfigDigest, documents)
	if err != nil {
		return Slice6LocalRoleCandidateProbe{}, ErrInvalidImageDescriptor
	}
	archiveDigest, archiveSize, err := digestSlice6LocalRoleArchive(archivePath)
	if err != nil {
		return Slice6LocalRoleCandidateProbe{}, ErrInvalidImageDescriptor
	}
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if json.Unmarshal(documents.Config, &config) != nil || len(config.RootFS.DiffIDs) == 0 {
		return Slice6LocalRoleCandidateProbe{}, ErrInvalidImageDescriptor
	}
	chain, err := json.Marshal(config.RootFS.DiffIDs)
	if err != nil {
		return Slice6LocalRoleCandidateProbe{}, ErrInvalidImageDescriptor
	}
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-rootfs-chain/v1\x00"), chain...))
	return Slice6LocalRoleCandidateProbe{Image: image, ArchiveDigest: archiveDigest, ArchiveSize: archiveSize,
		RootFSChainDigest: "sha256:" + hex.EncodeToString(hash[:])}, nil
}

func digestSlice6LocalRoleArchive(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxOCIArchiveBytes {
		return "", 0, ErrInvalidImageDescriptor
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, ErrInvalidImageDescriptor
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() ||
		opened.Mode().Perm() != 0o600 {
		return "", 0, ErrInvalidImageDescriptor
	}
	hash := sha256.New()
	count, copyErr := io.Copy(hash, io.LimitReader(file, maxOCIArchiveBytes+1))
	if copyErr != nil || count != info.Size() || count > maxOCIArchiveBytes {
		return "", 0, ErrInvalidImageDescriptor
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), count, nil
}
