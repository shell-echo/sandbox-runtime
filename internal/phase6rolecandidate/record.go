package phase6rolecandidate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrRecordCandidate = errors.New("cannot record Phase 6 local role candidate")

// RecordInput selects an already-built, local digest-addressed image. The
// caller must create a private output directory outside the source tree. The
// recorder never builds, pulls, publishes, signs or prunes an image.
type RecordInput struct {
	SourceRoot string
	Deployment string
	Platform   string
	ImageID    string
	OutputPath string
}

// Record observes one stopped run-owned Docker container, retains its exact
// archive and creates an exclusive private manifest only after cleanup.
func Record(ctx context.Context, input RecordInput) (result Manifest, err error) {
	if ctx == nil || ctx.Err() != nil || !validPrivateManifestPath(input.OutputPath) ||
		!filepath.IsAbs(input.SourceRoot) || filepath.Clean(input.SourceRoot) != input.SourceRoot ||
		!isOutsideSource(input.SourceRoot, input.OutputPath) || !validDigest(input.ImageID) {
		return Manifest{}, recordStage("input")
	}
	for _, path := range []string{input.OutputPath, input.OutputPath + ".oci.tar"} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			return Manifest{}, recordStage("output-exists")
		}
	}
	source, err := CollectSourceInputs(ctx, input.SourceRoot, input.Deployment, input.Platform)
	if err != nil {
		return Manifest{}, recordStage("source")
	}
	imageInspect, err := dockerRecordOutput(ctx, "image", "inspect", input.ImageID)
	if err != nil {
		return Manifest{}, recordStage("image-inspect")
	}
	var images []struct {
		ID         string `json:"Id"`
		Descriptor *struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"Descriptor"`
	}
	if json.Unmarshal(imageInspect, &images) != nil || len(images) != 1 ||
		images[0].ID != input.ImageID || images[0].Descriptor == nil ||
		images[0].Descriptor.Digest != input.ImageID {
		return Manifest{}, recordStage("image-identity")
	}
	kind := phase6security.ImageIdentityOCIManifest
	if validRoleDescriptorType(phase6security.ImageIdentityOCIIndex, images[0].Descriptor.MediaType) {
		kind = phase6security.ImageIdentityOCIIndex
	} else if !validRoleDescriptorType(kind, images[0].Descriptor.MediaType) {
		return Manifest{}, recordStage("image-descriptor")
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Manifest{}, recordStage("observation-identity")
	}
	containerName := "sr-p6-role-observe-" + hex.EncodeToString(random[:])
	created, err := dockerRecordOutput(ctx, "create", "--pull=never", "--network", "none",
		"--name", containerName, input.ImageID)
	if err != nil {
		return Manifest{}, recordStage("observation-create")
	}
	containerID := strings.TrimSpace(string(created))
	if len(containerID) != 64 || !lowerHex(containerID) {
		_ = removeExactObservationContainer(containerName)
		return Manifest{}, recordStage("observation-id")
	}
	defer func() {
		if containerID == "" {
			return
		}
		if cleanupErr := removeExactObservationContainer(containerID); cleanupErr != nil {
			result, err = Manifest{}, recordStage("observation-cleanup")
		}
	}()
	containerInspect, err := dockerRecordOutput(ctx, "inspect", containerID)
	if err != nil {
		return Manifest{}, recordStage("observation-inspect")
	}
	var containers []struct {
		ID       string `json:"Id"`
		Image    string `json:"Image"`
		Selected *struct {
			Digest string `json:"digest"`
		} `json:"ImageManifestDescriptor"`
	}
	if json.Unmarshal(containerInspect, &containers) != nil || len(containers) != 1 ||
		containers[0].ID != containerID || containers[0].Image != input.ImageID ||
		containers[0].Selected == nil || !validDigest(containers[0].Selected.Digest) {
		return Manifest{}, recordStage("observation-descriptor")
	}
	selected := containers[0].Selected.Digest
	if kind == phase6security.ImageIdentityOCIManifest && selected != input.ImageID {
		return Manifest{}, recordStage("observation-manifest")
	}
	archive, err := os.CreateTemp(filepath.Dir(input.OutputPath), ".phase6-role-candidate-*.oci.tar")
	if err != nil {
		return Manifest{}, recordStage("archive-create")
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)
	if archive.Close() != nil || os.Chmod(archivePath, 0o600) != nil {
		return Manifest{}, recordStage("archive-private")
	}
	command := exec.CommandContext(ctx, "docker", "image", "save", "-o", archivePath, input.ImageID)
	if command.Run() != nil || os.Chmod(archivePath, 0o600) != nil {
		return Manifest{}, recordStage("archive-save")
	}
	documents, err := phase6security.ReadOCIArchiveDocuments(archivePath, kind, input.ImageID, selected, "")
	if err != nil {
		return Manifest{}, recordStage("archive-documents")
	}
	var selectedManifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if json.Unmarshal(documents.Manifest, &selectedManifest) != nil ||
		!validDigest(selectedManifest.Config.Digest) {
		return Manifest{}, recordStage("archive-config-descriptor")
	}
	principal := phase6security.Principal{Name: input.Deployment, ImageLocation: "local",
		ImageReference: input.ImageID, ImageDigest: input.ImageID, ImageIdentityKind: kind,
		ImagePlatform: input.Platform, ImageConfigDigest: selectedManifest.Config.Digest}
	if kind == phase6security.ImageIdentityOCIIndex {
		principal.ImageSelectedManifestDigest = selected
	}
	probe, err := phase6security.VerifySlice6LocalRoleCandidateProbe(principal, source.SourceRevision,
		containerInspect, imageInspect, archivePath)
	if err != nil {
		return Manifest{}, recordStage("candidate-probe")
	}
	documents, err = phase6security.ReadOCIArchiveDocuments(archivePath, kind,
		input.ImageID, selected, principal.ImageConfigDigest)
	if err != nil {
		return Manifest{}, recordStage("archive-reopen")
	}
	build, err := VerifyBuildContext(ctx, input.SourceRoot, source, archivePath,
		documents.Manifest, documents.Config)
	if err != nil {
		return Manifest{}, recordStage("build-context")
	}
	manifest, err := NewManifest(ctx, input.SourceRoot, archivePath, source, principal, probe, build)
	if err != nil {
		return Manifest{}, recordStage("manifest-verify")
	}
	if removeExactObservationContainer(containerID) != nil {
		return Manifest{}, recordStage("observation-cleanup")
	}
	containerID = ""
	retainedArchive := input.OutputPath + ".oci.tar"
	if os.Link(archivePath, retainedArchive) != nil {
		return Manifest{}, recordStage("archive-retain")
	}
	if manifest.WritePrivate(input.OutputPath) != nil {
		_ = os.Remove(retainedArchive)
		return Manifest{}, recordStage("manifest-write")
	}
	return manifest, nil
}

func recordStage(stage string) error {
	return fmt.Errorf("%w: stage %s", ErrRecordCandidate, stage)
}

func isOutsideSource(root, output string) bool {
	relative, err := filepath.Rel(root, output)
	return err == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	return lowerHex(strings.TrimPrefix(value, "sha256:"))
}

func dockerRecordOutput(ctx context.Context, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	pipe, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return nil, ErrRecordCandidate
	}
	document, readErr := io.ReadAll(io.LimitReader(pipe, 2<<20+1))
	if readErr != nil || len(document) > 2<<20 {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, ErrRecordCandidate
	}
	if command.Wait() != nil {
		return nil, ErrRecordCandidate
	}
	return document, nil
}

func removeExactObservationContainer(id string) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := dockerRecordOutput(cleanup, "rm", "-f", id); err != nil {
		return fmt.Errorf("%w: owned container cleanup", ErrRecordCandidate)
	}
	if _, err := dockerRecordOutput(cleanup, "inspect", id); err == nil {
		return fmt.Errorf("%w: owned container remained", ErrRecordCandidate)
	}
	if _, err := dockerRecordOutput(cleanup, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: daemon unavailable during cleanup proof", ErrRecordCandidate)
	}
	return nil
}
