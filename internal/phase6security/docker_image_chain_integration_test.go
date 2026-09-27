//go:build integration

package phase6security

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is a real Docker image-store component gate, not the full Slice 6
// role/inventory gate. It asserts the selected platform manifest rather than
// assuming Docker's .Image/.Id is the OCI config digest.
func TestDockerRuntimeImageSelectedManifestAndOCIConfig(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_IMAGE_ID_DOCKER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_IMAGE_ID_DOCKER=1")
	}
	const image = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := dockerTopology(ctx, "image", "inspect", image); err != nil {
		t.Fatalf("pinned Docker image unavailable: %v", err)
	}
	name := fmt.Sprintf("p6-selected-manifest-%d", time.Now().UnixNano())
	if _, err := dockerTopology(ctx, "create", "--pull=never", "--name", name, "--network", "none", image, "sleep", "1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if _, err := dockerTopology(cleanupCtx, "rm", "-f", name); err != nil {
			t.Errorf("remove exact image-observation container: %v", err)
		}
		if _, err := dockerTopology(cleanupCtx, "inspect", name); err == nil {
			t.Error("image-observation container remained after cleanup")
		}
	})
	containerRaw, err := dockerTopology(ctx, "inspect", name)
	if err != nil {
		t.Fatal(err)
	}
	imageRaw, err := dockerTopology(ctx, "image", "inspect", image)
	if err != nil {
		t.Fatal(err)
	}
	var containers []struct {
		ImageManifestDescriptor dockerImageDescriptor `json:"ImageManifestDescriptor"`
	}
	var images []struct {
		Descriptor dockerImageDescriptor `json:"Descriptor"`
	}
	if json.Unmarshal([]byte(containerRaw), &containers) != nil || len(containers) != 1 ||
		json.Unmarshal([]byte(imageRaw), &images) != nil || len(images) != 1 {
		t.Fatal("real Docker inspect has no exact descriptor pair")
	}
	selected, store := containers[0].ImageManifestDescriptor, images[0].Descriptor
	if !digestPattern.MatchString(store.Digest) || !digestPattern.MatchString(selected.Digest) ||
		store.Digest == selected.Digest {
		t.Fatalf("expected an observed multi-platform index and distinct selected manifest: %#v %#v", store, selected)
	}
	archive := filepath.Join(t.TempDir(), "image.tar")
	command := exec.CommandContext(ctx, "docker", "image", "save", "-o", archive, image)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("save exact Docker image OCI archive: %v: %.2048s", err, output)
	}
	index, err := readOCIArchiveBlob(archive, store.Digest)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readOCIArchiveBlob(archive, selected.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var manifestDocument struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if json.Unmarshal(manifest, &manifestDocument) != nil || !digestPattern.MatchString(manifestDocument.Config.Digest) {
		t.Fatal("selected manifest omitted config digest")
	}
	config, err := readOCIArchiveBlob(archive, manifestDocument.Config.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOCIArchiveLayers(archive, manifest, config); err != nil {
		t.Fatalf("real Docker archive layer/config chain: %v", err)
	}
	platform := selected.Platform.OS + "/" + selected.Platform.Architecture
	if selected.Platform.Variant != "" {
		platform += "/" + selected.Platform.Variant
	}
	documents := ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: config}
	observed, err := ObserveDockerRuntimeImage([]byte(containerRaw), []byte(imageRaw), "registry", ImageIdentityOCIIndex,
		image, store.Digest, platform, selected.Digest, manifestDocument.Config.Digest, documents)
	if err != nil || observed.RuntimeStoreImageID != store.Digest ||
		observed.OCIConfigDigest != manifestDocument.Config.Digest ||
		observed.SelectedManifestDescriptor.Digest != selected.Digest ||
		!digestPattern.MatchString(observed.DescriptorProofDigest) {
		t.Fatalf("real Docker index/selected manifest/config chain rejected: %#v, %v", observed, err)
	}
	t.Logf("real Docker store index %s selected manifest %s OCI config %s; exact temporary container/archive cleanup", store.Digest, selected.Digest, observed.OCIConfigDigest)
}

// This checks the real cached Desktop candidate's current Docker store shape.
// It does not create a new source-bound v2 candidate or rerun its media gate.
func TestDockerDesktopCandidateStoreManifestAndConfig(t *testing.T) {
	image := os.Getenv("SANDBOX_RUNTIME_PHASE6_DESKTOP_CANDIDATE_IMAGE")
	if image == "" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_DESKTOP_CANDIDATE_IMAGE to a retained local Desktop image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	initialRaw, err := dockerTopology(ctx, "image", "inspect", image)
	if err != nil {
		t.Fatal(err)
	}
	var initial []struct {
		ID         string                `json:"Id"`
		Descriptor dockerImageDescriptor `json:"Descriptor"`
	}
	if json.Unmarshal([]byte(initialRaw), &initial) != nil || len(initial) != 1 || initial[0].ID != initial[0].Descriptor.Digest ||
		!digestPattern.MatchString(initial[0].ID) || initial[0].Descriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" {
		t.Fatal("cached Desktop image is not an exact local OCI manifest store object")
	}
	reference := initial[0].ID
	name := fmt.Sprintf("p6-desktop-manifest-%d", time.Now().UnixNano())
	id, err := dockerTopology(ctx, "create", "--pull=never", "--name", name, "--network", "none", reference)
	if err != nil {
		t.Fatal(err)
	}
	id = strings.TrimSpace(id)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if _, err := dockerTopology(cleanup, "rm", "-f", id); err != nil {
			t.Errorf("remove exact Desktop observation container: %v", err)
		}
		if _, err := dockerTopology(cleanup, "inspect", id); err == nil {
			t.Error("Desktop observation container remained")
		}
	})
	containerRaw, err := dockerTopology(ctx, "inspect", id)
	if err != nil {
		t.Fatal(err)
	}
	imageRaw, err := dockerTopology(ctx, "image", "inspect", reference)
	if err != nil {
		t.Fatal(err)
	}
	var containers []struct {
		ImageManifestDescriptor dockerImageDescriptor `json:"ImageManifestDescriptor"`
	}
	if json.Unmarshal([]byte(containerRaw), &containers) != nil || len(containers) != 1 || containers[0].ImageManifestDescriptor.Digest != reference {
		t.Fatal("Desktop container selected a different manifest")
	}
	archive := filepath.Join(t.TempDir(), "desktop.tar")
	command := exec.CommandContext(ctx, "docker", "image", "save", "-o", archive, reference)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("save Desktop OCI archive: %v: %.512s", err, output)
	}
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := readOCIArchiveBlob(archive, reference)
	if err != nil {
		t.Fatal(err)
	}
	var selected struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if json.Unmarshal(manifest, &selected) != nil || !digestPattern.MatchString(selected.Config.Digest) || selected.Config.Digest == reference {
		t.Fatal("Desktop store descriptor was incorrectly used as config digest")
	}
	documents, err := ReadOCIArchiveDocuments(archive, ImageIdentityOCIManifest, reference, reference, selected.Config.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOCIArchiveLayers(archive, documents.Manifest, documents.Config); err != nil {
		t.Fatal(err)
	}
	observed, err := ObserveDockerRuntimeImage([]byte(containerRaw), []byte(imageRaw), "local", ImageIdentityOCIManifest,
		reference, reference, "linux/arm64/v8", "", selected.Config.Digest, documents)
	if err != nil || observed.OCIConfigDigest != selected.Config.Digest || observed.RuntimeStoreImageID != reference {
		t.Fatalf("Desktop runtime/store/config observation = %#v, %v", observed, err)
	}
	t.Logf("real cached Desktop store manifest %s, selected manifest %s, OCI config %s", reference, observed.SelectedManifestDescriptor.Digest, observed.OCIConfigDigest)
}

func readOCIArchiveBlob(path, digest string) ([]byte, error) {
	if !digestPattern.MatchString(digest) {
		return nil, ErrInvalidImageDescriptor
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidImageDescriptor
	}
	defer file.Close()
	wanted := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil, ErrInvalidImageDescriptor
		}
		if err != nil || filepath.IsAbs(header.Name) || strings.HasPrefix(header.Name, "../") ||
			filepath.Clean(header.Name) != strings.TrimSuffix(header.Name, "/") {
			return nil, ErrInvalidImageDescriptor
		}
		if header.Name != wanted {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, ErrInvalidImageDescriptor
		}
		if header.Size < 1 || header.Size > 4<<20 {
			return nil, ErrInvalidImageDescriptor
		}
		document, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(document)) != header.Size || hashImageBytes(document) != digest {
			return nil, ErrInvalidImageDescriptor
		}
		return document, nil
	}
}
