package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// DockerImageObservation projects independently read container/image inspect
// receipts and an independently verified raw descriptor chain. A Docker store
// ID is not assumed to be an OCI config digest.
type DockerImageObservation struct {
	ContainerID                string          `json:"container_id"`
	ImageReference             string          `json:"image_reference"`
	RuntimeStoreImageID        string          `json:"runtime_store_image_id"`
	RuntimeStoreDescriptor     ImageDescriptor `json:"runtime_store_descriptor"`
	SelectedManifestDescriptor ImageDescriptor `json:"selected_manifest_descriptor"`
	OCIConfigDigest            string          `json:"oci_config_digest"`
	RuntimePlatform            string          `json:"runtime_platform"`
	DescriptorProofDigest      string          `json:"descriptor_proof_digest"`
	ContainerInspectDigest     string          `json:"container_inspect_digest"`
	ImageInspectDigest         string          `json:"image_inspect_digest"`
}

func ObserveDockerRuntimeImage(containerDocument, imageDocument []byte,
	location, kind, reference, digest, platform, selectedManifest, configDigest string,
	documents ImageDescriptorDocuments) (DockerImageObservation, error) {
	proof, proofErr := VerifyImageDescriptorDocuments(location, kind, reference, digest, platform, selectedManifest, configDigest, documents)
	if proofErr != nil ||
		len(containerDocument) < 1 || len(containerDocument) > maxBytes ||
		len(imageDocument) < 1 || len(imageDocument) > maxBytes ||
		rejectDuplicateMembers(containerDocument) != nil || rejectDuplicateMembers(imageDocument) != nil {
		return DockerImageObservation{}, ErrInvalidObservation
	}
	var containers []struct {
		ID                      string                 `json:"Id"`
		Image                   string                 `json:"Image"`
		ImageManifestDescriptor *dockerImageDescriptor `json:"ImageManifestDescriptor"`
		Config                  struct {
			Image string `json:"Image"`
		} `json:"Config"`
	}
	var images []struct {
		ID           string                 `json:"Id"`
		OS           string                 `json:"Os"`
		Architecture string                 `json:"Architecture"`
		Variant      string                 `json:"Variant"`
		Descriptor   *dockerImageDescriptor `json:"Descriptor"`
		RootFS       struct {
			Layers []string `json:"Layers"`
		} `json:"RootFS"`
	}
	if !decodeDockerInspectArray(containerDocument, &containers) || !decodeDockerInspectArray(imageDocument, &images) ||
		len(containers) != 1 || len(images) != 1 || !containerIDPattern.MatchString(containers[0].ID) ||
		containers[0].Config.Image != reference || containers[0].Image != images[0].ID ||
		images[0].ID != digest || !sameImagePlatform(images[0].OS, images[0].Architecture, images[0].Variant, platform) ||
		!sameRootFSDiffIDs(documents.Config, images[0].RootFS.Layers) {
		return DockerImageObservation{}, ErrInvalidObservation
	}
	storeDescriptor, selectedDescriptor := ImageDescriptor{}, ImageDescriptor{}
	if kind == ImageIdentityLocalConfig {
		if images[0].Descriptor != nil || containers[0].ImageManifestDescriptor != nil {
			return DockerImageObservation{}, ErrInvalidObservation
		}
	} else {
		if images[0].Descriptor == nil || containers[0].ImageManifestDescriptor == nil ||
			!sameImagePlatform(containers[0].ImageManifestDescriptor.Platform.OS,
				containers[0].ImageManifestDescriptor.Platform.Architecture,
				containers[0].ImageManifestDescriptor.Platform.Variant, platform) {
			return DockerImageObservation{}, ErrInvalidObservation
		}
		storeDescriptor = images[0].Descriptor.project()
		selectedDescriptor = containers[0].ImageManifestDescriptor.project()
		expectedSelected := selectedImageManifest(kind, digest, selectedManifest)
		if storeDescriptor.Digest != digest || storeDescriptor.Size != int64(len(descriptorTopDocument(kind, documents))) ||
			!validStoreDescriptorMediaType(kind, storeDescriptor.MediaType) ||
			selectedDescriptor.Digest != expectedSelected || selectedDescriptor.Size != int64(len(documents.Manifest)) ||
			!validStoreDescriptorMediaType(ImageIdentityOCIManifest, selectedDescriptor.MediaType) {
			return DockerImageObservation{}, ErrInvalidObservation
		}
	}
	containerHash := sha256.Sum256(containerDocument)
	imageHash := sha256.Sum256(imageDocument)
	return DockerImageObservation{ContainerID: containers[0].ID, ImageReference: containers[0].Config.Image,
		RuntimeStoreImageID: images[0].ID, RuntimeStoreDescriptor: storeDescriptor,
		SelectedManifestDescriptor: selectedDescriptor, OCIConfigDigest: proof.ConfigDigest,
		RuntimePlatform: platform, DescriptorProofDigest: proof.ProofDigest,
		ContainerInspectDigest: "sha256:" + hex.EncodeToString(containerHash[:]),
		ImageInspectDigest:     "sha256:" + hex.EncodeToString(imageHash[:])}, nil
}

type dockerImageDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

func (d dockerImageDescriptor) project() ImageDescriptor {
	return ImageDescriptor{MediaType: d.MediaType, Digest: d.Digest, Size: d.Size}
}

func descriptorTopDocument(kind string, documents ImageDescriptorDocuments) []byte {
	if kind == ImageIdentityOCIIndex {
		return documents.Index
	}
	return documents.Manifest
}

func validStoreDescriptorMediaType(kind, mediaType string) bool {
	if kind == ImageIdentityOCIIndex {
		return oneOf(mediaType, "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
	}
	return oneOf(mediaType, "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
}

func sameRootFSDiffIDs(configDocument []byte, observed []string) bool {
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if !decodeImageJSON(configDocument, &config) || len(config.RootFS.DiffIDs) != len(observed) {
		return false
	}
	for index, digest := range observed {
		if digest != config.RootFS.DiffIDs[index] {
			return false
		}
	}
	return true
}

func decodeDockerInspectArray[T any](document []byte, target *[]T) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if decoder.Decode(target) != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}
