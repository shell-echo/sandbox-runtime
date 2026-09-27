package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var ErrInvalidImageDescriptor = errors.New("invalid Phase 6 image descriptor chain")

// ImageDescriptorDocuments are exact raw descriptor bytes retained by the
// operator gate. A local config needs only Config; a registry manifest needs
// Manifest and Config; an index additionally needs Index. The resulting proof
// digest binds these exact bytes, not a re-marshaled projection.
type ImageDescriptorDocuments struct {
	Index    []byte
	Manifest []byte
	Config   []byte
}

type ImageDescriptorProof struct {
	ConfigDigest string
	ProofDigest  string
}

func VerifyImageDescriptorDocuments(location, kind, reference, digest, platform, selectedManifest, configDigest string,
	documents ImageDescriptorDocuments) (ImageDescriptorProof, error) {
	if !validImageIdentity(location, kind, reference, digest, platform, selectedManifest, configDigest) ||
		len(documents.Config) < 1 || len(documents.Config) > 4<<20 || rejectDuplicateMembers(documents.Config) != nil {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	runtimeID := hashImageBytes(documents.Config)
	diffIDCount, validConfig := validOCIConfig(documents.Config, platform)
	expectedConfig := configDigest
	if kind == ImageIdentityLocalConfig {
		expectedConfig = digest
	}
	if runtimeID != expectedConfig || !validConfig {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	if kind == ImageIdentityLocalConfig {
		if len(documents.Index) != 0 || len(documents.Manifest) != 0 {
			return ImageDescriptorProof{}, ErrInvalidImageDescriptor
		}
		return ImageDescriptorProof{ConfigDigest: runtimeID}, nil
	}
	if len(documents.Manifest) < 1 || len(documents.Manifest) > 4<<20 ||
		rejectDuplicateMembers(documents.Manifest) != nil ||
		hashImageBytes(documents.Manifest) != selectedImageManifest(kind, digest, selectedManifest) ||
		!validOCIManifest(documents.Manifest, runtimeID, len(documents.Config), diffIDCount) {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	if kind == ImageIdentityOCIIndex {
		if len(documents.Index) < 1 || len(documents.Index) > 4<<20 || rejectDuplicateMembers(documents.Index) != nil ||
			hashImageBytes(documents.Index) != digest || !validOCIIndex(documents.Index, platform, selectedManifest, len(documents.Manifest)) {
			return ImageDescriptorProof{}, ErrInvalidImageDescriptor
		}
	} else if len(documents.Index) != 0 {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("sandbox-runtime/phase6-image-descriptor-proof/v1\x00"))
	for _, document := range [][]byte{documents.Index, documents.Manifest, documents.Config} {
		_, _ = hash.Write([]byte{byte(len(document) >> 24), byte(len(document) >> 16), byte(len(document) >> 8), byte(len(document))})
		_, _ = hash.Write(document)
	}
	return ImageDescriptorProof{ConfigDigest: runtimeID, ProofDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil))}, nil
}

func selectedImageManifest(kind, digest, selectedManifest string) string {
	if kind == ImageIdentityOCIIndex {
		return selectedManifest
	}
	return digest
}

func hashImageBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func decodeImageJSON(document []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if decoder.Decode(target) != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func validOCIConfig(document []byte, platform string) (int, bool) {
	var config struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Variant      string `json:"variant"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if !decodeImageJSON(document, &config) ||
		!sameImagePlatform(config.OS, config.Architecture, config.Variant, platform) ||
		config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) < 1 || len(config.RootFS.DiffIDs) > 512 {
		return 0, false
	}
	for _, digest := range config.RootFS.DiffIDs {
		if !digestPattern.MatchString(digest) {
			return 0, false
		}
	}
	return len(config.RootFS.DiffIDs), true
}

func sameImagePlatform(osName, architecture, variant, expected string) bool {
	// OCI permits the baseline ARM64 variant to be omitted. For this
	// repository's sole ARM64 profile, omitted and explicit v8 are the same
	// normalized platform. Never infer OS/architecture or admit another ARM
	// variant; descriptor bytes and digests remain untouched.
	if expected == "linux/arm64/v8" {
		return osName == "linux" && architecture == "arm64" && (variant == "" || variant == "v8")
	}
	value := osName + "/" + architecture
	if variant != "" {
		value += "/" + variant
	}
	return value == expected
}

func validOCIManifest(document []byte, configDigest string, configSize, diffIDCount int) bool {
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Config        struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"config"`
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if !decodeImageJSON(document, &manifest) || manifest.SchemaVersion != 2 ||
		!oneOf(manifest.MediaType, "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json") ||
		!oneOf(manifest.Config.MediaType, "application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json") ||
		manifest.Config.Digest != configDigest || manifest.Config.Size != int64(configSize) ||
		len(manifest.Layers) < 1 || len(manifest.Layers) > 512 || len(manifest.Layers) != diffIDCount {
		return false
	}
	for _, layer := range manifest.Layers {
		if !strings.HasPrefix(layer.MediaType, "application/vnd.oci.image.layer.v1") &&
			!strings.HasPrefix(layer.MediaType, "application/vnd.docker.image.rootfs.diff.tar") {
			return false
		}
		if !digestPattern.MatchString(layer.Digest) || layer.Size < 1 {
			return false
		}
	}
	return true
}

func validOCIIndex(document []byte, platform, selectedManifest string, selectedSize int) bool {
	var index struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			Platform  struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if !decodeImageJSON(document, &index) || index.SchemaVersion != 2 ||
		!oneOf(index.MediaType, "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json") ||
		len(index.Manifests) < 1 || len(index.Manifests) > 128 {
		return false
	}
	selected, matchingPlatform := 0, 0
	for _, descriptor := range index.Manifests {
		if !oneOf(descriptor.MediaType, "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json") ||
			!digestPattern.MatchString(descriptor.Digest) || descriptor.Size < 1 {
			return false
		}
		if sameImagePlatform(descriptor.Platform.OS, descriptor.Platform.Architecture, descriptor.Platform.Variant, platform) {
			matchingPlatform++
			if descriptor.Digest == selectedManifest && descriptor.Size == int64(selectedSize) {
				selected++
			}
		}
	}
	return selected == 1 && matchingPlatform == 1
}

func oneOf(value string, accepted ...string) bool {
	for _, item := range accepted {
		if value == item {
			return true
		}
	}
	return false
}
