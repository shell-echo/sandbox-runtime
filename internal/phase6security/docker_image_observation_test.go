package phase6security

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestObserveDockerRuntimeImageBindsSelectedManifestNotStoreIDAsConfig(t *testing.T) {
	encode := func(value any) []byte { document, _ := json.Marshal(value); return document }
	containerID := testDigest("container")[7:]
	platform := "linux/arm64/v8"
	diffID := testDigest("diffid")
	config := encode(map[string]any{"architecture": "arm64", "os": "linux", "variant": "v8",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{diffID}}})
	configID := hashImageBytes(config)
	manifest := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configID, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": testDigest("layer"), "size": 12}}})
	manifestID := hashImageBytes(manifest)
	index := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestID, "size": len(manifest),
				"platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}},
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": testDigest("attestation"), "size": 99,
				"platform": map[string]any{"os": "unknown", "architecture": "unknown"}},
		}})
	indexID := hashImageBytes(index)
	store := map[string]any{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": indexID, "size": len(index)}
	selected := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestID, "size": len(manifest),
		"platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}}
	container := func(reference, storeID string, selectedManifest any) []byte {
		return encode([]any{map[string]any{"Id": containerID, "Image": storeID,
			"ImageManifestDescriptor": selectedManifest, "Config": map[string]any{"Image": reference}}})
	}
	image := func(storeID string, descriptor any, roots []string) []byte {
		return encode([]any{map[string]any{"Id": storeID, "Os": "linux", "Architecture": "arm64", "Variant": "v8",
			"Descriptor": descriptor, "RootFS": map[string]any{"Layers": roots}}})
	}
	documents := ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: config}
	validContainer, validImage := container(indexID, indexID, selected), image(indexID, store, []string{diffID})
	observed, err := ObserveDockerRuntimeImage(validContainer, validImage, "local", ImageIdentityOCIIndex,
		indexID, indexID, platform, manifestID, configID, documents)
	if err != nil || observed.RuntimeStoreImageID != indexID || observed.OCIConfigDigest != configID ||
		observed.SelectedManifestDescriptor.Digest != manifestID || !digestPattern.MatchString(observed.DescriptorProofDigest) {
		t.Fatalf("real store descriptor chain projection = %#v, %v", observed, err)
	}
	wrongSelected := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": testDigest("attestation"),
		"size": 99, "platform": map[string]any{"os": "unknown", "architecture": "unknown"}}
	for name, candidate := range map[string][2][]byte{
		"actual selected manifest wrong": {container(indexID, indexID, wrongSelected), validImage},
		"selected descriptor absent":     {container(indexID, indexID, nil), validImage},
		"wrong store image ID":           {container(indexID, configID, selected), validImage},
		"wrong launch reference":         {container("runtime:latest", indexID, selected), validImage},
		"wrong image descriptor":         {validContainer, image(indexID, map[string]any{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": configID, "size": len(index)}, []string{diffID})},
		"rootfs diffid drift":            {validContainer, image(indexID, store, []string{testDigest("other")})},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ObserveDockerRuntimeImage(candidate[0], candidate[1], "local", ImageIdentityOCIIndex,
				indexID, indexID, platform, manifestID, configID, documents); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("store/manifest/config substitution accepted: %v", err)
			}
		})
	}
	if _, err := ObserveDockerRuntimeImage(validContainer, validImage, "local", ImageIdentityLocalConfig,
		indexID, indexID, platform, "", "", ImageDescriptorDocuments{Config: config}); !errors.Is(err, ErrInvalidObservation) {
		t.Fatal("containerd index silently treated as classic config")
	}
}
