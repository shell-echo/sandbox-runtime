package phase6security

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestVerifyImageDescriptorDocumentsRejectsDigestKindAndPlatformMixing(t *testing.T) {
	encode := func(value any) []byte {
		t.Helper()
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	platform := "linux/arm64/v8"
	config := encode(map[string]any{"architecture": "arm64", "os": "linux", "variant": "v8",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{testDigest("uncompressed-layer")}}})
	configID := hashImageBytes(config)
	manifest := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configID, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": testDigest("compressed-layer"), "size": 17}}})
	manifestID := hashImageBytes(manifest)
	index := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest": manifestID, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}}}})
	indexID := hashImageBytes(index)
	registry := "registry.example.test/runtime@"
	for _, item := range []struct {
		name, location, kind, reference, digest, selected, configDigest string
		documents                                                       ImageDescriptorDocuments
	}{
		{"local config", "local", ImageIdentityLocalConfig, configID, configID, "", "", ImageDescriptorDocuments{Config: config}},
		{"local index", "local", ImageIdentityOCIIndex, indexID, indexID, manifestID, configID,
			ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: config}},
		{"registry manifest", "registry", ImageIdentityOCIManifest, registry + manifestID, manifestID, "", configID,
			ImageDescriptorDocuments{Manifest: manifest, Config: config}},
		{"registry index", "registry", ImageIdentityOCIIndex, registry + indexID, indexID, manifestID, configID,
			ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: config}},
	} {
		t.Run(item.name, func(t *testing.T) {
			proof, err := VerifyImageDescriptorDocuments(item.location, item.kind, item.reference, item.digest, platform,
				item.selected, item.configDigest, item.documents)
			if err != nil || proof.ConfigDigest != configID ||
				(item.kind == ImageIdentityLocalConfig && proof.ProofDigest != "") ||
				(item.kind != ImageIdentityLocalConfig && !digestPattern.MatchString(proof.ProofDigest)) {
				t.Fatalf("valid descriptor chain = %#v, %v", proof, err)
			}
		})
	}
	for name, mutate := range map[string]func(*ImageDescriptorDocuments, *string, *string, *string, *string, *string){
		"manifest digest as config": func(_ *ImageDescriptorDocuments, _, digest, _, configDigest, _ *string) {
			*configDigest = *digest
		},
		"config bytes substituted": func(d *ImageDescriptorDocuments, _, _, _, _, _ *string) {
			d.Config = append(append([]byte(nil), config...), byte(' '))
		},
		"manifest bytes substituted": func(d *ImageDescriptorDocuments, _, _, _, _, _ *string) {
			d.Manifest = append(append([]byte(nil), manifest...), byte(' '))
		},
		"index bytes substituted": func(d *ImageDescriptorDocuments, _, _, _, _, _ *string) {
			d.Index = append(append([]byte(nil), index...), byte(' '))
		},
		"index with wrong platform": func(_ *ImageDescriptorDocuments, _, _, _, _, platform *string) {
			*platform = "linux/amd64"
		},
		"missing index": func(d *ImageDescriptorDocuments, _, _, _, _, _ *string) { d.Index = nil },
		"tag fallback": func(_ *ImageDescriptorDocuments, reference, _, _, _, _ *string) {
			*reference = "registry.example.test/runtime:latest"
		},
		"wrong selected manifest": func(_ *ImageDescriptorDocuments, _, _, selected, _, _ *string) {
			*selected = testDigest("wrong-manifest")
		},
	} {
		t.Run(name, func(t *testing.T) {
			documents := ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: config}
			reference, digest, selected, configDigest, targetPlatform := registry+indexID, indexID, manifestID, configID, platform
			mutate(&documents, &reference, &digest, &selected, &configDigest, &targetPlatform)
			if _, err := VerifyImageDescriptorDocuments("registry", ImageIdentityOCIIndex, reference, digest, targetPlatform,
				selected, configDigest, documents); !errors.Is(err, ErrInvalidImageDescriptor) {
				t.Fatalf("descriptor substitution accepted: %v", err)
			}
		})
	}
}

func TestARM64DefaultV8NormalizationIsNarrowAndDoesNotRewriteDescriptors(t *testing.T) {
	for _, item := range []struct {
		name, os, architecture, variant, expected string
		want                                      bool
	}{
		{"omitted variant", "linux", "arm64", "", "linux/arm64/v8", true},
		{"explicit v8", "linux", "arm64", "v8", "linux/arm64/v8", true},
		{"explicit v9", "linux", "arm64", "v9", "linux/arm64/v8", false},
		{"wrong OS", "darwin", "arm64", "", "linux/arm64/v8", false},
		{"wrong architecture", "linux", "arm", "v8", "linux/arm64/v8", false},
		{"unknown attestation", "unknown", "unknown", "", "linux/arm64/v8", false},
		{"missing OS", "", "arm64", "", "linux/arm64/v8", false},
		{"amd64 unchanged", "linux", "amd64", "", "linux/amd64", true},
	} {
		t.Run(item.name, func(t *testing.T) {
			if got := sameImagePlatform(item.os, item.architecture, item.variant, item.expected); got != item.want {
				t.Fatalf("platform match = %v, want %v", got, item.want)
			}
		})
	}
	encode := func(value any) []byte {
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	config := encode(map[string]any{"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{testDigest("diff")}}})
	configID := hashImageBytes(config)
	manifest := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configID, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": testDigest("layer"), "size": 17}}})
	manifestID := hashImageBytes(manifest)
	selected := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestID,
		"size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "arm64"}}
	index := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{selected}})
	indexID := hashImageBytes(index)
	documents := ImageDescriptorDocuments{Index: index, Manifest: manifest, Config: config}
	proof, err := VerifyImageDescriptorDocuments("local", ImageIdentityOCIIndex, indexID, indexID,
		"linux/arm64/v8", manifestID, configID, documents)
	if err != nil || proof.ConfigDigest != configID || hashImageBytes(index) != indexID {
		t.Fatalf("omitted-v8 raw descriptor chain = %#v, %v", proof, err)
	}
	for name, extra := range map[string]map[string]any{
		"canonical duplicate": {"os": "linux", "architecture": "arm64", "variant": "v8"},
		"unknown attestation": {"os": "unknown", "architecture": "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			other := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": testDigest("other"),
				"size": 99, "platform": extra}
			changed := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{selected, other}})
			changedID := hashImageBytes(changed)
			_, err := VerifyImageDescriptorDocuments("local", ImageIdentityOCIIndex, changedID, changedID,
				"linux/arm64/v8", manifestID, configID, ImageDescriptorDocuments{Index: changed, Manifest: manifest, Config: config})
			if name == "canonical duplicate" && !errors.Is(err, ErrInvalidImageDescriptor) {
				t.Fatalf("duplicate normalized platform admitted: %v", err)
			}
			if name == "unknown attestation" && err != nil {
				t.Fatalf("non-selected attestation confused selection: %v", err)
			}
			if name == "unknown attestation" {
				_, selectedErr := VerifyImageDescriptorDocuments("local", ImageIdentityOCIIndex, changedID, changedID,
					"linux/arm64/v8", testDigest("other"), configID,
					ImageDescriptorDocuments{Index: changed, Manifest: manifest, Config: config})
				if !errors.Is(selectedErr, ErrInvalidImageDescriptor) {
					t.Fatalf("unknown/unknown attestation selected as ARM64 runtime: %v", selectedErr)
				}
			}
		})
	}
}
