package desktopcandidate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestCandidateBindsCurrentSourceAndRoundTripsCanonically(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	candidate, err := New(root, "linux/arm64/v8", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.VerifySource(root); err != nil {
		t.Fatal(err)
	}
	committedDigest, err := SourceTreeDigestAtRevision(root, candidate.SourceRevision)
	if err != nil {
		t.Fatal(err)
	}
	// A dirty working tree is intentionally distinct from the immutable
	// revision, but a clean checkout must reproduce the same digest.
	if status, statusErr := gitOutput(root, "status", "--porcelain"); statusErr == nil && status == "" && committedDigest != candidate.SourceTreeDigest {
		t.Fatalf("committed tree digest = %s, working tree digest = %s", committedDigest, candidate.SourceTreeDigest)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "candidate.json")
	if err := Save(path, candidate); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded != candidate {
		t.Fatalf("loaded candidate differs: err=%v", err)
	}
	loaded.Classification = "production"
	if !errors.Is(loaded.Validate(), ErrInvalidCandidate) {
		t.Fatal("candidate was promoted to production classification")
	}
}

func TestCandidateRejectsUnknownDuplicateAndBroadFiles(t *testing.T) {
	for name, document := range map[string]string{
		"unknown":   `{"schema_version":"x","unknown":true}`,
		"duplicate": `{"schema_version":"x","schema_version":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "candidate.json")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); !errors.Is(err, ErrInvalidCandidate) {
				t.Fatalf("unsafe document error = %v", err)
			}
		})
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("broad candidate error = %v", err)
	}
}

func TestCurrentCandidateSeparatesStoreManifestAndConfigAndRejectsLegacy(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "candidate.json.oci.tar")
	config, manifest, archive := currentCandidateArchive(t, archivePath)
	configDigest, manifestDigest, archiveDigest := testHash(config), testHash(manifest), testHash(archive)
	proof, err := phase6security.VerifyImageDescriptorDocuments("local", phase6security.ImageIdentityOCIManifest,
		manifestDigest, manifestDigest, "linux/amd64", "", configDigest,
		phase6security.ImageDescriptorDocuments{Manifest: manifest, Config: config})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewCurrent(root, "linux/amd64", CurrentIdentity{
		Accounts:     validAccounts(),
		Kind:         phase6security.ImageIdentityOCIManifest,
		Store:        phase6security.ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: manifestDigest, Size: int64(len(manifest))},
		Selected:     phase6security.ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: manifestDigest, Size: int64(len(manifest))},
		ConfigDigest: configDigest, DescriptorProofDigest: proof.ProofDigest,
		ArchiveDigest: archiveDigest, ArchiveSize: int64(len(archive)),
	})
	if err != nil || candidate.VerifyArchive(archivePath) != nil || candidate.ImageDigest == candidate.ConfigDigest {
		t.Fatalf("current candidate descriptor/config separation failed: %v", err)
	}
	if candidate.Version != CurrentVersion || candidate.WorkloadAccountCount != 2 {
		t.Fatalf("candidate account schema = %d, count = %d", candidate.Version, candidate.WorkloadAccountCount)
	}
	wrongAccounts := candidate
	wrongAccounts.WorkloadAccountDigest = testHash([]byte("different-accounts"))
	wrongAccounts.BuildArgumentsDigest = wrongAccounts.calculateBuildArgumentsDigest()
	wrongAccounts.ManifestDigest = wrongAccounts.calculateManifestDigest()
	if wrongAccounts.ValidateCurrent() == nil {
		t.Fatal("candidate accepted a substituted account digest")
	}
	wrongAccounts = candidate
	wrongAccounts.WorkloadAccounts += "\n"
	wrongAccounts.ManifestDigest = wrongAccounts.calculateManifestDigest()
	if wrongAccounts.ValidateCurrent() == nil {
		t.Fatal("candidate accepted a noncanonical account list")
	}
	manifestPath := strings.TrimSuffix(archivePath, ".oci.tar")
	if err := Save(manifestPath, candidate); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadCurrent(manifestPath); err != nil || loaded != candidate {
		t.Fatalf("current candidate load = %v", err)
	}
	legacy, err := New(root, "linux/amd64", manifestDigest, manifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ValidateCurrent() == nil {
		t.Fatal("legacy v1 admitted as current candidate")
	}
	if err := Save(manifestPath, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCurrent(manifestPath); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("legacy current admission = %v", err)
	}
	wrongConfig := candidate
	wrongConfig.ConfigDigest = wrongConfig.ImageDigest
	wrongConfig.ManifestDigest = wrongConfig.calculateManifestDigest()
	if wrongConfig.ValidateCurrent() == nil {
		t.Fatal("store manifest digest admitted as OCI config")
	}
	wrongSelected := candidate
	wrongSelected.SelectedManifestDigest = testHash([]byte("wrong-selected"))
	wrongSelected.ManifestDigest = wrongSelected.calculateManifestDigest()
	if wrongSelected.ValidateCurrent() == nil {
		t.Fatal("selected manifest mismatch admitted")
	}
	if err := os.WriteFile(archivePath, append([]byte(nil), archive[:len(archive)-1]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if candidate.VerifyArchive(archivePath) == nil {
		t.Fatal("altered raw archive admitted")
	}
}

func TestCurrentCandidateRejectsNSSMismatchDespiteMatchingLabelAndOCIHashes(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	passwdFragment, groupFragment, err := validAccounts().NSSFragments()
	if err != nil {
		t.Fatal(err)
	}
	basePasswd := []byte("root:x:0:0:root:/root:/bin/sh\ndesktop:x:1000:1000::/tmp/desktop-home:/bin/sh\n")
	baseGroup := []byte("root:x:0:\ndesktop:x:1000:\n")
	for name, mutate := range map[string]func() ([]byte, []byte){
		"missing account": func() ([]byte, []byte) {
			return append(bytes.Clone(basePasswd), passwdFragment[:bytes.IndexByte(passwdFragment, '\n')+1]...), append(bytes.Clone(baseGroup), groupFragment...)
		},
		"unexpected high uid": func() ([]byte, []byte) {
			return append(append(bytes.Clone(basePasswd), passwdFragment...), []byte("extra:x:45000:45000::/tmp:/sbin/nologin\n")...), append(bytes.Clone(baseGroup), groupFragment...)
		},
		"wrong group": func() ([]byte, []byte) {
			return append(bytes.Clone(basePasswd), passwdFragment...), append(bytes.Clone(baseGroup), []byte("desktop-slot-30000:x:30001:\n")...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "candidate.json.oci.tar")
			passwd, group := mutate()
			config, manifest, archive := currentCandidateArchiveWithNSS(t, archivePath, passwd, group)
			configDigest, manifestDigest := testHash(config), testHash(manifest)
			proof, err := phase6security.VerifyImageDescriptorDocuments("local", phase6security.ImageIdentityOCIManifest,
				manifestDigest, manifestDigest, "linux/amd64", "", configDigest,
				phase6security.ImageDescriptorDocuments{Manifest: manifest, Config: config})
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := NewCurrent(root, "linux/amd64", CurrentIdentity{
				Accounts: validAccounts(), Kind: phase6security.ImageIdentityOCIManifest,
				Store:        phase6security.ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: manifestDigest, Size: int64(len(manifest))},
				Selected:     phase6security.ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: manifestDigest, Size: int64(len(manifest))},
				ConfigDigest: configDigest, DescriptorProofDigest: proof.ProofDigest,
				ArchiveDigest: testHash(archive), ArchiveSize: int64(len(archive)),
			})
			if err != nil {
				t.Fatal(err)
			}
			if candidate.VerifyArchive(archivePath) == nil {
				t.Fatal("matching label and OCI hashes masked false account capability")
			}
		})
	}
}

func currentCandidateArchive(t *testing.T, path string) ([]byte, []byte, []byte) {
	t.Helper()
	passwd, group, err := validAccounts().NSSFragments()
	if err != nil {
		t.Fatal(err)
	}
	return currentCandidateArchiveWithNSS(t, path,
		append([]byte("root:x:0:0:root:/root:/bin/sh\ndesktop:x:1000:1000::/tmp/desktop-home:/bin/sh\n"), passwd...),
		append([]byte("root:x:0:\ndesktop:x:1000:\n"), group...))
}

func currentCandidateArchiveWithNSS(t *testing.T, path string, passwd, group []byte) ([]byte, []byte, []byte) {
	t.Helper()
	var layerBuffer bytes.Buffer
	layerWriter := tar.NewWriter(&layerBuffer)
	for _, item := range []struct {
		name     string
		document []byte
	}{{"etc/passwd", passwd}, {"etc/group", group}} {
		if err := layerWriter.WriteHeader(&tar.Header{Name: item.name, Mode: 0o644, Size: int64(len(item.document))}); err != nil {
			t.Fatal(err)
		}
		if _, err := layerWriter.Write(item.document); err != nil {
			t.Fatal(err)
		}
	}
	if err := layerWriter.Close(); err != nil {
		t.Fatal(err)
	}
	layer := layerBuffer.Bytes()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(layer); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	accountDigest, err := validAccounts().Digest()
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"architecture": "amd64", "os": "linux",
		"config": map[string]any{"Labels": map[string]string{"io.github.shell-echo.sandbox-runtime.workload-account-digest": accountDigest}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{testHash(layer)}}})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": testHash(config), "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": testHash(compressed.Bytes()), "size": compressed.Len()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, blob := range [][]byte{manifest, config, compressed.Bytes()} {
		if err := writer.WriteHeader(&tar.Header{Name: "blobs/sha256/" + strings.TrimPrefix(testHash(blob), "sha256:"), Mode: 0o600, Size: int64(len(blob))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(blob); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return config, manifest, buffer.Bytes()
}

func testHash(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
