package phase6security

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyOCIArchiveLayersRejectsTamperMissingAndWrongDiffID(t *testing.T) {
	raw := []byte("test-owned uncompressed layer contents")
	var compressed bytes.Buffer
	compressor := gzip.NewWriter(&compressed)
	if _, err := compressor.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	compressedDigest, diffID := hashImageBytes(compressed.Bytes()), hashImageBytes(raw)
	encode := func(value any) []byte { document, _ := json.Marshal(value); return document }
	manifest := func(layerDigest string) []byte {
		return encode(map[string]any{"layers": []any{map[string]any{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layerDigest, "size": compressed.Len()}}})
	}
	config := func(rootDigest string) []byte {
		return encode(map[string]any{"rootfs": map[string]any{"diff_ids": []string{rootDigest}}})
	}
	archive := func(path, blobName string, contents []byte, duplicate bool) {
		t.Helper()
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		write := func() {
			if err := writer.WriteHeader(&tar.Header{Name: blobName, Mode: 0o644, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(contents); err != nil {
				t.Fatal(err)
			}
		}
		write()
		if duplicate {
			write()
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	blobName := "blobs/sha256/" + compressedDigest[7:]
	archive(path, blobName, compressed.Bytes(), false)
	if err := VerifyOCIArchiveLayers(path, manifest(compressedDigest), config(diffID)); err != nil {
		t.Fatalf("valid layer archive rejected: %v", err)
	}
	for name, run := range map[string]func() error{
		"wrong diffID": func() error {
			return VerifyOCIArchiveLayers(path, manifest(compressedDigest), config(testDigest("wrong")))
		},
		"wrong layer digest": func() error { return VerifyOCIArchiveLayers(path, manifest(testDigest("wrong")), config(diffID)) },
		"missing blob": func() error {
			archive(path, "blobs/sha256/"+testDigest("other")[7:], compressed.Bytes(), false)
			return VerifyOCIArchiveLayers(path, manifest(compressedDigest), config(diffID))
		},
		"tampered bytes": func() error {
			changed := append([]byte(nil), compressed.Bytes()...)
			changed[len(changed)-1] ^= 1
			archive(path, blobName, changed, false)
			return VerifyOCIArchiveLayers(path, manifest(compressedDigest), config(diffID))
		},
		"duplicate blob": func() error {
			archive(path, blobName, compressed.Bytes(), true)
			return VerifyOCIArchiveLayers(path, manifest(compressedDigest), config(diffID))
		},
		"unsafe path": func() error {
			archive(path, "../"+blobName, compressed.Bytes(), false)
			return VerifyOCIArchiveLayers(path, manifest(compressedDigest), config(diffID))
		},
	} {
		t.Run(name, func(t *testing.T) {
			archive(path, blobName, compressed.Bytes(), false)
			if err := run(); !errors.Is(err, ErrInvalidImageDescriptor) {
				t.Fatalf("invalid layer archive accepted: %v", err)
			}
		})
	}
	archive(path, blobName, compressed.Bytes(), false)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOCIArchiveLayers(path, manifest(compressedDigest), config(diffID)); !errors.Is(err, ErrInvalidImageDescriptor) {
		t.Fatal("public archive accepted")
	}
}
