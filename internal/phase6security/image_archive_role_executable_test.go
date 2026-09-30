package phase6security

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type roleTarEntry struct {
	name     string
	data     []byte
	mode     int64
	typeFlag byte
}

func TestReadVerifiedOCIArchiveRoleExecutableUsesOrderedLayers(t *testing.T) {
	makeLayer := func(entries ...roleTarEntry) []byte {
		t.Helper()
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		for _, entry := range entries {
			header := &tar.Header{Name: entry.name, Size: int64(len(entry.data)), Mode: entry.mode, Typeflag: entry.typeFlag}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if len(entry.data) > 0 {
				if _, err := writer.Write(entry.data); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	role := func(value string, mode int64) roleTarEntry {
		return roleTarEntry{name: "usr/local/bin/phase6-role", data: []byte(value), mode: mode, typeFlag: tar.TypeReg}
	}
	check := func(layers [][]byte) ([]byte, error) {
		t.Helper()
		var descriptors []map[string]any
		var diffIDs []string
		archive := filepath.Join(t.TempDir(), "candidate.oci.tar")
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		for _, layer := range layers {
			digest := hashImageBytes(layer)
			descriptors = append(descriptors, map[string]any{
				"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest, "size": len(layer)})
			diffIDs = append(diffIDs, digest)
			header := &tar.Header{Name: "blobs/sha256/" + digest[7:], Mode: 0o600,
				Size: int64(len(layer)), Typeflag: tar.TypeReg}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(layer); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(archive, buffer.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		manifest, err := json.Marshal(map[string]any{"layers": descriptors})
		if err != nil {
			t.Fatal(err)
		}
		config, err := json.Marshal(map[string]any{"rootfs": map[string]any{"diff_ids": diffIDs}})
		if err != nil {
			t.Fatal(err)
		}
		return ReadVerifiedOCIArchiveRoleExecutable(archive, manifest, config)
	}
	old := makeLayer(role("old", 0o555))
	newer := makeLayer(role("new", 0o555))
	if value, err := check([][]byte{old, newer}); err != nil || string(value) != "new" {
		t.Fatalf("ordered replacement = %q, %v", value, err)
	}
	for name, layer := range map[string][]byte{
		"wrong mode":        makeLayer(role("unsafe", 0o755)),
		"symlink":           makeLayer(roleTarEntry{name: "usr/local/bin/phase6-role", mode: 0o555, typeFlag: tar.TypeSymlink}),
		"duplicate":         makeLayer(role("first", 0o555), role("second", 0o555)),
		"whiteout":          makeLayer(roleTarEntry{name: "usr/local/bin/.wh.phase6-role", mode: 0o000, typeFlag: tar.TypeReg}),
		"ancestor whiteout": makeLayer(roleTarEntry{name: "usr/local/.wh.bin", mode: 0o000, typeFlag: tar.TypeReg}),
		"absent":            makeLayer(roleTarEntry{name: "usr/local/bin/other", data: []byte("other"), mode: 0o555, typeFlag: tar.TypeReg}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := check([][]byte{layer}); err == nil {
				t.Fatal("invalid role executable layer admitted")
			}
		})
	}
	whiteout := makeLayer(roleTarEntry{name: "usr/local/bin/.wh.phase6-role", mode: 0, typeFlag: tar.TypeReg})
	if _, err := check([][]byte{old, whiteout}); err == nil {
		t.Fatal("later role whiteout retained an earlier executable")
	}
}

func TestReadVerifiedOCIArchiveDesktopBrokerRejectsAmbiguousLayers(t *testing.T) {
	const target = "usr/local/libexec/sandbox-runtime/desktop-broker"
	layer := func(entries ...roleTarEntry) []byte {
		t.Helper()
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		for _, entry := range entries {
			header := &tar.Header{Name: entry.name, Size: int64(len(entry.data)), Mode: entry.mode, Typeflag: entry.typeFlag}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	check := func(layers ...[]byte) ([]byte, error) {
		t.Helper()
		var descriptors []map[string]any
		var diffIDs []string
		archive := filepath.Join(t.TempDir(), "desktop.oci.tar")
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		for _, content := range layers {
			digest := hashImageBytes(content)
			descriptors = append(descriptors, map[string]any{
				"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest, "size": len(content)})
			diffIDs = append(diffIDs, digest)
			if err := writer.WriteHeader(&tar.Header{Name: "blobs/sha256/" + digest[7:], Mode: 0o600,
				Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(content); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(archive, buffer.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		manifest, err := json.Marshal(map[string]any{"layers": descriptors})
		if err != nil {
			t.Fatal(err)
		}
		config, err := json.Marshal(map[string]any{"rootfs": map[string]any{"diff_ids": diffIDs}})
		if err != nil {
			t.Fatal(err)
		}
		return ReadVerifiedOCIArchiveDesktopBroker(archive, manifest, config)
	}
	old := layer(roleTarEntry{name: target, data: []byte("old"), mode: 0o555, typeFlag: tar.TypeReg})
	newer := layer(roleTarEntry{name: target, data: []byte("new"), mode: 0o555, typeFlag: tar.TypeReg})
	if value, err := check(old, newer); err != nil || string(value) != "new" {
		t.Fatalf("selected effective broker = %q, %v", value, err)
	}
	for name, unsafe := range map[string][]byte{
		"symlink": layer(roleTarEntry{name: target, mode: 0o555, typeFlag: tar.TypeSymlink}),
		"mode":    layer(roleTarEntry{name: target, data: []byte("unsafe"), mode: 0o755, typeFlag: tar.TypeReg}),
		"whiteout": layer(roleTarEntry{name: "usr/local/libexec/sandbox-runtime/.wh.desktop-broker",
			mode: 0, typeFlag: tar.TypeReg}),
		"ancestor symlink": layer(roleTarEntry{name: "usr/local/libexec/sandbox-runtime", mode: 0o777,
			typeFlag: tar.TypeSymlink}, roleTarEntry{name: target, data: []byte("unsafe"), mode: 0o555, typeFlag: tar.TypeReg}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := check(unsafe); err == nil {
				t.Fatal("ambiguous Desktop broker layer admitted")
			}
		})
	}
	whiteout := layer(roleTarEntry{name: "usr/local/libexec/sandbox-runtime/.wh.desktop-broker",
		mode: 0, typeFlag: tar.TypeReg})
	if _, err := check(old, whiteout); err == nil {
		t.Fatal("later Desktop broker whiteout retained earlier bytes")
	}
}
