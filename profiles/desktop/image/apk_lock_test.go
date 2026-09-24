package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase6APKLocksAreClosedPerArchitecture(t *testing.T) {
	for _, item := range []struct{ platform, path, arch string }{
		{"linux/amd64", APKLockAMD64Path, "x86_64"},
		{"linux/arm64/v8", APKLockARM64Path, "aarch64"},
	} {
		t.Run(item.platform, func(t *testing.T) {
			path, err := APKLockPath(item.platform)
			if err != nil || path != item.path {
				t.Fatalf("lock path = %q, %v", path, err)
			}
			lock, err := LoadAPKLock(path)
			if err != nil || lock.Platform != item.platform || lock.ArchiveSetDigest() == "" {
				t.Fatalf("load lock = %v", err)
			}
			for _, pkg := range lock.Packages {
				if pkg.Architecture != item.arch && pkg.Architecture != "noarch" {
					t.Fatalf("wrong package architecture %q", pkg.Architecture)
				}
				if !strings.HasPrefix(pkg.URL(lock), APKRepositoryBase+"/") {
					t.Fatalf("package URL escapes pinned repository: %q", pkg.URL(lock))
				}
			}
			for name, mutate := range map[string]func(*APKLock){
				"missing package":    func(value *APKLock) { value.Packages = value.Packages[1:] },
				"duplicate package":  func(value *APKLock) { value.Packages = append(value.Packages, value.Packages[len(value.Packages)-1]) },
				"cross architecture": func(value *APKLock) { value.Packages[0].Architecture = "opposite" },
				"bad source":         func(value *APKLock) { value.RepositoryBase = "https://example.test/apk" },
				"bad repository":     func(value *APKLock) { value.Packages[0].Repository = "../main" },
				"mutable digest":     func(value *APKLock) { value.Packages[0].SHA256 = "sha256:latest" },
				"oversized package":  func(value *APKLock) { value.Packages[0].Size = maxLockedAPKBytes + 1 },
			} {
				t.Run(name, func(t *testing.T) {
					copy := lock
					copy.Packages = append([]LockedAPK(nil), lock.Packages...)
					mutate(&copy)
					if copy.Validate() == nil {
						t.Fatal("unsafe APK lock was accepted")
					}
				})
			}
		})
	}
	if _, err := APKLockPath("linux/s390x"); err == nil {
		t.Fatal("unsupported architecture inherited a package lock")
	}
}

func TestLockedAPKBytesRejectMutationTruncationAndSymlink(t *testing.T) {
	contents := []byte("signed-test-archive")
	digest := sha256.Sum256(contents)
	item := LockedAPK{Name: "sample", Version: "1-r0", Architecture: "aarch64", Repository: "main",
		SHA256: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(contents)), License: "MIT"}
	directory := t.TempDir()
	valid := filepath.Join(directory, item.Filename())
	if err := writeLockedAPK(valid, bytes.NewReader(contents), item); err != nil {
		t.Fatal(err)
	}
	if err := verifyLockedAPK(valid, item); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"mutation":   []byte("signed-test-archivE"),
		"truncation": []byte("signed-test-archiv"),
		"oversized":  []byte("signed-test-archive!"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".apk")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := verifyLockedAPK(path, item); err == nil {
				t.Fatal("modified archive was accepted")
			}
		})
	}
	link := filepath.Join(directory, "linked.apk")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyLockedAPK(link, item); err == nil {
		t.Fatal("symlinked archive was accepted")
	}
	for name, data := range map[string][]byte{
		"mutation":   []byte("signed-test-archivE"),
		"truncation": []byte("signed-test-archiv"),
		"oversized":  []byte("signed-test-archive!"),
	} {
		t.Run("stage-"+name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rejected.apk")
			if err := writeLockedAPK(path, bytes.NewReader(data), item); err == nil {
				t.Fatal("modified archive was staged")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("failed staging left archive behind: %v", err)
			}
		})
	}
}

func TestPhase6APKLockLoaderRejectsUnknownAndDuplicateJSON(t *testing.T) {
	lock, err := LoadAPKLock(APKLockARM64Path)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string][]byte{
		"duplicate": append([]byte(`{"schema_version":"x",`), document[1:]...),
		"unknown":   append([]byte(`{"unknown":true,`), document[1:]...),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock.json")
			if err := os.WriteFile(path, mutated, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAPKLock(path); err == nil {
				t.Fatal("invalid APK lock JSON was accepted")
			}
		})
	}
}
