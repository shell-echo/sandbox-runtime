package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSlice6PreparedPrivateConfigFileSetIsExact(t *testing.T) {
	profile, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	profile.Principals = slices.Clone(profile.Principals)
	for index := range profile.Principals {
		if profile.Principals[index].Name == "workload-credential-controller" {
			profile.Principals[index].UID = uint32(os.Getuid())
			profile.Principals[index].GID = uint32(os.Getgid())
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, Slice6ProfileConfigFile)
	contents := []byte("bounded-test-profile")
	if err := os.WriteFile(file, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	digests := map[string]string{Slice6ProfileConfigFile: "sha256:" + hex.EncodeToString(sum[:])}
	observe := func() error {
		_, err := ObserveSlice6PrivateConfigDirectory(profile, "workload-credential-controller", directory, digests)
		return err
	}
	observed, err := ObserveSlice6PrivateConfigDirectory(profile, "workload-credential-controller", directory, digests)
	if err != nil || len(observed.Files) != 1 || observed.TotalBytes != int64(len(contents)) ||
		observed.Files[0].Digest != digests[Slice6ProfileConfigFile] {
		rootInfo, _ := os.Lstat(directory)
		fileInfo, _ := os.Lstat(file)
		t.Fatalf("exact private file set rejected: %+v, %v; root=%v owned=%v file=%v owned=%v mounts=%v",
			observed, err, rootInfo.Mode(), slice6OwnedBy(rootInfo, uint32(os.Getuid()), uint32(os.Getgid())),
			fileInfo.Mode(), slice6OwnedBy(fileInfo, uint32(os.Getuid()), uint32(os.Getgid())),
			VerifySlice6PrivateConfigMounts(profile))
	}
	wrong := map[string]string{Slice6ProfileConfigFile: "sha256:" + hex.EncodeToString(make([]byte, 32))}
	if _, err := ObserveSlice6PrivateConfigDirectory(profile, "workload-credential-controller", directory, wrong); err == nil {
		t.Fatal("wrong file digest accepted")
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if observe() == nil {
		t.Fatal("public file admitted")
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(directory, "unexpected")
	if err := os.WriteFile(extra, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if observe() == nil {
		t.Fatal("extra file admitted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "missing"), file); err != nil {
		t.Fatal(err)
	}
	if observe() == nil {
		t.Fatal("symlink admitted")
	}
}
