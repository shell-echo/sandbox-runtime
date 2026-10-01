package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

// Slice6PrivateConfigFileObservation records only non-secret filesystem facts.
// It is not a Docker mount observation or evidence of a kernel disk quota.
type Slice6PrivateConfigFileObservation struct {
	Name   string
	Bytes  int64
	Digest string
}

type Slice6PrivateConfigDirectoryObservation struct {
	Files      []Slice6PrivateConfigFileObservation
	TotalBytes int64
}

// ObserveSlice6PrivateConfigDirectory reopens one exact per-UID prepared file
// set. The caller still has to prove the directory is mounted read-only into
// only its intended non-root container, with no remaining preparation writer.
func ObserveSlice6PrivateConfigDirectory(profile Profile, deployment, directory string,
	expectedDigests map[string]string) (Slice6PrivateConfigDirectoryObservation, error) {
	if VerifySlice6PrivateConfigMounts(profile) != nil || !filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory {
		return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
	}
	want, ok := Slice6PrivateConfigMount(deployment)
	if !ok {
		return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
	}
	var owner Principal
	for _, principal := range profile.Principals {
		if principal.Name == deployment {
			owner = principal
			break
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
		!slice6OwnedBy(info, owner.UID, owner.GID) {
		return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
	}
	listed := strings.Split(want.PrivateFiles, ",")
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(listed) || len(expectedDigests) != len(listed) {
		return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
	}
	result := Slice6PrivateConfigDirectoryObservation{Files: make([]Slice6PrivateConfigFileObservation, 0, len(listed))}
	for _, entry := range entries {
		name := entry.Name()
		if !slices.Contains(listed, name) || !digestPattern.MatchString(expectedDigests[name]) {
			return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
		}
		limit, ok := Slice6PrivateConfigFileLimit(deployment, name)
		if !ok {
			return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
		}
		path := filepath.Join(directory, name)
		fileInfo, err := os.Lstat(path)
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 ||
			!slice6OwnedBy(fileInfo, owner.UID, owner.GID) || fileInfo.Size() < 1 || fileInfo.Size() > limit {
			return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
		}
		contents, err := secretfile.Read(path, limit)
		if err != nil {
			return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
		}
		sum := sha256.Sum256(contents)
		clear(contents)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if digest != expectedDigests[name] {
			return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
		}
		result.TotalBytes += fileInfo.Size()
		result.Files = append(result.Files, Slice6PrivateConfigFileObservation{Name: name,
			Bytes: fileInfo.Size(), Digest: digest})
	}
	if result.TotalBytes > want.MaxBytes {
		return Slice6PrivateConfigDirectoryObservation{}, errSlice6DesiredInventory
	}
	return result, nil
}

func slice6OwnedBy(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}
