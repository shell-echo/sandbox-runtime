package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	APKLockSchema       = "sandbox.runtime/desktop-phase6-apk-lock/v1"
	APKRepositoryBase   = "https://dl-cdn.alpinelinux.org/alpine/v3.23"
	APKLockAMD64Path    = "phase6-apk-lock-amd64.json"
	APKLockARM64Path    = "phase6-apk-lock-arm64.json"
	maxAPKLockBytes     = 64 << 10
	maxLockedAPKBytes   = 64 << 20
	maxLockedTotalBytes = 512 << 20
)

var (
	ErrInvalidAPKLock = errors.New("invalid Desktop Phase 6 APK lock")
	apkNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}$`)
	apkVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}$`)
)

type APKLock struct {
	SchemaVersion     string      `json:"schema_version"`
	Platform          string      `json:"platform"`
	BaseImageDigest   string      `json:"base_image_digest"`
	SourceIndexDigest string      `json:"source_index_digest"`
	RepositoryBase    string      `json:"repository_base"`
	Required          []Package   `json:"required"`
	PackageCount      int         `json:"package_count"`
	ArchiveDigest     string      `json:"archive_set_digest"`
	InstalledDigest   string      `json:"installed_set_digest"`
	Packages          []LockedAPK `json:"packages"`
}

type LockedAPK struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Repository   string `json:"repository"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	License      string `json:"license"`
}

func APKLockPath(platform string) (string, error) {
	switch platform {
	case "linux/amd64":
		return APKLockAMD64Path, nil
	case "linux/arm64/v8":
		return APKLockARM64Path, nil
	default:
		return "", ErrInvalidAPKLock
	}
}

func LoadAPKLock(path string) (APKLock, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxAPKLockBytes {
		return APKLock{}, ErrInvalidAPKLock
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return APKLock{}, ErrInvalidAPKLock
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var lock APKLock
	if decoder.Decode(&lock) != nil || decoder.Decode(new(any)) != io.EOF || lock.Validate() != nil {
		return APKLock{}, ErrInvalidAPKLock
	}
	canonical, err := json.Marshal(lock)
	if err != nil {
		return APKLock{}, ErrInvalidAPKLock
	}
	var compact bytes.Buffer
	if json.Compact(&compact, document) != nil || !bytes.Equal(compact.Bytes(), canonical) {
		return APKLock{}, ErrInvalidAPKLock
	}
	return lock, nil
}

func (l APKLock) Validate() error {
	if l.SchemaVersion != APKLockSchema || l.SourceIndexDigest != SourceIndexDigest ||
		l.RepositoryBase != APKRepositoryBase || len(l.Required) != 9 ||
		len(l.Packages) < 100 || len(l.Packages) > 250 || l.PackageCount != len(l.Packages) ||
		!digestPattern.MatchString(l.ArchiveDigest) || !digestPattern.MatchString(l.InstalledDigest) {
		return ErrInvalidAPKLock
	}
	var targetArch string
	switch l.Platform {
	case "linux/amd64":
		targetArch = "x86_64"
		if l.BaseImageDigest != "sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3" {
			return ErrInvalidAPKLock
		}
	case "linux/arm64/v8":
		targetArch = "aarch64"
		if l.BaseImageDigest != "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c" {
			return ErrInvalidAPKLock
		}
	default:
		return ErrInvalidAPKLock
	}
	wantRequired := []Package{
		{"xvfb", "21.1.23-r0"}, {"openbox", "3.6.1-r8"}, {"xterm", "403-r0"},
		{"xdotool", "4.20251130.1-r0"}, {"xdpyinfo", "1.4.0-r0"}, {"xset", "1.2.5-r1"},
		{"xwd", "1.0.9-r2"}, {"font-dejavu", "2.37-r6"}, {"ffmpeg", "8.0.1-r1"},
	}
	if !equal(l.Required, wantRequired) {
		return ErrInvalidAPKLock
	}
	seen := make(map[string]LockedAPK, len(l.Packages))
	previous := ""
	var total int64
	for _, item := range l.Packages {
		filename := item.Filename()
		if !apkNamePattern.MatchString(item.Name) || !apkVersionPattern.MatchString(item.Version) ||
			(item.Architecture != targetArch && item.Architecture != "noarch") ||
			(item.Repository != "main" && item.Repository != "community") ||
			!digestPattern.MatchString(item.SHA256) || item.Size < 1 || item.Size > maxLockedAPKBytes ||
			item.License == "" || len(item.License) > 512 || strings.ContainsAny(item.License, "\r\n\x00") ||
			filename <= previous {
			return ErrInvalidAPKLock
		}
		previous = filename
		total += item.Size
		if total > maxLockedTotalBytes {
			return ErrInvalidAPKLock
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return ErrInvalidAPKLock
		}
		seen[item.Name] = item
	}
	for _, required := range l.Required {
		item, ok := seen[required.Name]
		if !ok || item.Version != required.Version {
			return ErrInvalidAPKLock
		}
	}
	if l.ArchiveDigest != l.ArchiveSetDigest() {
		return ErrInvalidAPKLock
	}
	return nil
}

func (p LockedAPK) Filename() string { return p.Name + "-" + p.Version + ".apk" }

func (p LockedAPK) URL(l APKLock) string {
	arch := "x86_64"
	if l.Platform == "linux/arm64/v8" {
		arch = "aarch64"
	}
	return l.RepositoryBase + "/" + p.Repository + "/" + arch + "/" + p.Filename()
}

// ArchiveSetDigest has a stable repository-owned canonical record format.
// The final newline and package ordering are part of the digest domain.
func (l APKLock) ArchiveSetDigest() string {
	hash := sha256.New()
	for _, item := range l.Packages {
		_, _ = fmt.Fprintf(hash, "%s\t%s\t%s\t%s\t%s\t%d\n",
			item.Name, item.Version, item.Architecture, item.Repository, item.SHA256, item.Size)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// VerifyAPKDirectory rejects missing, extra, symlinked and modified archives.
// The Docker build receives only this exact verified directory.
func (l APKLock) VerifyAPKDirectory(directory string) error {
	if l.Validate() != nil || !filepath.IsAbs(directory) {
		return ErrInvalidAPKLock
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(l.Packages) {
		return ErrInvalidAPKLock
	}
	for index, item := range l.Packages {
		entry := entries[index]
		if entry.Name() != item.Filename() || !entry.Type().IsRegular() ||
			verifyLockedAPK(filepath.Join(directory, entry.Name()), item) != nil {
			return ErrInvalidAPKLock
		}
	}
	return nil
}

func verifyLockedAPK(path string, item LockedAPK) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != item.Size {
		return ErrInvalidAPKLock
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrInvalidAPKLock
	}
	defer file.Close()
	hash := sha256.New()
	if count, err := io.Copy(hash, io.LimitReader(file, item.Size+1)); err != nil || count != item.Size ||
		"sha256:"+hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		return ErrInvalidAPKLock
	}
	return nil
}
