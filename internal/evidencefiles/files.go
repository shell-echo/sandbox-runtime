// Package evidencefiles reads the bounded, sanitized file inventory used by
// qualification evidence. It intentionally exposes only relative paths,
// byte counts, and raw-file digests; callers remain responsible for validating
// the report that describes those files.
package evidencefiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	// DefaultMaxFiles is the P2.7 evidence payload file-count bound. The bound
	// applies to every regular file below the root, including excluded report
	// and receipt files.
	DefaultMaxFiles = 16
	// DefaultMaxFileBytes is the P2.7 per-file evidence bound.
	DefaultMaxFileBytes int64 = 2 << 20
	// DefaultMaxTotalBytes is the P2.7 aggregate evidence bound.
	DefaultMaxTotalBytes int64 = 8 << 20
	// DigestProfile is the canonical digest profile for the payload inventory.
	DigestProfile = "sha256-rfc8785-json-array-v1"
	// FileDigestProfile is the digest profile for raw file bytes.
	FileDigestProfile = "sha256-raw-file-bytes-v1"
	// MaxPathRunes bounds the normalized relative path exposed in evidence.
	MaxPathRunes = 240
)

// Options controls the hard bounds used by Read. All values must be positive
// (MaxTotalBytes may be zero only when an empty root is intentionally allowed).
// A zero Options value is invalid; use DefaultOptions when profile defaults are
// desired.
type Options struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// DefaultOptions returns the bounds locked by the coding/shell qualification
// profile.
func DefaultOptions() Options {
	return Options{
		MaxFiles:      DefaultMaxFiles,
		MaxFileBytes:  DefaultMaxFileBytes,
		MaxTotalBytes: DefaultMaxTotalBytes,
	}
}

// Entry is one sanitized evidence payload file. Path is a normalized relative
// POSIX path. SHA256 hashes exactly the bytes read from that regular file.
type Entry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Inventory is the bounded snapshot of a root. Entries excludes the paths
// supplied to Read, while FileCount and TotalBytes cover every regular file,
// including excluded paths, so report and receipt files cannot bypass limits.
type Inventory struct {
	Entries    []Entry
	Digest     string
	FileCount  int
	TotalBytes int64
}

// Read inventories only regular, non-symlink, singly linked files directly in
// root. Directories and nested paths are rejected. Exclusions are normalized
// root-level names and are omitted from Entries, but remain included in the
// count and byte limits. The returned entries and digest are deterministic.
func Read(root string, exclusions []string, options Options) (Inventory, error) {
	opened, err := OpenRoot(root)
	if err != nil {
		return Inventory{}, err
	}
	defer opened.Close()
	return opened.Read(exclusions, options)
}

// DigestEntries returns the SHA-256 digest of entries serialized as an RFC
// 8785 canonical JSON array. Entries must contain normalized, unique paths and
// are sorted by path before canonicalization. A copy is sorted, so the caller's
// slice is not mutated.
func DigestEntries(entries []Entry) (string, error) {
	copyEntries := append([]Entry(nil), entries...)
	seen := make(map[string]struct{}, len(copyEntries))
	for index, entry := range copyEntries {
		if err := validateEntry(entry); err != nil {
			return "", fmt.Errorf("inventory entry %d: %w", index, err)
		}
		if _, duplicate := seen[entry.Path]; duplicate {
			return "", fmt.Errorf("evidence inventory contains duplicate path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
	}
	sort.Slice(copyEntries, func(i, j int) bool { return copyEntries[i].Path < copyEntries[j].Path })
	encoded, err := json.Marshal(copyEntries)
	if err != nil {
		return "", fmt.Errorf("encode evidence inventory: %w", err)
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return "", fmt.Errorf("canonicalize evidence inventory: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateOptions(options Options) error {
	if options.MaxFiles <= 0 {
		return errors.New("evidence MaxFiles must be positive")
	}
	if options.MaxFileBytes <= 0 {
		return errors.New("evidence MaxFileBytes must be positive")
	}
	if options.MaxTotalBytes < 0 {
		return errors.New("evidence MaxTotalBytes must not be negative")
	}
	return nil
}

func normalizeExclusions(exclusions []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(exclusions))
	for _, exclusion := range exclusions {
		if err := validateRootFilePath(exclusion); err != nil {
			return nil, fmt.Errorf("evidence exclusion %q: %w", exclusion, err)
		}
		if _, duplicate := result[exclusion]; duplicate {
			return nil, fmt.Errorf("evidence exclusions contain duplicate path %q", exclusion)
		}
		result[exclusion] = struct{}{}
	}
	return result, nil
}

func validateRootFilePath(value string) error {
	if err := validateRelativePath(value); err != nil {
		return err
	}
	if strings.Contains(value, "/") {
		return errors.New("path must name a file directly at the evidence root")
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) || strings.ContainsRune(value, '\\') || !fs.ValidPath(value) || value == "." {
		return errors.New("path must be a normalized relative POSIX path")
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxPathRunes {
		return fmt.Errorf("path must be valid UTF-8 and at most %d characters", MaxPathRunes)
	}
	for _, character := range value {
		if character <= 0x1f || character == 0x7f {
			return errors.New("path must not contain control characters")
		}
	}
	return nil
}

func validateEntry(entry Entry) error {
	if err := validateRootFilePath(entry.Path); err != nil {
		return err
	}
	if entry.Bytes < 0 {
		return errors.New("byte count must not be negative")
	}
	if len(entry.SHA256) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(entry.SHA256, "sha256:") {
		return errors.New("SHA-256 digest must use lowercase sha256: form")
	}
	for _, digit := range entry.SHA256[len("sha256:"):] {
		if !((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f')) {
			return errors.New("SHA-256 digest must use lowercase sha256: form")
		}
	}
	return nil
}

func rawDigest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// RawDigest returns the lowercase SHA-256 digest of exact raw bytes using the
// FileDigestProfile representation.
func RawDigest(contents []byte) string {
	return rawDigest(contents)
}

// ReadFile reads one bounded, regular, non-symlink, singly linked file directly
// in root and checks its identity before and after reading. This is used for
// report.json, whose raw bytes must be hashed exactly for the validator receipt.
func ReadFile(root, relative string, maximum int64) ([]byte, error) {
	opened, err := OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	return opened.ReadFile(relative, maximum)
}
