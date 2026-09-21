// Package desktopcandidate defines the non-release Desktop runtime identity
// used only by the Phase 6 Slice 4 local integration gate.
package desktopcandidate

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
)

const (
	SchemaID       = "sandbox.runtime/desktop-phase6-local-candidate/v1"
	Classification = "local-candidate-non-release"
	Version        = 1
	MaxDocument    = 64 << 10
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

var ErrInvalidCandidate = errors.New("invalid Desktop Phase 6 local candidate")

type Manifest struct {
	SchemaVersion           string `json:"schema_version"`
	Version                 int    `json:"version"`
	Classification          string `json:"classification"`
	SourceRevision          string `json:"source_revision"`
	SourceTreeDigest        string `json:"source_tree_digest"`
	GoVersion               string `json:"go_version"`
	Platform                string `json:"platform"`
	ProfileID               string `json:"profile_id"`
	BrokerProtocol          string `json:"broker_protocol"`
	SessionProtocol         string `json:"session_protocol"`
	BaseImageDigest         string `json:"base_image_digest"`
	PackageArchiveSetDigest string `json:"package_archive_set_digest"`
	InstalledSetDigest      string `json:"installed_set_digest"`
	DockerfileDigest        string `json:"dockerfile_digest"`
	EntrypointDigest        string `json:"entrypoint_digest"`
	BuildScriptDigest       string `json:"build_script_digest"`
	CandidateScriptDigest   string `json:"candidate_script_digest"`
	BuildArgumentsDigest    string `json:"build_arguments_digest"`
	ImageDigest             string `json:"image_digest"`
	ConfigDigest            string `json:"config_digest"`
	ManifestDigest          string `json:"manifest_digest"`
}

func New(sourceRoot, platform, imageDigest, configDigest string) (Manifest, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return Manifest{}, ErrInvalidCandidate
	}
	revision, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil || !revisionPattern.MatchString(revision) {
		return Manifest{}, ErrInvalidCandidate
	}
	treeDigest, err := SourceTreeDigest(root)
	if err != nil {
		return Manifest{}, err
	}
	locked, err := desktopimage.Load(filepath.Join(root, "profiles", "desktop", "image", "manifest.json"))
	if err != nil {
		return Manifest{}, ErrInvalidCandidate
	}
	source, ok := locked.Source.Manifests[platform]
	if !ok {
		return Manifest{}, ErrInvalidCandidate
	}
	imageRoot := filepath.Join(root, "profiles", "desktop", "image")
	dockerfileDigest, err := fileDigest(filepath.Join(imageRoot, "Dockerfile"))
	if err != nil {
		return Manifest{}, err
	}
	entrypointDigest, err := fileDigest(filepath.Join(imageRoot, "entrypoint.sh"))
	if err != nil {
		return Manifest{}, err
	}
	buildScriptDigest, err := fileDigest(filepath.Join(imageRoot, "build.sh"))
	if err != nil {
		return Manifest{}, err
	}
	candidateScriptDigest, err := fileDigest(filepath.Join(imageRoot, "build-phase6-candidate.sh"))
	if err != nil {
		return Manifest{}, err
	}
	value := Manifest{
		SchemaVersion: SchemaID, Version: Version, Classification: Classification,
		SourceRevision: revision, SourceTreeDigest: treeDigest, GoVersion: runtime.Version(), Platform: platform,
		ProfileID: desktopimage.ProfileID, BrokerProtocol: desktopimage.BrokerProtocol, SessionProtocol: desktopbroker.SessionProtocolV2ID,
		BaseImageDigest: source.Digest, PackageArchiveSetDigest: source.PackageArchiveSetDigest,
		InstalledSetDigest: source.InstalledSetDigest, DockerfileDigest: dockerfileDigest,
		EntrypointDigest: entrypointDigest, BuildScriptDigest: buildScriptDigest, CandidateScriptDigest: candidateScriptDigest,
		ImageDigest: imageDigest, ConfigDigest: configDigest,
	}
	value.BuildArgumentsDigest = value.calculateBuildArgumentsDigest()
	value.ManifestDigest = value.calculateManifestDigest()
	if err := value.Validate(); err != nil {
		return Manifest{}, err
	}
	return value, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaID || m.Version != Version || m.Classification != Classification ||
		!revisionPattern.MatchString(m.SourceRevision) || m.GoVersion != "go1.26.5" ||
		(m.Platform != "linux/amd64" && m.Platform != "linux/arm64/v8") || m.ProfileID != desktopimage.ProfileID ||
		m.BrokerProtocol != desktopimage.BrokerProtocol || m.SessionProtocol != desktopbroker.SessionProtocolV2ID {
		return ErrInvalidCandidate
	}
	for _, digest := range []string{m.SourceTreeDigest, m.BaseImageDigest, m.PackageArchiveSetDigest, m.InstalledSetDigest, m.DockerfileDigest, m.EntrypointDigest, m.BuildScriptDigest, m.CandidateScriptDigest, m.BuildArgumentsDigest, m.ImageDigest, m.ConfigDigest, m.ManifestDigest} {
		if !digestPattern.MatchString(digest) {
			return ErrInvalidCandidate
		}
	}
	if m.ImageDigest != m.ConfigDigest || m.BuildArgumentsDigest != m.calculateBuildArgumentsDigest() || m.ManifestDigest != m.calculateManifestDigest() {
		return ErrInvalidCandidate
	}
	return nil
}

func (m Manifest) VerifySource(sourceRoot string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return ErrInvalidCandidate
	}
	revision, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil || revision != m.SourceRevision {
		return ErrInvalidCandidate
	}
	tree, err := SourceTreeDigest(root)
	if err != nil || tree != m.SourceTreeDigest {
		return ErrInvalidCandidate
	}
	locked, err := desktopimage.Load(filepath.Join(root, "profiles", "desktop", "image", "manifest.json"))
	source, ok := locked.Source.Manifests[m.Platform]
	if err != nil || !ok || source.Digest != m.BaseImageDigest || source.PackageArchiveSetDigest != m.PackageArchiveSetDigest || source.InstalledSetDigest != m.InstalledSetDigest {
		return ErrInvalidCandidate
	}
	for path, want := range map[string]string{
		"profiles/desktop/image/Dockerfile":                m.DockerfileDigest,
		"profiles/desktop/image/entrypoint.sh":             m.EntrypointDigest,
		"profiles/desktop/image/build.sh":                  m.BuildScriptDigest,
		"profiles/desktop/image/build-phase6-candidate.sh": m.CandidateScriptDigest,
	} {
		got, digestErr := fileDigest(filepath.Join(root, filepath.FromSlash(path)))
		if digestErr != nil || got != want {
			return ErrInvalidCandidate
		}
	}
	return nil
}

func Load(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) || info.Size() < 1 || info.Size() > MaxDocument {
		return Manifest{}, ErrInvalidCandidate
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, ErrInvalidCandidate
	}
	var value Manifest
	if decode(document, &value) != nil || value.Validate() != nil {
		return Manifest{}, ErrInvalidCandidate
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(document, canonical) {
		return Manifest{}, ErrInvalidCandidate
	}
	return value, nil
}

func Save(path string, value Manifest) error {
	if !filepath.IsAbs(path) || value.Validate() != nil {
		return ErrInvalidCandidate
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !ownedByCurrentUser(info) {
		return ErrInvalidCandidate
	}
	document, err := json.Marshal(value)
	if err != nil || len(document) > MaxDocument {
		return ErrInvalidCandidate
	}
	temporary, err := os.CreateTemp(directory, ".desktop-phase6-candidate-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(document); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func SourceTreeDigest(sourceRoot string) (string, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return "", ErrInvalidCandidate
	}
	command := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", ErrInvalidCandidate
	}
	paths := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	entries := make([]sourceEntry, 0, len(paths))
	for _, relative := range paths {
		if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", ErrInvalidCandidate
		}
		absolute := filepath.Join(root, relative)
		info, err := os.Lstat(absolute)
		if err != nil {
			return "", ErrInvalidCandidate
		}
		var contents []byte
		mode := canonicalSourceMode(info.Mode().Perm())
		switch {
		case info.Mode().IsRegular():
			contents, err = os.ReadFile(absolute)
		case info.Mode()&os.ModeSymlink != 0:
			mode = "symlink"
			var target string
			target, err = os.Readlink(absolute)
			contents = []byte(target)
		default:
			return "", ErrInvalidCandidate
		}
		if err != nil {
			return "", ErrInvalidCandidate
		}
		entries = append(entries, sourceEntry{path: filepath.ToSlash(relative), mode: mode, contents: contents})
	}
	return digestSourceEntries(entries), nil
}

// SourceTreeDigestAtRevision reproduces SourceTreeDigest from one immutable
// Git revision. It is used by the evidence verifier after a documentation-only
// evidence commit has advanced HEAD beyond the implementation revision.
func SourceTreeDigestAtRevision(sourceRoot, revision string) (string, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil || !revisionPattern.MatchString(revision) {
		return "", ErrInvalidCandidate
	}
	command := exec.Command("git", "archive", "--format=tar", revision)
	command.Dir = root
	document, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("%w: archive implementation revision", ErrInvalidCandidate)
	}
	reader := tar.NewReader(bytes.NewReader(document))
	entries := make([]sourceEntry, 0)
	for {
		header, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || header.Name == "" {
			return "", fmt.Errorf("%w: read archive header", ErrInvalidCandidate)
		}
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeXHeader, tar.TypeXGlobalHeader:
			continue
		case tar.TypeReg, tar.TypeRegA:
			if filepath.IsAbs(header.Name) || filepath.Clean(header.Name) != filepath.FromSlash(header.Name) || strings.HasPrefix(header.Name, "../") {
				return "", fmt.Errorf("%w: unsafe archive path %q", ErrInvalidCandidate, header.Name)
			}
			contents, readErr := io.ReadAll(io.LimitReader(reader, header.Size+1))
			if readErr != nil || int64(len(contents)) != header.Size {
				return "", fmt.Errorf("%w: read archive file %q", ErrInvalidCandidate, header.Name)
			}
			entries = append(entries, sourceEntry{path: header.Name, mode: canonicalSourceMode(os.FileMode(header.Mode)), contents: contents})
		case tar.TypeSymlink:
			if filepath.IsAbs(header.Name) || filepath.Clean(header.Name) != filepath.FromSlash(header.Name) || strings.HasPrefix(header.Name, "../") {
				return "", fmt.Errorf("%w: unsafe archive path %q", ErrInvalidCandidate, header.Name)
			}
			entries = append(entries, sourceEntry{path: header.Name, mode: "symlink", contents: []byte(header.Linkname)})
		default:
			return "", fmt.Errorf("%w: unsupported archive entry %q type %d", ErrInvalidCandidate, header.Name, header.Typeflag)
		}
	}
	return digestSourceEntries(entries), nil
}

type sourceEntry struct {
	path, mode string
	contents   []byte
}

func canonicalSourceMode(mode os.FileMode) string {
	if mode&0o111 != 0 {
		return "regular:0755"
	}
	return "regular:0644"
}

func digestSourceEntries(entries []sourceEntry) string {
	sort.Slice(entries, func(left, right int) bool { return entries[left].path < entries[right].path })
	hash := sha256.New()
	for _, entry := range entries {
		_, _ = hash.Write([]byte(entry.path))
		_, _ = hash.Write([]byte{'\x00'})
		_, _ = hash.Write([]byte(entry.mode))
		_, _ = hash.Write([]byte{'\x00'})
		_, _ = hash.Write(entry.contents)
		_, _ = hash.Write([]byte{'\x00'})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func (m Manifest) calculateBuildArgumentsDigest() string {
	value := struct {
		Platform, SourceRevision, GoVersion, BaseImageDigest, PackageArchiveSetDigest, InstalledSetDigest, DockerfileDigest, EntrypointDigest, BuildScriptDigest, CandidateScriptDigest string
	}{m.Platform, m.SourceRevision, m.GoVersion, m.BaseImageDigest, m.PackageArchiveSetDigest, m.InstalledSetDigest, m.DockerfileDigest, m.EntrypointDigest, m.BuildScriptDigest, m.CandidateScriptDigest}
	return digestJSON(value)
}

func (m Manifest) calculateManifestDigest() string {
	m.ManifestDigest = ""
	return digestJSON(m)
}

func digestJSON(value any) string {
	document, _ := json.Marshal(value)
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func fileDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidCandidate
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return "", ErrInvalidCandidate
	}
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func decode(document []byte, target any) error {
	duplicate := json.NewDecoder(bytes.NewReader(document))
	if err := scanUniqueJSON(duplicate); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidCandidate
	}
	return nil
}

func scanUniqueJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	var scan func(json.Token) error
	scan = func(value json.Token) error {
		delimiter, ok := value.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidCandidate
				}
				if _, exists := seen[key]; exists {
					return ErrInvalidCandidate
				}
				seen[key] = struct{}{}
				next, err := decoder.Token()
				if err != nil || scan(next) != nil {
					return ErrInvalidCandidate
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				next, err := decoder.Token()
				if err != nil || scan(next) != nil {
					return ErrInvalidCandidate
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrInvalidCandidate
		}
	}
	if err := scan(token); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidCandidate
	}
	return nil
}

func gitOutput(root string, arguments ...string) (string, error) {
	command := exec.Command("git", arguments...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(stat.Uid) == uint32(os.Getuid())
}

func (m Manifest) String() string {
	return fmt.Sprintf("%s %s %s", m.Classification, m.Platform, m.ImageDigest)
}
