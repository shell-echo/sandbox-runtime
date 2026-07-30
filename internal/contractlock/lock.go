// Package contractlock verifies the immutable Agent Platform Contract inputs
// consumed by this repository without copying those resources into this module.
package contractlock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxLockBytes     = 64 << 10
	maxMetadataBytes = 16 << 20
)

var (
	gitObjectPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Lock identifies one immutable upstream Contract input set.
type Lock struct {
	FormatVersion int          `json:"format_version"`
	Source        Source       `json:"source"`
	Contract      Contract     `json:"contract"`
	SandboxSuite  SandboxSuite `json:"sandbox_suite"`
}

// Source identifies the upstream Git repository and Contract tree.
type Source struct {
	Repository   string `json:"repository"`
	Revision     string `json:"revision"`
	ContractTree string `json:"contract_tree"`
}

// Contract identifies the upstream manifest and Provider OpenAPI.
type Contract struct {
	Root           string `json:"root"`
	License        string `json:"license"`
	Consumption    string `json:"consumption"`
	ManifestPath   string `json:"manifest_path"`
	ManifestDigest string `json:"manifest_digest"`
	OpenAPIPath    string `json:"openapi_path"`
	OpenAPISHA256  string `json:"openapi_sha256"`
}

// SandboxSuite identifies the required upstream conformance input.
type SandboxSuite struct {
	Path            string `json:"path"`
	SuiteID         string `json:"suite_id"`
	SuiteVersion    string `json:"suite_version"`
	SuiteDigest     string `json:"suite_digest"`
	RequiredProfile string `json:"required_profile"`
}

// Report describes the verified checkout without claiming conformance.
type Report struct {
	LockedRevision string
	CheckoutHead   string
	ContractTree   string
	ManifestDigest string
	OpenAPISHA256  string
	SuiteDigest    string
}

// Load reads and strictly decodes a lock file.
func Load(path string) (Lock, error) {
	file, err := os.Open(path)
	if err != nil {
		return Lock{}, fmt.Errorf("open contract lock: %w", err)
	}
	defer file.Close()
	if err := checkFileSize(file, maxLockBytes); err != nil {
		return Lock{}, fmt.Errorf("inspect contract lock: %w", err)
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var lock Lock
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("decode contract lock: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Lock{}, err
	}
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

// Validate checks the lock's closed metadata and path constraints.
func (l Lock) Validate() error {
	if l.FormatVersion != 1 {
		return fmt.Errorf("unsupported contract lock format %d", l.FormatVersion)
	}
	repositoryURL, err := url.Parse(l.Source.Repository)
	if err != nil || repositoryURL.Scheme != "https" || repositoryURL.Host == "" {
		return errors.New("contract source repository must be an absolute HTTPS URL")
	}
	if !gitObjectPattern.MatchString(l.Source.Revision) {
		return errors.New("contract source revision must be a full lowercase Git object ID")
	}
	if !gitObjectPattern.MatchString(l.Source.ContractTree) {
		return errors.New("contract source tree must be a full lowercase Git object ID")
	}
	for name, path := range map[string]string{
		"contract root": l.Contract.Root,
		"manifest":      l.Contract.ManifestPath,
		"OpenAPI":       l.Contract.OpenAPIPath,
		"Sandbox Suite": l.SandboxSuite.Path,
	} {
		if !fs.ValidPath(path) || path == "." {
			return fmt.Errorf("%s path must be a clean relative slash path", name)
		}
	}
	for name, path := range map[string]string{
		"manifest":      l.Contract.ManifestPath,
		"OpenAPI":       l.Contract.OpenAPIPath,
		"Sandbox Suite": l.SandboxSuite.Path,
	} {
		if !strings.HasPrefix(path, l.Contract.Root+"/") {
			return fmt.Errorf("%s path must be inside the Contract root", name)
		}
	}
	if l.Contract.License != "LicenseRef-Proprietary" {
		return errors.New("unexpected upstream Contract license")
	}
	if l.Contract.Consumption != "read-only-checkout" {
		return errors.New("upstream Contract must use read-only-checkout consumption")
	}
	for name, digest := range map[string]string{
		"manifest":      l.Contract.ManifestDigest,
		"OpenAPI":       l.Contract.OpenAPISHA256,
		"Sandbox Suite": l.SandboxSuite.SuiteDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("%s digest must be a lowercase SHA-256 digest", name)
		}
	}
	if l.SandboxSuite.SuiteID == "" || l.SandboxSuite.SuiteVersion == "" || l.SandboxSuite.RequiredProfile == "" {
		return errors.New("Sandbox Suite identity and required profile are required")
	}
	return nil
}

// Verify confirms that sourceRoot exposes the exact locked Contract content.
// The checkout itself may be a later commit only when its Contract tree is
// unchanged and the Contract path has no worktree modifications.
func Verify(ctx context.Context, lock Lock, sourceRoot string) (Report, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return Report{}, fmt.Errorf("resolve source root: %w", err)
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return Report{}, fmt.Errorf("inspect source root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Report{}, fmt.Errorf("resolve source root: %w", err)
	}
	origin, err := git(ctx, root, "remote", "get-url", "origin")
	if err != nil {
		return Report{}, err
	}
	if normalizeRepository(origin) != normalizeRepository(lock.Source.Repository) {
		return Report{}, fmt.Errorf("checkout origin %q, want %q", origin, lock.Source.Repository)
	}

	lockedRevision, err := git(ctx, root, "rev-parse", "--verify", lock.Source.Revision+"^{commit}")
	if err != nil {
		return Report{}, err
	}
	if lockedRevision != lock.Source.Revision {
		return Report{}, fmt.Errorf("resolved locked revision %s, want %s", lockedRevision, lock.Source.Revision)
	}
	lockedTree, err := git(ctx, root, "rev-parse", lock.Source.Revision+":"+lock.Contract.Root)
	if err != nil {
		return Report{}, err
	}
	if lockedTree != lock.Source.ContractTree {
		return Report{}, fmt.Errorf("locked Contract tree %s, want %s", lockedTree, lock.Source.ContractTree)
	}
	checkoutHead, err := git(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return Report{}, err
	}
	checkoutTree, err := git(ctx, root, "rev-parse", "HEAD:"+lock.Contract.Root)
	if err != nil {
		return Report{}, err
	}
	if checkoutTree != lock.Source.ContractTree {
		return Report{}, fmt.Errorf("checkout Contract tree %s, want %s", checkoutTree, lock.Source.ContractTree)
	}
	dirty, err := git(ctx, root, "status", "--porcelain", "--untracked-files=all", "--", lock.Contract.Root)
	if err != nil {
		return Report{}, err
	}
	if dirty != "" {
		return Report{}, fmt.Errorf("checkout Contract path has uncommitted changes: %s", strings.ReplaceAll(dirty, "\n", "; "))
	}

	manifestPath, err := securePath(root, lock.Contract.ManifestPath)
	if err != nil {
		return Report{}, err
	}
	var manifest struct {
		ManifestDigest string `json:"manifest_digest"`
	}
	if err := readMetadata(manifestPath, &manifest); err != nil {
		return Report{}, fmt.Errorf("read Contract manifest: %w", err)
	}
	if manifest.ManifestDigest != lock.Contract.ManifestDigest {
		return Report{}, fmt.Errorf("Contract manifest digest %s, want %s", manifest.ManifestDigest, lock.Contract.ManifestDigest)
	}

	openAPIPath, err := securePath(root, lock.Contract.OpenAPIPath)
	if err != nil {
		return Report{}, err
	}
	openAPIDigest, err := fileSHA256(openAPIPath)
	if err != nil {
		return Report{}, fmt.Errorf("hash Provider OpenAPI: %w", err)
	}
	if openAPIDigest != lock.Contract.OpenAPISHA256 {
		return Report{}, fmt.Errorf("Provider OpenAPI digest %s, want %s", openAPIDigest, lock.Contract.OpenAPISHA256)
	}

	suitePath, err := securePath(root, lock.SandboxSuite.Path)
	if err != nil {
		return Report{}, err
	}
	var suite struct {
		SuiteID      string `json:"suite_id"`
		SuiteVersion string `json:"suite_version"`
		SuiteDigest  string `json:"suite_digest"`
		Profiles     []struct {
			ProfileID string `json:"profile_id"`
		} `json:"profiles"`
	}
	if err := readMetadata(suitePath, &suite); err != nil {
		return Report{}, fmt.Errorf("read Sandbox Suite: %w", err)
	}
	if suite.SuiteID != lock.SandboxSuite.SuiteID || suite.SuiteVersion != lock.SandboxSuite.SuiteVersion || suite.SuiteDigest != lock.SandboxSuite.SuiteDigest {
		return Report{}, errors.New("Sandbox Suite identity does not match the contract lock")
	}
	profileFound := false
	for _, profile := range suite.Profiles {
		if profile.ProfileID == lock.SandboxSuite.RequiredProfile {
			profileFound = true
			break
		}
	}
	if !profileFound {
		return Report{}, fmt.Errorf("Sandbox Suite is missing required profile %q", lock.SandboxSuite.RequiredProfile)
	}

	return Report{
		LockedRevision: lockedRevision,
		CheckoutHead:   checkoutHead,
		ContractTree:   checkoutTree,
		ManifestDigest: manifest.ManifestDigest,
		OpenAPISHA256:  openAPIDigest,
		SuiteDigest:    suite.SuiteDigest,
	}, nil
}

func git(ctx context.Context, root string, arguments ...string) (string, error) {
	args := append([]string{"-C", root}, arguments...)
	command := exec.CommandContext(ctx, "git", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func securePath(root, relative string) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(relative))
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", relative, err)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %s escapes the source root", relative)
	}
	return resolved, nil
}

func normalizeRepository(repository string) string {
	return strings.TrimSuffix(strings.TrimSuffix(repository, "/"), ".git")
}

func readMetadata(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := checkFileSize(file, maxMetadataBytes); err != nil {
		return err
	}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := checkFileSize(file, maxMetadataBytes); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func checkFileSize(file *os.File, limit int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if info.Size() > limit {
		return fmt.Errorf("file exceeds %d bytes", limit)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode JSON trailer: %w", err)
	}
	return errors.New("JSON contains multiple values")
}
