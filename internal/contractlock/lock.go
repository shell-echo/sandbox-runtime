// Package contractlock verifies the immutable repository-owned Provider
// Contract consumed by this module.
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

// Lock identifies one immutable local Contract input set.
type Lock struct {
	FormatVersion int          `json:"format_version"`
	Source        Source       `json:"source"`
	Contract      Contract     `json:"contract"`
	SandboxSuite  SandboxSuite `json:"sandbox_suite"`
}

// Source identifies the Git repository and Contract tree that owns the
// Contract. The verifier permits later commits only when this tree is unchanged.
type Source struct {
	Repository   string `json:"repository"`
	Revision     string `json:"revision"`
	ContractTree string `json:"contract_tree"`
}

// Contract identifies the repository-owned manifest, OpenAPI, and semantic
// resources.
type Contract struct {
	Root                string `json:"root"`
	Namespace           string `json:"namespace"`
	Version             string `json:"version"`
	License             string `json:"license"`
	ManifestPath        string `json:"manifest_path"`
	ManifestDigest      string `json:"manifest_digest"`
	OpenAPIPath         string `json:"openapi_path"`
	OpenAPISHA256       string `json:"openapi_sha256"`
	SemanticRulesPath   string `json:"semantic_rules_path"`
	SemanticRulesSHA256 string `json:"semantic_rules_sha256"`
	FixturesRoot        string `json:"fixtures_root"`
}

// SandboxSuite identifies the required local conformance input.
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
		"contract root":  l.Contract.Root,
		"manifest":       l.Contract.ManifestPath,
		"OpenAPI":        l.Contract.OpenAPIPath,
		"semantic rules": l.Contract.SemanticRulesPath,
		"fixtures root":  l.Contract.FixturesRoot,
		"Sandbox Suite":  l.SandboxSuite.Path,
	} {
		if !fs.ValidPath(path) || path == "." {
			return fmt.Errorf("%s path must be a clean relative slash path", name)
		}
	}
	for name, path := range map[string]string{
		"manifest":       l.Contract.ManifestPath,
		"OpenAPI":        l.Contract.OpenAPIPath,
		"semantic rules": l.Contract.SemanticRulesPath,
		"fixtures root":  l.Contract.FixturesRoot,
		"Sandbox Suite":  l.SandboxSuite.Path,
	} {
		if !strings.HasPrefix(path, l.Contract.Root+"/") {
			return fmt.Errorf("%s path must be inside the Contract root", name)
		}
	}
	if l.Contract.Namespace != "urn:shell-echo:sandbox-runtime:provider-v1" {
		return errors.New("unexpected Provider Contract namespace")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(l.Contract.Version) {
		return errors.New("Provider Contract version must be semantic version")
	}
	if l.Contract.License != "MIT" {
		return errors.New("Provider Contract must use the repository MIT license")
	}
	for name, digest := range map[string]string{
		"manifest":       l.Contract.ManifestDigest,
		"OpenAPI":        l.Contract.OpenAPISHA256,
		"semantic rules": l.Contract.SemanticRulesSHA256,
		"Sandbox Suite":  l.SandboxSuite.SuiteDigest,
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
		Namespace string `json:"namespace"`
		Version   string `json:"version"`
		License   string `json:"license"`
	}
	if err := readMetadata(manifestPath, &manifest); err != nil {
		return Report{}, fmt.Errorf("read Contract manifest: %w", err)
	}
	if manifest.Namespace != lock.Contract.Namespace || manifest.Version != lock.Contract.Version || manifest.License != lock.Contract.License {
		return Report{}, errors.New("Contract manifest identity does not match the contract lock")
	}
	manifestDigest, err := fileSHA256(manifestPath)
	if err != nil {
		return Report{}, fmt.Errorf("hash Contract manifest: %w", err)
	}
	if manifestDigest != lock.Contract.ManifestDigest {
		return Report{}, fmt.Errorf("Contract manifest digest %s, want %s", manifestDigest, lock.Contract.ManifestDigest)
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

	semanticRulesPath, err := securePath(root, lock.Contract.SemanticRulesPath)
	if err != nil {
		return Report{}, err
	}
	var semanticRules struct {
		Namespace string            `json:"namespace"`
		Version   string            `json:"version"`
		Rules     []json.RawMessage `json:"rules"`
	}
	if err := readMetadata(semanticRulesPath, &semanticRules); err != nil {
		return Report{}, fmt.Errorf("read semantic rules: %w", err)
	}
	semanticRulesDigest, err := fileSHA256(semanticRulesPath)
	if err != nil {
		return Report{}, fmt.Errorf("hash semantic rules: %w", err)
	}
	if semanticRulesDigest != lock.Contract.SemanticRulesSHA256 {
		return Report{}, fmt.Errorf("semantic rules digest %s, want %s", semanticRulesDigest, lock.Contract.SemanticRulesSHA256)
	}
	if semanticRules.Namespace != lock.Contract.Namespace || semanticRules.Version != lock.Contract.Version || len(semanticRules.Rules) == 0 {
		return Report{}, errors.New("semantic rules identity or rules are invalid")
	}
	fixturesRoot, err := securePath(root, lock.Contract.FixturesRoot)
	if err != nil {
		return Report{}, err
	}
	if info, err := os.Stat(fixturesRoot); err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return Report{}, fmt.Errorf("inspect Contract fixtures: %w", err)
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
		ManifestDigest: manifestDigest,
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
	repository = strings.TrimSpace(repository)
	if strings.HasPrefix(repository, "git@") {
		if separator := strings.IndexByte(repository, ':'); separator > 0 {
			repository = "https://" + repository[4:separator] + "/" + repository[separator+1:]
		}
	}
	repository = strings.TrimSuffix(strings.TrimSuffix(repository, "/"), ".git")
	return strings.TrimPrefix(repository, "https://")
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
