// Package contractlock verifies the immutable repository-owned Provider
// Contract consumed by this module.
package contractlock

import (
	"archive/tar"
	"bytes"
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
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/internal/suitedigest"
)

const (
	LockFormatVersion = 2
	maxLockBytes      = 64 << 10
	maxMetadataBytes  = 16 << 20
	maxSnapshotBytes  = 64 << 20
)

var (
	gitObjectPattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	semanticVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	manifestKinds          = map[string]struct{}{
		"specification":     {},
		"openapi":           {},
		"json-schema":       {},
		"semantic-rules":    {},
		"fixture":           {},
		"conformance-suite": {},
	}
)

// Lock identifies one immutable local Contract input set.
type Lock struct {
	FormatVersion       int       `json:"format_version"`
	Source              Source    `json:"source"`
	Contract            Contract  `json:"contract"`
	SandboxSuite        SuiteLock `json:"sandbox_suite"`
	ProviderRemoteSuite SuiteLock `json:"provider_remote_suite"`
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

// SuiteLock identifies one required content-derived Conformance Suite input.
type SuiteLock struct {
	Path               string `json:"path"`
	SuiteID            string `json:"suite_id"`
	SuiteVersion       string `json:"suite_version"`
	SuiteDigest        string `json:"suite_digest"`
	SuiteDigestProfile string `json:"suite_digest_profile"`
	RequiredProfile    string `json:"required_profile"`
}

// SandboxSuite is retained as an alias for callers constructing the local
// Suite lock programmatically.
type SandboxSuite = SuiteLock

type contractManifest struct {
	Namespace string                     `json:"namespace"`
	Version   string                     `json:"version"`
	License   string                     `json:"license"`
	Resources []contractManifestResource `json:"resources"`
}

type contractManifestResource struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Report describes the verified checkout without claiming conformance.
type Report struct {
	LockedRevision    string
	CheckoutHead      string
	ContractTree      string
	ContractNamespace string
	ContractVersion   string
	ManifestDigest    string
	OpenAPISHA256     string
	SuiteDigest       string
	SandboxSuite      VerifiedSuite
	RemoteSuite       VerifiedSuite
	snapshot          verifiedSnapshot
}

type verifiedSnapshot struct {
	lock      Lock
	resources map[string][]byte
}

// VerifiedSuite is the exact locked profile and ordered case snapshot read and
// content-verified by Verify.
type VerifiedSuite struct {
	ID            string
	Version       string
	Digest        string
	DigestProfile string
	ProfileID     string
	Cases         []string
}

// Resource returns a defensive copy of one Contract resource from the exact
// byte snapshot verified against the locked Git tree. The lock argument
// prevents a report produced for one lock from being reused with another.
func (r Report) Resource(lock Lock, relative string) ([]byte, error) {
	if r.snapshot.lock != lock {
		return nil, errors.New("verified Contract snapshot does not match the requested lock")
	}
	if !fs.ValidPath(relative) || relative == "." || !strings.HasPrefix(relative, lock.Contract.Root+"/") {
		return nil, errors.New("requested resource path is outside the verified Contract snapshot")
	}
	document, ok := r.snapshot.resources[relative]
	if !ok {
		return nil, fmt.Errorf("resource %q is absent from the verified Contract snapshot", relative)
	}
	return append([]byte(nil), document...), nil
}

// Load reads and strictly decodes a lock file.
func Load(path string) (Lock, error) {
	document, err := readBoundedRegularFile(path, maxLockBytes)
	if err != nil {
		return Lock{}, fmt.Errorf("read contract lock: %w", err)
	}
	if err := validateUniqueJSONMembers(document); err != nil {
		return Lock{}, fmt.Errorf("decode contract lock: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(document))
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
	if l.FormatVersion != LockFormatVersion {
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
		"contract root":         l.Contract.Root,
		"manifest":              l.Contract.ManifestPath,
		"OpenAPI":               l.Contract.OpenAPIPath,
		"semantic rules":        l.Contract.SemanticRulesPath,
		"fixtures root":         l.Contract.FixturesRoot,
		"Sandbox Suite":         l.SandboxSuite.Path,
		"Provider Remote Suite": l.ProviderRemoteSuite.Path,
	} {
		if !fs.ValidPath(path) || path == "." {
			return fmt.Errorf("%s path must be a clean relative slash path", name)
		}
	}
	for name, path := range map[string]string{
		"manifest":              l.Contract.ManifestPath,
		"OpenAPI":               l.Contract.OpenAPIPath,
		"semantic rules":        l.Contract.SemanticRulesPath,
		"fixtures root":         l.Contract.FixturesRoot,
		"Sandbox Suite":         l.SandboxSuite.Path,
		"Provider Remote Suite": l.ProviderRemoteSuite.Path,
	} {
		if !strings.HasPrefix(path, l.Contract.Root+"/") {
			return fmt.Errorf("%s path must be inside the Contract root", name)
		}
	}
	if l.Contract.Namespace != "urn:shell-echo:sandbox-runtime:provider-v1" {
		return errors.New("unexpected Provider Contract namespace")
	}
	if !semanticVersionPattern.MatchString(l.Contract.Version) {
		return errors.New("Provider Contract version must be semantic version")
	}
	if l.Contract.License != "MIT" {
		return errors.New("Provider Contract must use the repository MIT license")
	}
	for name, digest := range map[string]string{
		"manifest":              l.Contract.ManifestDigest,
		"OpenAPI":               l.Contract.OpenAPISHA256,
		"semantic rules":        l.Contract.SemanticRulesSHA256,
		"Sandbox Suite":         l.SandboxSuite.SuiteDigest,
		"Provider Remote Suite": l.ProviderRemoteSuite.SuiteDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("%s digest must be a lowercase SHA-256 digest", name)
		}
	}
	for name, suite := range map[string]SuiteLock{
		"Sandbox Suite":         l.SandboxSuite,
		"Provider Remote Suite": l.ProviderRemoteSuite,
	} {
		if strings.TrimSpace(suite.SuiteID) == "" || !semanticVersionPattern.MatchString(suite.SuiteVersion) || strings.TrimSpace(suite.RequiredProfile) == "" {
			return fmt.Errorf("%s identity and required profile are required", name)
		}
		if suite.SuiteDigestProfile != suitedigest.DigestProfile {
			return fmt.Errorf("%s digest profile must be %q", name, suitedigest.DigestProfile)
		}
	}
	return nil
}

// Verify confirms that sourceRoot exposes the exact locked Contract content.
// The checkout itself may be a later commit only when its Contract tree is
// unchanged and the Contract path has no worktree modifications.
func Verify(ctx context.Context, lock Lock, sourceRoot string) (Report, error) {
	gitExecutable, err := resolveGitExecutable()
	if err != nil {
		return Report{}, err
	}
	return verifyWithGitExecutable(ctx, lock, sourceRoot, gitExecutable, true)
}

// VerifyWithGitExecutable is Verify with one caller-selected Git executable.
// The executable is resolved to a regular absolute path once and reused for
// every Git operation in this verification.
func VerifyWithGitExecutable(ctx context.Context, lock Lock, sourceRoot, gitExecutable string) (Report, error) {
	return verifyWithGitExecutable(ctx, lock, sourceRoot, gitExecutable, true)
}

// VerifyHistoricalRevision verifies an immutable Contract revision without
// requiring the current checkout's Contract tree to be identical. It is for
// retained evidence definitions that deliberately pin an older authority; new
// compatibility claims must use Verify against the current checkout instead.
func VerifyHistoricalRevision(ctx context.Context, lock Lock, sourceRoot string) (Report, error) {
	gitExecutable, err := resolveGitExecutable()
	if err != nil {
		return Report{}, err
	}
	return verifyWithGitExecutable(ctx, lock, sourceRoot, gitExecutable, false)
}

func verifyWithGitExecutable(ctx context.Context, lock Lock, sourceRoot, gitExecutable string, requireCheckoutMatch bool) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("contract verification context is required")
	}
	gitExecutable, err := validateGitExecutable(gitExecutable)
	if err != nil {
		return Report{}, err
	}
	if err := lock.Validate(); err != nil {
		return Report{}, err
	}
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
	origin, err := git(ctx, gitExecutable, root, "remote", "get-url", "origin")
	if err != nil {
		return Report{}, err
	}
	if normalizeRepository(origin) != normalizeRepository(lock.Source.Repository) {
		return Report{}, fmt.Errorf("checkout origin %q, want %q", origin, lock.Source.Repository)
	}

	lockedRevision, err := git(ctx, gitExecutable, root, "rev-parse", "--verify", lock.Source.Revision+"^{commit}")
	if err != nil {
		return Report{}, err
	}
	if lockedRevision != lock.Source.Revision {
		return Report{}, fmt.Errorf("resolved locked revision %s, want %s", lockedRevision, lock.Source.Revision)
	}
	lockedTree, err := git(ctx, gitExecutable, root, "rev-parse", lock.Source.Revision+":"+lock.Contract.Root)
	if err != nil {
		return Report{}, err
	}
	if lockedTree != lock.Source.ContractTree {
		return Report{}, fmt.Errorf("locked Contract tree %s, want %s", lockedTree, lock.Source.ContractTree)
	}
	checkoutHead, err := git(ctx, gitExecutable, root, "rev-parse", "HEAD")
	if err != nil {
		return Report{}, err
	}
	if requireCheckoutMatch {
		checkoutTree, err := git(ctx, gitExecutable, root, "rev-parse", "HEAD:"+lock.Contract.Root)
		if err != nil {
			return Report{}, err
		}
		if checkoutTree != lock.Source.ContractTree {
			return Report{}, fmt.Errorf("checkout Contract tree %s, want %s", checkoutTree, lock.Source.ContractTree)
		}
		dirty, err := git(ctx, gitExecutable, root, "status", "--porcelain", "--untracked-files=all", "--", lock.Contract.Root)
		if err != nil {
			return Report{}, err
		}
		if dirty != "" {
			return Report{}, fmt.Errorf("checkout Contract path has uncommitted changes: %s", strings.ReplaceAll(dirty, "\n", "; "))
		}
	}

	lockedResources, err := readLockedContractTree(ctx, gitExecutable, root, lock.Source.Revision, lock.Contract.Root)
	if err != nil {
		return Report{}, fmt.Errorf("read locked Contract tree: %w", err)
	}
	manifestData, err := readLockedResource(root, lock.Contract.ManifestPath, maxMetadataBytes, lockedResources, requireCheckoutMatch)
	if err != nil {
		return Report{}, fmt.Errorf("read locked Contract manifest: %w", err)
	}
	manifest, err := decodeContractManifest(manifestData)
	if err != nil {
		return Report{}, fmt.Errorf("read Contract manifest: %w", err)
	}
	if manifest.Namespace != lock.Contract.Namespace || manifest.Version != lock.Contract.Version || manifest.License != lock.Contract.License {
		return Report{}, errors.New("Contract manifest identity does not match the contract lock")
	}
	if requireCheckoutMatch {
		contractRoot, err := securePath(root, lock.Contract.Root)
		if err != nil {
			return Report{}, fmt.Errorf("resolve Contract root: %w", err)
		}
		if err := validateContractManifestResources(contractRoot, manifest.Resources); err != nil {
			return Report{}, err
		}
	} else if err := validateContractManifestResourceDefinitions(manifest.Resources); err != nil {
		return Report{}, err
	}
	resources, err := readLockedManifestResources(root, lock, manifest.Resources, lockedResources, requireCheckoutMatch)
	if err != nil {
		return Report{}, err
	}
	resources[lock.Contract.ManifestPath] = append([]byte(nil), manifestData...)
	if err := requireManifestSuite(manifest.Resources, lock.Contract.Root, lock.SandboxSuite, "Sandbox Suite"); err != nil {
		return Report{}, err
	}
	if err := requireManifestSuite(manifest.Resources, lock.Contract.Root, lock.ProviderRemoteSuite, "Provider Remote Suite"); err != nil {
		return Report{}, err
	}
	manifestDigest := bytesSHA256(manifestData)
	if manifestDigest != lock.Contract.ManifestDigest {
		return Report{}, fmt.Errorf("Contract manifest digest %s, want %s", manifestDigest, lock.Contract.ManifestDigest)
	}

	openAPIData, ok := resources[lock.Contract.OpenAPIPath]
	if !ok {
		return Report{}, errors.New("Provider OpenAPI is absent from the Contract manifest")
	}
	openAPIDigest := bytesSHA256(openAPIData)
	if openAPIDigest != lock.Contract.OpenAPISHA256 {
		return Report{}, fmt.Errorf("Provider OpenAPI digest %s, want %s", openAPIDigest, lock.Contract.OpenAPISHA256)
	}

	var semanticRules struct {
		Namespace string            `json:"namespace"`
		Version   string            `json:"version"`
		Rules     []json.RawMessage `json:"rules"`
	}
	semanticRulesData, ok := resources[lock.Contract.SemanticRulesPath]
	if !ok {
		return Report{}, errors.New("semantic rules are absent from the Contract manifest")
	}
	if err := decodeMetadata(semanticRulesData, &semanticRules); err != nil {
		return Report{}, fmt.Errorf("read semantic rules: %w", err)
	}
	semanticRulesDigest := bytesSHA256(semanticRulesData)
	if semanticRulesDigest != lock.Contract.SemanticRulesSHA256 {
		return Report{}, fmt.Errorf("semantic rules digest %s, want %s", semanticRulesDigest, lock.Contract.SemanticRulesSHA256)
	}
	if semanticRules.Namespace != lock.Contract.Namespace || semanticRules.Version != lock.Contract.Version || len(semanticRules.Rules) == 0 {
		return Report{}, errors.New("semantic rules identity or rules are invalid")
	}
	if requireCheckoutMatch {
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
	}

	sandboxSuiteData, ok := resources[lock.SandboxSuite.Path]
	if !ok {
		return Report{}, errors.New("Sandbox Suite is absent from the verified Contract snapshot")
	}
	sandboxSuite, err := verifyLockedSuiteDocument(sandboxSuiteData, "Sandbox Suite", lock.SandboxSuite, suitedigest.ExecutionModeRepositoryGoTest)
	if err != nil {
		return Report{}, err
	}
	remoteSuiteData, ok := resources[lock.ProviderRemoteSuite.Path]
	if !ok {
		return Report{}, errors.New("Provider Remote Suite is absent from the verified Contract snapshot")
	}
	remoteSuite, err := verifyLockedSuiteDocument(remoteSuiteData, "Provider Remote Suite", lock.ProviderRemoteSuite, suitedigest.ExecutionModeRemoteHTTPBlackBox)
	if err != nil {
		return Report{}, err
	}

	return Report{
		LockedRevision:    lockedRevision,
		CheckoutHead:      checkoutHead,
		ContractTree:      lockedTree,
		ContractNamespace: lock.Contract.Namespace,
		ContractVersion:   lock.Contract.Version,
		ManifestDigest:    manifestDigest,
		OpenAPISHA256:     openAPIDigest,
		SuiteDigest:       sandboxSuite.Digest,
		SandboxSuite:      sandboxSuite,
		RemoteSuite:       remoteSuite,
		snapshot: verifiedSnapshot{
			lock:      lock,
			resources: resources,
		},
	}, nil
}

func verifyLockedSuite(root, name string, locked SuiteLock, executionMode string) (VerifiedSuite, error) {
	path, err := securePath(root, locked.Path)
	if err != nil {
		return VerifiedSuite{}, err
	}
	verified, err := suitedigest.Load(path, locked.SuiteDigestProfile)
	if err != nil {
		return VerifiedSuite{}, fmt.Errorf("read %s: %w", name, err)
	}
	return verifiedSuiteProfile(verified, name, locked, executionMode)
}

func verifyLockedSuiteDocument(document []byte, name string, locked SuiteLock, executionMode string) (VerifiedSuite, error) {
	verified, err := suitedigest.Verify(document, locked.SuiteDigestProfile)
	if err != nil {
		return VerifiedSuite{}, fmt.Errorf("read %s: %w", name, err)
	}
	return verifiedSuiteProfile(verified, name, locked, executionMode)
}

func verifiedSuiteProfile(verified suitedigest.Verified, name string, locked SuiteLock, executionMode string) (VerifiedSuite, error) {
	if verified.SuiteID != locked.SuiteID || verified.SuiteVersion != locked.SuiteVersion || verified.SuiteDigest != locked.SuiteDigest {
		return VerifiedSuite{}, fmt.Errorf("%s identity does not match the contract lock", name)
	}
	profile, err := verified.RequiredProfile(locked.RequiredProfile)
	if err != nil {
		return VerifiedSuite{}, fmt.Errorf("verify %s: %w", name, err)
	}
	if profile.ExecutionMode != executionMode {
		return VerifiedSuite{}, fmt.Errorf("%s required profile execution mode %q, want %q", name, profile.ExecutionMode, executionMode)
	}
	if executionMode == suitedigest.ExecutionModeRemoteHTTPBlackBox && (profile.MutationsPerformed == nil || *profile.MutationsPerformed) {
		return VerifiedSuite{}, fmt.Errorf("%s required profile must explicitly set mutations_performed to false", name)
	}
	return VerifiedSuite{
		ID:            verified.SuiteID,
		Version:       verified.SuiteVersion,
		Digest:        verified.SuiteDigest,
		DigestProfile: verified.SuiteDigestProfile,
		ProfileID:     profile.ProfileID,
		Cases:         append([]string(nil), profile.Tests...),
	}, nil
}

func requireManifestSuite(resources []contractManifestResource, contractRoot string, suite SuiteLock, name string) error {
	relative := strings.TrimPrefix(suite.Path, contractRoot+"/")
	for _, resource := range resources {
		if resource.Path != relative {
			continue
		}
		if resource.Kind != "conformance-suite" {
			return fmt.Errorf("%s manifest resource %q must have kind conformance-suite", name, relative)
		}
		return nil
	}
	return fmt.Errorf("%s path %q is not registered in the Contract manifest", name, suite.Path)
}

func readContractManifest(path string) (contractManifest, error) {
	document, err := readBoundedRegularFile(path, maxMetadataBytes)
	if err != nil {
		return contractManifest{}, err
	}
	return decodeContractManifest(document)
}

func decodeContractManifest(document []byte) (contractManifest, error) {
	if err := validateUniqueJSONMembers(document); err != nil {
		return contractManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest contractManifest
	if err := decoder.Decode(&manifest); err != nil {
		return contractManifest{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return contractManifest{}, err
	}
	return manifest, nil
}

func readLockedManifestResources(root string, lock Lock, resources []contractManifestResource, lockedResources map[string][]byte, verifyWorking bool) (map[string][]byte, error) {
	result := make(map[string][]byte, len(resources)+1)
	total := 0
	for index, resource := range resources {
		relative := lock.Contract.Root + "/" + resource.Path
		document, err := readLockedResource(root, relative, maxMetadataBytes, lockedResources, verifyWorking)
		if err != nil {
			return nil, fmt.Errorf("verify Contract manifest resource %d: %w", index, err)
		}
		total += len(document)
		if total > maxSnapshotBytes {
			return nil, fmt.Errorf("verified Contract resource snapshot exceeds %d bytes", maxSnapshotBytes)
		}
		result[relative] = document
	}
	return result, nil
}

func readLockedResource(root, relative string, maximum int64, lockedResources map[string][]byte, verifyWorking bool) ([]byte, error) {
	expected, ok := lockedResources[relative]
	if !ok {
		return nil, fmt.Errorf("resource %s is absent from the locked Git tree", relative)
	}
	if int64(len(expected)) > maximum {
		return nil, fmt.Errorf("locked resource %s exceeds %d bytes", relative, maximum)
	}
	if !verifyWorking {
		return append([]byte(nil), expected...), nil
	}
	original := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(original)
	if err != nil {
		return nil, fmt.Errorf("inspect working resource %s: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("working resource %s is not a regular file", relative)
	}
	path, err := securePath(root, relative)
	if err != nil {
		return nil, err
	}
	actual, err := readBoundedRegularFile(path, maximum)
	if err != nil {
		return nil, fmt.Errorf("read working resource %s: %w", relative, err)
	}
	if !bytes.Equal(actual, expected) {
		return nil, fmt.Errorf("working resource %s differs from the locked Git blob", relative)
	}
	return actual, nil
}

func readLockedContractTree(ctx context.Context, gitExecutable, root, revision, contractRoot string) (map[string][]byte, error) {
	command := exec.CommandContext(ctx, gitExecutable, "-C", root, "archive", "--format=tar", revision, "--", contractRoot)
	var archive limitedBuffer
	archive.maximum = maxSnapshotBytes + (8 << 20)
	var stderr limitedBuffer
	stderr.maximum = 64 << 10
	command.Stdout = &archive
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("git archive: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	result := make(map[string][]byte)
	total := 0
	reader := tar.NewReader(bytes.NewReader(archive.Bytes()))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read Git Contract archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		if !fs.ValidPath(header.Name) || !strings.HasPrefix(header.Name, contractRoot+"/") || header.Size < 0 || header.Size > maxMetadataBytes {
			return nil, fmt.Errorf("Git Contract archive contains invalid resource %q", header.Name)
		}
		if _, duplicate := result[header.Name]; duplicate {
			return nil, fmt.Errorf("Git Contract archive duplicates resource %q", header.Name)
		}
		document, err := io.ReadAll(io.LimitReader(reader, maxMetadataBytes+1))
		if err != nil || int64(len(document)) != header.Size {
			return nil, fmt.Errorf("read Git Contract resource %q", header.Name)
		}
		total += len(document)
		if total > maxSnapshotBytes {
			return nil, fmt.Errorf("locked Contract resource snapshot exceeds %d bytes", maxSnapshotBytes)
		}
		result[header.Name] = document
	}
	return result, nil
}

type limitedBuffer struct {
	bytes.Buffer
	maximum int
}

func (b *limitedBuffer) Write(document []byte) (int, error) {
	if len(document) > b.maximum-b.Len() {
		return 0, errors.New("bounded command output exceeded")
	}
	return b.Buffer.Write(document)
}

func validateContractManifestResources(contractRoot string, resources []contractManifestResource) error {
	contractRoot, err := filepath.Abs(contractRoot)
	if err != nil {
		return fmt.Errorf("resolve Contract manifest root: %w", err)
	}
	contractRoot, err = filepath.EvalSymlinks(contractRoot)
	if err != nil {
		return fmt.Errorf("resolve Contract manifest root: %w", err)
	}
	if info, err := os.Stat(contractRoot); err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return fmt.Errorf("inspect Contract manifest root: %w", err)
	}
	if err := validateContractManifestResourceDefinitions(resources); err != nil {
		return err
	}
	for index, resource := range resources {
		path, err := securePath(contractRoot, resource.Path)
		if err != nil {
			return fmt.Errorf("resolve Contract manifest resource %d: %w", index, err)
		}
		info, err := os.Lstat(filepath.Join(contractRoot, filepath.FromSlash(resource.Path)))
		if err != nil {
			return fmt.Errorf("inspect Contract manifest resource %d: %w", index, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("Contract manifest resource %d is not a regular file", index)
		}
		if resolvedInfo, err := os.Stat(path); err != nil || !resolvedInfo.Mode().IsRegular() {
			if err == nil {
				err = errors.New("not a regular file")
			}
			return fmt.Errorf("inspect Contract manifest resource %d: %w", index, err)
		}
	}
	return nil
}

func validateContractManifestResourceDefinitions(resources []contractManifestResource) error {
	if len(resources) == 0 {
		return errors.New("Contract manifest resources must not be empty")
	}
	paths := make(map[string]struct{}, len(resources))
	ids := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		if strings.TrimSpace(resource.Path) == "" || strings.TrimSpace(resource.Kind) == "" || strings.TrimSpace(resource.ID) == "" {
			return fmt.Errorf("Contract manifest resource %d path, kind, and id must not be empty", index)
		}
		if !fs.ValidPath(resource.Path) || resource.Path == "." {
			return fmt.Errorf("Contract manifest resource %d path must be a clean relative slash path", index)
		}
		if _, ok := manifestKinds[resource.Kind]; !ok {
			return fmt.Errorf("Contract manifest resource %d has unsupported kind %q", index, resource.Kind)
		}
		if _, duplicate := paths[resource.Path]; duplicate {
			return fmt.Errorf("Contract manifest resource %d duplicates path %q", index, resource.Path)
		}
		paths[resource.Path] = struct{}{}
		if _, duplicate := ids[resource.ID]; duplicate {
			return fmt.Errorf("Contract manifest resource %d duplicates id %q", index, resource.ID)
		}
		ids[resource.ID] = struct{}{}
	}
	return nil
}

func git(ctx context.Context, gitExecutable, root string, arguments ...string) (string, error) {
	args := append([]string{"-C", root}, arguments...)
	command := exec.CommandContext(ctx, gitExecutable, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func resolveGitExecutable() (string, error) {
	executable, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("resolve Git executable: %w", err)
	}
	return validateGitExecutable(executable)
}

func validateGitExecutable(executable string) (string, error) {
	if !filepath.IsAbs(executable) {
		return "", errors.New("Git executable must resolve to an absolute path")
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve Git executable path: %w", err)
	}
	if !filepath.IsAbs(resolved) {
		return "", errors.New("Git executable symlink must resolve to an absolute path")
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect Git executable: %w", err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", errors.New("Git executable must be a regular executable")
	}
	return resolved, nil
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

func decodeMetadata(document []byte, destination any) error {
	if err := validateUniqueJSONMembers(document); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func validateUniqueJSONMembers(document []byte) error {
	if !utf8.Valid(document) {
		return errors.New("JSON must be valid UTF-8")
	}
	if err := validateJSONUnicodeEscapes(document); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err == nil {
		return errors.New("JSON contains multiple values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func validateJSONUnicodeEscapes(document []byte) error {
	inString := false
	for index := 0; index < len(document); index++ {
		switch document[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(document) {
				continue
			}
			if document[index+1] != 'u' {
				index++
				continue
			}
			codePoint, ok := decodeJSONHexQuad(document, index+2)
			if !ok {
				continue
			}
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if index+11 >= len(document) || document[index+6] != '\\' || document[index+7] != 'u' {
					return errors.New("JSON contains an invalid Unicode surrogate escape")
				}
				low, ok := decodeJSONHexQuad(document, index+8)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("JSON contains an invalid Unicode surrogate escape")
				}
				index += 11
			case codePoint >= 0xdc00 && codePoint <= 0xdfff:
				return errors.New("JSON contains an invalid Unicode surrogate escape")
			default:
				index += 5
			}
		}
	}
	return nil
}

func decodeJSONHexQuad(document []byte, start int) (uint16, bool) {
	if start+4 > len(document) {
		return 0, false
	}
	var value uint16
	for _, digit := range document[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object member")
			}
			if _, duplicate := members[key]; duplicate {
				return fmt.Errorf("duplicate JSON object member %q", key)
			}
			members[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, ']')
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func consumeJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > limit {
		return nil, errors.New("regular file changed while opening")
	}
	document, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(document)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return document, nil
}

func bytesSHA256(document []byte) string {
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
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
