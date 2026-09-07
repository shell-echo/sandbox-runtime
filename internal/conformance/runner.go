// Package conformance executes the repository-owned Provider Contract Suite.
package conformance

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
)

// Options controls the test process used for each locked Suite case.
type Options struct {
	SourceRoot string
	Race       bool
	Shuffle    bool
}

// Report records the exact Suite profile and cases that were executed.
type Report struct {
	SuiteID            string
	SuiteVersion       string
	SuiteDigest        string
	SuiteDigestProfile string
	ProfileID          string
	RunnerRevision     string
	GoToolchain        string
	GitVersion         string
	EvidenceBoundary   string
	Race               bool
	Shuffle            bool
	Cases              []string
}

type testCase struct {
	Package         string
	Run             string
	ExpectedMatches int
}

type runnerIdentity struct {
	revision  string
	toolchain string
}

type goTestEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

type goTestEvidence struct {
	started         map[string]struct{}
	passed          map[string]struct{}
	terminal        map[string]string
	expected        *regexp.Regexp
	expectedMatches int
	packagePassed   bool
	packageFailed   bool
}

const (
	defaultLockPath           = "compatibility/sandbox-runtime/contract.lock.json"
	maxRunnerArchiveEntries   = 8192
	maxRunnerArchiveFileBytes = 32 << 20
	maxRunnerArchiveBytes     = 64 << 20
	maxRunnerArchivePathBytes = 4096
	maxGitStderrBytes         = 64 << 10
	maxToolchainOutputBytes   = 4 << 10
	localEvidenceBoundary     = "host OS, filesystem, initial Git selection, and Go and Git executables are trusted local inputs; path and self-reported version checks do not attest their integrity"
)

// The IDs are Contract-owned. The package/test mapping is local execution
// plumbing and is deliberately kept outside the Contract resources.
var testCases = map[string]testCase{
	"capability-discovery-mtls-only": {
		Package: "./providerapi",
		Run:     `^TestServerServesCapabilitiesOnlyAfterMTLSAdmission$`,
	},
	"capability-discovery-admitted-identity": {
		Package:         "./providerapi",
		Run:             `^TestLoadMTLSConfig(AdmitsExactVerifiedURI|RejectsCertificateFailures)$`,
		ExpectedMatches: 2,
	},
	"capability-discovery-immutable-schema": {
		Package:         "./providerapi",
		Run:             `^(TestLockedCapabilityResponseSchema|TestCapabilitiesHandlerReadsSourceOnceAndFreezesResponse)$`,
		ExpectedMatches: 2,
	},
	"capability-discovery-terminal-profile-advertisement": {
		Package: "./providerapi",
		Run:     `^TestMapCapabilitiesProjectsTerminalAdvertisement$`,
	},
	"capability-discovery-terminal-session-contract-consistency": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedTerminalSessionContractConsistency$`,
	},
	"capability-discovery-coding-shell-profile-advertisement": {
		Package: "./providerapi",
		Run:     `^TestMapCapabilitiesProjectsCodingShellAdvertisement$`,
	},
	"capability-discovery-coding-shell-contract-consistency": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedCodingShellContractConsistency$`,
	},
	"capability-discovery-coding-shell-rejection-fixtures": {
		Package: "./providerapi",
		Run:     `^TestCodingShellCapabilityRejectionFixtures$`,
	},
	"capability-discovery-browser-profile-advertisement": {
		Package: "./providerapi",
		Run:     `^TestMapCapabilitiesProjectsBrowserAdvertisement$`,
	},
	"capability-discovery-browser-contract-consistency": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedBrowserCapabilityContractConsistency$`,
	},
	"capability-discovery-browser-rejection-fixtures": {
		Package: "./providerapi",
		Run:     `^TestBrowserCapabilityRejectionFixtures$`,
	},
	"capability-discovery-empty-request": {
		Package:         "./providerapi",
		Run:             `^(TestCapabilitiesHandlerRejectsRequestsWithoutADocumentBeforeDispatch|TestProviderServerReconcilesHTTP11CapabilityInputTransport)$`,
		ExpectedMatches: 2,
	},
	"capability-discovery-no-mutation-routes": {
		Package: "./providerapi",
		Run:     `^TestCapabilitiesHandlerRejectsMethodsAndAbsentRoutesWithoutSourceReads$`,
	},
	"protected-admission-context-schema": {
		Package:         "./provider/admission",
		Run:             `^(TestDecodeAdmissionContextCarrierEnforcesSchemaBounds|TestDecodeAdmissionContextCarrierRejectsCarrierAndDocumentConfusion)$`,
		ExpectedMatches: 2,
	},
	"protected-admission-jws-profile-schema": {
		Package:         "./provider/admission",
		Run:             `^(TestLocalContractProtectedAdmissionJWSProfile|TestLocalContractProtectedAdmissionJWSProfileRejectsRetiredWireProfile|TestVerifyCompactJWSRejectsClosedHeaderAndSignatureFailures|TestVerifyCompactJWSRejectsClosedClaimFailures|TestValidateTokenBindingRejectsInvalidTokenLifetime)$`,
		ExpectedMatches: 5,
	},
	"protected-admission-issuer-local-authority-binding": {
		Package:         "./provider/admission",
		Run:             `^(TestLocalContractProtectedAdmissionIssuerLocalAuthorityBinding|TestNewAdmissionAuthorityAcceptsExactGenericIssuer|TestNewAdmissionAuthorityAcceptsExplicitLegacyStringOrURI|TestNewAdmissionAuthorityRejectsInvalidValues|TestVerifyCompactJWSRejectsTrustedIssuerSubstitution|TestVerifyCompactJWSSupportsOverlappingRotationKeys|TestProtectedOperationGateRejectsTrustedIssuerSubstitutionAsUnauthenticated|TestProtectedOperationGateRejectsLocalAuthorityMismatchBeforeGuard|TestValidateTokenBindingRejectsMismatchedContext)$`,
		ExpectedMatches: 9,
	},
	"protected-admission-token-binding": {
		Package:         "./provider/admission",
		Run:             `^(TestValidateTokenBindingRejectsMismatchedContext|TestVerifyCompactJWSRequiresEachOperationBinding)$`,
		ExpectedMatches: 2,
	},
	"protected-admission-digest-substitution": {
		Package: "./providerapi",
		Run:     `^TestProtectedHandlerRejectsRequestDescriptorSubstitutionAcrossAllRoutes$`,
	},
	"protected-admission-expiry": {
		Package:         "./providerapi",
		Run:             `^(TestProtectedHandlerRejectsInactiveBearerAcrossAllRoutes|TestProtectedHandlerMapsBearerExpiryDuringDocumentReadToUnauthorized)$`,
		ExpectedMatches: 2,
	},
	"protected-admission-replay-and-fencing": {
		Package:         "./providerapi",
		Run:             `^(TestProtectedHandlerRejectsDigestConsistentCreateAndSessionDocumentsBeforeGuard|TestProtectedHandlerRejectsOversizedCreateAndSessionDocumentsBeforeGuard|TestProtectedHandlerRejectsReplayAndStaleFencingAcrossAllMutations)$`,
		ExpectedMatches: 3,
	},
	"lifecycle-create-request-schema": {
		Package:         "./providerapi",
		Run:             `^(TestDecodeCreateRequestProjectsOnlyAdmittedProviderFields|TestDecodeCreateRequestRejectsUnsupportedCapabilitiesAndContextSubstitution|TestLifecycleProjectionsMatchLockedSchemas)$`,
		ExpectedMatches: 3,
	},
	"lifecycle-operation-state-schema": {
		Package:         "./providerapi",
		Run:             `^(TestLifecycleProjectionsAreBoundedAndOpaque|TestLifecycleProjectionsMatchLockedSchemas)$`,
		ExpectedMatches: 2,
	},
	"lifecycle-idempotency-generation-fencing": {
		Package:         "./provider/lifecycle/coordinator",
		Run:             `^(TestAcceptCreateIsDurableAndIdempotent|TestStaleGenerationPreventsDriverDispatch|TestConcurrentReconcileSerializesDispatch)$`,
		ExpectedMatches: 3,
	},
	"lifecycle-deadline-outcome": {
		Package:         "./provider/lifecycle/coordinator",
		Run:             `^(TestKnownFailureAndDeadlineDoNotDispatch|TestCanceledContextDoesNotDispatch|TestCreateUnknownOutcomeIsNotRetriedBlindlyAndReconcilesByInspection|TestRestartedRunningOperationIsReconciledWithoutDuplicateCreate)$`,
		ExpectedMatches: 4,
	},
	"exec-request-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedExecRequestProjection$`,
	},
	"exec-cancel-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedCancelExecRequestProjection$`,
	},
	"exec-result-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedExecResultProjection$`,
	},
	"exec-semantic-bounds": {
		Package: "./providerapi/v1",
		Run:     `^TestLocalContractExecSemanticRules$`,
	},
	"exec-rejection-fixtures": {
		Package: "./providerapi/v1",
		Run:     `^TestExecRejectionFixtures$`,
	},
	"runtime-session-open-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedRuntimeSessionOpenRequestProjection$`,
	},
	"runtime-session-operation-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedRuntimeSessionOperationProjection$`,
	},
	"runtime-session-handoff-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedRuntimeSessionHandoffProjection$`,
	},
	"runtime-session-semantic-bounds": {
		Package: "./providerapi/v1",
		Run:     `^TestLocalContractRuntimeSessionSemanticRules$`,
	},
	"runtime-session-rejection-fixtures": {
		Package: "./providerapi/v1",
		Run:     `^TestRuntimeSessionRejectionFixtures$`,
	},
	"browser-session-open-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedBrowserSessionOpenRequestProjection$`,
	},
	"browser-session-operation-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedBrowserSessionOperationProjection$`,
	},
	"browser-session-handoff-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedBrowserSessionHandoffProjection$`,
	},
	"browser-session-semantic-bounds": {
		Package:         "./providerapi/v1",
		Run:             `^(TestLocalContractBrowserSessionSemanticRules|TestLocalContractBrowserSessionSecurityMatrix)$`,
		ExpectedMatches: 2,
	},
	"browser-session-rejection-fixtures": {
		Package: "./providerapi/v1",
		Run:     `^TestBrowserSessionRejectionFixtures$`,
	},
	"browser-session-usage-evidence": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedBrowserSessionUsageEvidenceProjection$`,
	},
	"browser-session-protected-admission-bindings": {
		Package: "./provider/admission",
		Run:     `^TestLocalContractBrowserSessionAdmissionBindings$`,
	},
	"artifact-staging-request-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedArtifactAndUsageProjection/artifact-staging-request\.json$`,
	},
	"artifact-staging-evidence-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedArtifactAndUsageProjection/artifact-staging-evidence\.json$`,
	},
	"artifact-staging-semantic-bounds": {
		Package: "./providerapi/v1",
		Run:     `^TestLocalContractArtifactAndUsageSemanticRules$`,
	},
	"artifact-staging-rejection-fixtures": {
		Package: "./providerapi/v1",
		Run:     `^TestArtifactStagingRejectionFixtures$`,
	},
	"usage-evidence-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedArtifactAndUsageProjection/usage-evidence\.json$`,
	},
	"usage-evidence-semantic-bounds": {
		Package: "./providerapi/v1",
		Run:     `^TestLocalContractArtifactAndUsageSemanticRules$`,
	},
	"artifact-usage-protected-admission-bindings": {
		Package: "./provider/admission",
		Run:     `^TestLocalContractArtifactUsageAdmissionBindings$`,
	},
	"artifact-operation-read-schema": {
		Package: "./providerapi/v1",
		Run:     `^TestLockedArtifactOperationReadProjection$`,
	},
	"artifact-usage-read-state-matrix": {
		Package: "./providerapi/v1",
		Run:     `^TestLocalContractArtifactUsageReadStateMatrix$`,
	},
}

// Run verifies the locked local Contract and executes every case in its
// required Suite profile. It never downloads or reads an external Contract.
func Run(ctx context.Context, options Options, stdout, stderr io.Writer) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("context is required")
	}
	identity, err := loadRunnerIdentity(debug.ReadBuildInfo)
	if err != nil {
		return Report{}, err
	}
	root, err := filepath.Abs(options.SourceRoot)
	if err != nil {
		return Report{}, fmt.Errorf("resolve source root: %w", err)
	}
	testEnvironment := withSourceRootEnv(root)
	goTool, err := resolveGoToolchain(ctx, identity.toolchain, testEnvironment)
	if err != nil {
		return Report{}, err
	}
	gitTool, gitVersion, err := resolveGitToolchain(ctx, testEnvironment)
	if err != nil {
		return Report{}, err
	}
	lockPath := filepath.Join(root, filepath.FromSlash(defaultLockPath))
	lock, err := contractlock.Load(lockPath)
	if err != nil {
		return Report{}, err
	}
	verified, err := contractlock.VerifyWithGitExecutable(ctx, lock, root, gitTool)
	if err != nil {
		return Report{}, fmt.Errorf("verify locked Provider Contract: %w", err)
	}
	suite := verified.SandboxSuite
	if err := validateCases(suite.Cases); err != nil {
		return Report{}, err
	}
	executionRoot, err := prepareRunnerSource(ctx, gitTool, root, identity.revision)
	if err != nil {
		return Report{}, fmt.Errorf("prepare runner source snapshot: %w", err)
	}
	defer cleanupRunnerSource(executionRoot)

	report := Report{
		SuiteID: suite.ID, SuiteVersion: suite.Version,
		SuiteDigest: suite.Digest, SuiteDigestProfile: suite.DigestProfile,
		ProfileID: suite.ProfileID, RunnerRevision: identity.revision,
		GoToolchain: identity.toolchain, GitVersion: gitVersion,
		EvidenceBoundary: localEvidenceBoundary,
		Race:             options.Race, Shuffle: options.Shuffle,
		Cases: append([]string(nil), suite.Cases...),
	}
	for _, id := range suite.Cases {
		caseSpec := testCases[id]
		args := []string{"test", "-json", "-mod=readonly", "-count=1"}
		if options.Race {
			args = append(args, "-race")
		}
		if options.Shuffle {
			args = append(args, "-shuffle=on")
		}
		args = append(args, caseSpec.Package, "-run", caseSpec.Run)
		command := exec.CommandContext(ctx, goTool, args...)
		command.Dir = executionRoot
		command.Env = testEnvironment
		if err := runGoTestCommand(ctx, command, caseSpec.Run, caseSpec.expectedMatches(), stdout, stderr); err != nil {
			return Report{}, fmt.Errorf("Suite case %q failed: %w", id, err)
		}
	}
	return report, nil
}

func resolveGoToolchain(ctx context.Context, expectedVersion string, environment []string) (string, error) {
	if ctx == nil {
		return "", errors.New("Go toolchain context is required")
	}
	if _, explicit := os.LookupEnv("GOROOT"); explicit {
		return "", errors.New("Runner requires GOROOT to be unset")
	}
	executableName := "go"
	if runtime.GOOS == "windows" {
		executableName += ".exe"
	}
	executable := filepath.Join(runtime.GOROOT(), "bin", executableName)
	if !filepath.IsAbs(executable) {
		return "", errors.New("Runner GOROOT does not identify an absolute Go toolchain path")
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return "", fmt.Errorf("inspect Runner Go toolchain: %w", err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", errors.New("Runner Go toolchain must be a regular executable")
	}

	command := exec.CommandContext(ctx, executable, "env", "GOVERSION")
	command.Env = environment
	var stdout boundedOutput
	stdout.maximum = maxToolchainOutputBytes
	var stderr boundedOutput
	stderr.maximum = maxToolchainOutputBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return "", fmt.Errorf("inspect Go toolchain version: %w", contextErr)
		}
		return "", fmt.Errorf("inspect Go toolchain version: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	version := strings.TrimSpace(stdout.String())
	if version == "" || strings.ContainsAny(version, "\r\n") {
		return "", errors.New("Runner Go toolchain returned an invalid version")
	}
	if version != expectedVersion {
		return "", fmt.Errorf("Runner Go toolchain version %q does not match build version %q", version, expectedVersion)
	}
	return executable, nil
}

func resolveGitToolchain(ctx context.Context, environment []string) (string, string, error) {
	if ctx == nil {
		return "", "", errors.New("Git toolchain context is required")
	}
	executable, err := exec.LookPath("git")
	if err != nil {
		return "", "", fmt.Errorf("resolve Runner Git executable: %w", err)
	}
	if !filepath.IsAbs(executable) {
		return "", "", errors.New("Runner Git executable did not resolve to an absolute path")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", "", fmt.Errorf("resolve Runner Git executable path: %w", err)
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return "", "", fmt.Errorf("inspect Runner Git executable: %w", err)
	}
	if !filepath.IsAbs(executable) || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", "", errors.New("Runner Git executable must be a regular absolute executable")
	}

	command := exec.CommandContext(ctx, executable, "--version")
	command.Env = environment
	var stdout boundedOutput
	stdout.maximum = maxToolchainOutputBytes
	var stderr boundedOutput
	stderr.maximum = maxToolchainOutputBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return "", "", fmt.Errorf("inspect Git version: %w", contextErr)
		}
		return "", "", fmt.Errorf("inspect Git version: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	version := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(version, "git version ") || strings.ContainsAny(version, "\r\n") {
		return "", "", errors.New("Runner Git executable returned an invalid version")
	}
	return executable, strings.TrimPrefix(version, "git version "), nil
}

func prepareRunnerSource(ctx context.Context, gitExecutable, sourceRoot, revision string) (string, error) {
	if ctx == nil {
		return "", errors.New("runner source context is required")
	}
	if !filepath.IsAbs(gitExecutable) {
		return "", errors.New("runner source Git executable must be an absolute path")
	}
	directory, err := os.MkdirTemp("", "sandbox-runtime-conformance-source-")
	if err != nil {
		return "", fmt.Errorf("create runner source directory: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			cleanupRunnerSource(directory)
		}
	}()

	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(commandContext, gitExecutable, "-C", sourceRoot, "archive", "--format=tar", revision)
	output, err := command.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("capture Git archive: %w", err)
	}
	var stderr boundedOutput
	stderr.maximum = maxGitStderrBytes
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return "", fmt.Errorf("start Git archive: %w", err)
	}

	extractErr := extractRunnerArchive(output, directory, revision)
	if extractErr != nil {
		cancel()
		_, _ = io.Copy(io.Discard, output)
	}
	waitErr := command.Wait()
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("Git archive interrupted: %w", err)
	}
	if extractErr != nil {
		return "", extractErr
	}
	if waitErr != nil {
		return "", fmt.Errorf("Git archive failed: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	goModule, err := os.Lstat(filepath.Join(directory, "go.mod"))
	if err != nil || !goModule.Mode().IsRegular() {
		if err == nil {
			err = errors.New("not a regular file")
		}
		return "", fmt.Errorf("inspect archived go.mod: %w", err)
	}
	if err := makeRunnerSourceReadOnly(directory); err != nil {
		return "", err
	}
	keep = true
	return directory, nil
}

func extractRunnerArchive(archive io.Reader, destination, revision string) error {
	root, err := os.OpenRoot(destination)
	if err != nil {
		return fmt.Errorf("open runner source root: %w", err)
	}
	defer root.Close()

	reader := tar.NewReader(archive)
	seen := make(map[string]struct{})
	var total int64
	sawIdentity := false
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			if entries == 0 {
				return errors.New("runner source archive is empty")
			}
			if !sawIdentity {
				return errors.New("runner source archive lacks Git revision identity")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("read runner source archive: %w", err)
		}
		entries++
		if entries > maxRunnerArchiveEntries {
			return fmt.Errorf("runner source archive exceeds %d entries", maxRunnerArchiveEntries)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			if sawIdentity || header.Name != "pax_global_header" || len(header.PAXRecords) != 1 || header.PAXRecords["comment"] != revision {
				return errors.New("runner source archive has invalid Git revision identity")
			}
			sawIdentity = true
			continue
		}

		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if len(name) == 0 || len(name) > maxRunnerArchivePathBytes || !fs.ValidPath(name) || strings.ContainsRune(name, '\\') {
			return fmt.Errorf("runner source archive contains unsafe path %q", header.Name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("runner source archive duplicates path %q", name)
		}
		seen[name] = struct{}{}

		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return fmt.Errorf("runner source directory %q has non-zero size", name)
			}
			if err := root.MkdirAll(name, 0o700); err != nil {
				return fmt.Errorf("create runner source directory %q: %w", name, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxRunnerArchiveFileBytes || header.Size > maxRunnerArchiveBytes-total {
				return fmt.Errorf("runner source file %q exceeds archive bounds", name)
			}
			if parent := path.Dir(name); parent != "." {
				if err := root.MkdirAll(parent, 0o700); err != nil {
					return fmt.Errorf("create runner source parent for %q: %w", name, err)
				}
			}
			file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("create runner source file %q: %w", name, err)
			}
			written, copyErr := io.CopyN(file, reader, header.Size)
			mode := os.FileMode(0o400)
			if header.Mode&0o111 != 0 {
				mode = 0o500
			}
			chmodErr := file.Chmod(mode)
			closeErr := file.Close()
			if copyErr != nil || written != header.Size {
				return fmt.Errorf("read runner source file %q: %w", name, copyErr)
			}
			if chmodErr != nil {
				return fmt.Errorf("set runner source file %q read-only: %w", name, chmodErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close runner source file %q: %w", name, closeErr)
			}
			total += header.Size
		default:
			return fmt.Errorf("runner source archive entry %q has unsupported type %d", name, header.Typeflag)
		}
	}
}

func makeRunnerSourceReadOnly(directory string) error {
	var directories []string
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("runner source contains unexpected symlink %q", path)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("inspect runner source snapshot: %w", err)
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := os.Chmod(directories[index], 0o500); err != nil {
			return fmt.Errorf("set runner source directory read-only: %w", err)
		}
	}
	return nil
}

func cleanupRunnerSource(directory string) {
	_ = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(directory)
}

type boundedOutput struct {
	bytes.Buffer
	maximum int
}

func (output *boundedOutput) Write(document []byte) (int, error) {
	if len(document) > output.maximum-output.Len() {
		return 0, errors.New("bounded command output exceeded")
	}
	return output.Buffer.Write(document)
}

func loadRunnerIdentity(readBuildInfo func() (*debug.BuildInfo, bool)) (runnerIdentity, error) {
	if readBuildInfo == nil {
		return runnerIdentity{}, errors.New("runner build information reader is required")
	}
	info, ok := readBuildInfo()
	if !ok || info == nil {
		return runnerIdentity{}, errors.New("runner build information is unavailable")
	}
	toolchain := strings.TrimSpace(info.GoVersion)
	if toolchain == "" {
		return runnerIdentity{}, errors.New("runner Go toolchain is unavailable")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return runnerIdentity{}, fmt.Errorf("runner build information contains duplicate setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	if settings["vcs"] != "git" {
		return runnerIdentity{}, fmt.Errorf("runner VCS must be git, got %q", settings["vcs"])
	}
	revision := settings["vcs.revision"]
	if !validGitRevision(revision) {
		return runnerIdentity{}, fmt.Errorf("runner Git revision %q is invalid", revision)
	}
	switch settings["vcs.modified"] {
	case "false":
	case "true":
		return runnerIdentity{}, errors.New("runner build is modified")
	default:
		return runnerIdentity{}, errors.New("runner build does not declare an unmodified VCS state")
	}
	return runnerIdentity{revision: revision, toolchain: toolchain}, nil
}

func validGitRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (test testCase) expectedMatches() int {
	if test.ExpectedMatches == 0 {
		return 1
	}
	return test.ExpectedMatches
}

func runGoTestCommand(ctx context.Context, command *exec.Cmd, expectedPattern string, expectedMatches int, stdout, stderr io.Writer) error {
	if ctx == nil {
		return errors.New("go test context is required")
	}
	if expectedMatches < 1 {
		return errors.New("go test expected match count must be positive")
	}
	expected, err := regexp.Compile(expectedPattern)
	if err != nil {
		return fmt.Errorf("compile go test case pattern: %w", err)
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("capture go test JSON output: %w", err)
	}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start go test: %w", err)
	}

	evidence := newGoTestEvidence(expected, expectedMatches)
	decoder := json.NewDecoder(output)
	var streamErr error
	for {
		var event goTestEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			streamErr = fmt.Errorf("decode go test JSON output: %w", err)
			_, _ = io.Copy(io.Discard, output)
			break
		}
		if event.Output != "" && streamErr == nil {
			if _, err := io.WriteString(stdout, event.Output); err != nil {
				streamErr = fmt.Errorf("write go test output: %w", err)
			}
		}
		if err := evidence.observe(event); err != nil && streamErr == nil {
			streamErr = err
		}
	}
	waitErr := command.Wait()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("go test interrupted: %w", err)
	}
	evidenceErr := evidence.validate()
	if waitErr != nil && evidenceErr != nil {
		return errors.Join(
			fmt.Errorf("go test process failed: %w", waitErr),
			fmt.Errorf("go test execution evidence is invalid: %w", evidenceErr),
		)
	}
	if waitErr != nil {
		return fmt.Errorf("go test process failed: %w", waitErr)
	}
	if streamErr != nil {
		return streamErr
	}
	if evidenceErr != nil {
		return fmt.Errorf("go test execution evidence is invalid: %w", evidenceErr)
	}
	return nil
}

func newGoTestEvidence(expected *regexp.Regexp, expectedMatches int) *goTestEvidence {
	return &goTestEvidence{
		started:         make(map[string]struct{}),
		passed:          make(map[string]struct{}),
		terminal:        make(map[string]string),
		expected:        expected,
		expectedMatches: expectedMatches,
	}
}

func (evidence *goTestEvidence) observe(event goTestEvent) error {
	switch event.Action {
	case "start", "output":
		return nil
	case "run":
		if event.Test == "" {
			return errors.New("go test run event has no test identity")
		}
		if _, exists := evidence.started[event.Test]; exists {
			return fmt.Errorf("go test emitted duplicate run event for %q", event.Test)
		}
		evidence.started[event.Test] = struct{}{}
		return nil
	case "pause", "cont":
		if _, exists := evidence.started[event.Test]; !exists {
			return fmt.Errorf("go test emitted %s before run for %q", event.Action, event.Test)
		}
		return nil
	case "pass", "fail", "skip":
		if event.Test == "" {
			if event.Action == "pass" {
				evidence.packagePassed = true
			}
			if event.Action == "fail" {
				evidence.packageFailed = true
			}
			return nil
		}
		if _, exists := evidence.started[event.Test]; !exists {
			return fmt.Errorf("go test emitted %s before run for %q", event.Action, event.Test)
		}
		if terminal, exists := evidence.terminal[event.Test]; exists {
			return fmt.Errorf("go test emitted %s after terminal %s for %q", event.Action, terminal, event.Test)
		}
		evidence.terminal[event.Test] = event.Action
		if event.Action == "pass" {
			evidence.passed[event.Test] = struct{}{}
		}
		return nil
	default:
		return fmt.Errorf("go test emitted unknown action %q", event.Action)
	}
}

func (evidence *goTestEvidence) validate() error {
	if evidence.packageFailed {
		return errors.New("go test package failed")
	}
	if !evidence.packagePassed {
		return errors.New("go test package did not pass")
	}
	if len(evidence.started) == 0 {
		return errors.New("no tests matched the Suite case mapping")
	}
	for test := range evidence.started {
		switch evidence.terminal[test] {
		case "pass":
		case "skip":
			return fmt.Errorf("test %q was skipped", test)
		case "fail":
			return fmt.Errorf("test %q failed", test)
		default:
			return fmt.Errorf("test %q did not emit a terminal result", test)
		}
	}
	matched := 0
	for test := range evidence.passed {
		if evidence.expected.MatchString(test) {
			matched++
		}
	}
	if matched != evidence.expectedMatches {
		return fmt.Errorf("%d tests matching the Suite case mapping passed; want exactly %d", matched, evidence.expectedMatches)
	}
	return nil
}

func withSourceRootEnv(root string) []string {
	const key = "SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT="
	sanitized := map[string]string{
		"GOENV":       "off",
		"GOFLAGS":     "",
		"GOTOOLCHAIN": "local",
		"GOWORK":      "off",
	}
	current := os.Environ()
	env := make([]string, 0, len(current)+len(sanitized)+1)
	for _, value := range current {
		name, _, found := strings.Cut(value, "=")
		if strings.HasPrefix(value, key) || name == "GOROOT" {
			continue
		}
		if _, replace := sanitized[name]; replace || !found {
			continue
		}
		env = append(env, value)
	}
	for name, value := range sanitized {
		env = append(env, name+"="+value)
	}
	return append(env, key+root)
}

func validateCases(ids []string) error {
	if len(ids) == 0 {
		return errors.New("required Conformance Suite profile has no cases")
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return errors.New("Conformance Suite contains an empty case ID")
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("Conformance Suite contains duplicate case %q", id)
		}
		seen[id] = struct{}{}
		if _, exists := testCases[id]; !exists {
			return fmt.Errorf("Conformance Suite case %q has no local runner mapping", id)
		}
	}
	return nil
}
