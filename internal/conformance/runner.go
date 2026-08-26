// Package conformance executes the repository-owned Provider Contract Suite.
package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
)

// Options controls the test process used for each locked Suite case.
type Options struct {
	SourceRoot string
	LockPath   string
	Race       bool
	Shuffle    bool
}

// Report records the exact Suite profile and cases that were executed.
type Report struct {
	SuiteID      string
	SuiteVersion string
	ProfileID    string
	Cases        []string
}

type suiteDocument struct {
	SuiteID      string         `json:"suite_id"`
	SuiteVersion string         `json:"suite_version"`
	SuiteDigest  string         `json:"suite_digest"`
	Profiles     []suiteProfile `json:"profiles"`
}

type suiteProfile struct {
	ProfileID string   `json:"profile_id"`
	Tests     []string `json:"tests"`
}

type testCase struct {
	Package string
	Run     string
}

// The IDs are Contract-owned. The package/test mapping is local execution
// plumbing and is deliberately kept outside the Contract resources.
var testCases = map[string]testCase{
	"capability-discovery-mtls-only": {
		Package: "./providerapi",
		Run:     `^TestServerServesCapabilitiesOnlyAfterMTLSAdmission$`,
	},
	"capability-discovery-admitted-identity": {
		Package: "./providerapi",
		Run:     `^TestLoadMTLSConfig(AdmitsExactVerifiedURI|RejectsCertificateFailures)$`,
	},
	"capability-discovery-immutable-schema": {
		Package: "./providerapi",
		Run:     `^(TestLockedCapabilityResponseSchema|TestCapabilitiesHandlerReadsSourceOnceAndFreezesResponse)$`,
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
	"capability-discovery-empty-request": {
		Package: "./providerapi",
		Run:     `^(TestCapabilitiesHandlerRejectsRequestsWithoutADocumentBeforeDispatch|TestProviderServerReconcilesHTTP11CapabilityInputTransport)$`,
	},
	"capability-discovery-no-mutation-routes": {
		Package: "./providerapi",
		Run:     `^TestCapabilitiesHandlerRejectsMethodsAndAbsentRoutesWithoutSourceReads$`,
	},
	"protected-admission-context-schema": {
		Package: "./provider/admission",
		Run:     `^TestDecodeAdmissionContextCarrierEnforcesSchemaBounds$`,
	},
	"protected-admission-token-binding": {
		Package: "./provider/admission",
		Run:     `^(TestValidateTokenBindingRejectsMismatchedContext|TestVerifyCompactJWSRequiresEachOperationBinding)$`,
	},
	"protected-admission-digest-substitution": {
		Package: "./providerapi",
		Run:     `^TestProtectedHandlerRejectsRequestDescriptorSubstitutionAcrossAllRoutes$`,
	},
	"protected-admission-expiry": {
		Package: "./providerapi",
		Run:     `^(TestProtectedHandlerRejectsInactiveBearerAcrossAllRoutes|TestProtectedHandlerMapsBearerExpiryDuringDocumentReadToUnauthorized)$`,
	},
	"protected-admission-replay-and-fencing": {
		Package: "./providerapi",
		Run:     `^(TestProtectedHandlerRejectsDigestConsistentCreateAndSessionDocumentsBeforeGuard|TestProtectedHandlerRejectsOversizedCreateAndSessionDocumentsBeforeGuard|TestProtectedHandlerRejectsReplayAndStaleFencingAcrossAllMutations)$`,
	},
	"lifecycle-create-request-schema": {
		Package: "./providerapi",
		Run:     `^(TestDecodeCreateRequestProjectsOnlyAdmittedProviderFields|TestDecodeCreateRequestRejectsUnsupportedCapabilitiesAndContextSubstitution|TestLifecycleProjectionsMatchLockedSchemas)$`,
	},
	"lifecycle-operation-state-schema": {
		Package: "./providerapi",
		Run:     `^(TestLifecycleProjectionsAreBoundedAndOpaque|TestLifecycleProjectionsMatchLockedSchemas)$`,
	},
	"lifecycle-idempotency-generation-fencing": {
		Package: "./provider/lifecycle/coordinator",
		Run:     `^(TestAcceptCreateIsDurableAndIdempotent|TestStaleGenerationPreventsDriverDispatch|TestConcurrentReconcileSerializesDispatch)$`,
	},
	"lifecycle-deadline-outcome": {
		Package: "./provider/lifecycle/coordinator",
		Run:     `^(TestKnownFailureAndDeadlineDoNotDispatch|TestCanceledContextDoesNotDispatch|TestCreateUnknownOutcomeIsNotRetriedBlindlyAndReconcilesByInspection|TestRestartedRunningOperationIsReconciledWithoutDuplicateCreate)$`,
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
	root, err := filepath.Abs(options.SourceRoot)
	if err != nil {
		return Report{}, fmt.Errorf("resolve source root: %w", err)
	}
	lockPath := options.LockPath
	if !filepath.IsAbs(lockPath) {
		lockPath = filepath.Join(root, lockPath)
	}
	lockPath, err = filepath.Abs(lockPath)
	if err != nil {
		return Report{}, fmt.Errorf("resolve Contract lock: %w", err)
	}
	lock, err := contractlock.Load(lockPath)
	if err != nil {
		return Report{}, err
	}
	if _, err := contractlock.Verify(ctx, lock, root); err != nil {
		return Report{}, fmt.Errorf("verify locked Provider Contract: %w", err)
	}
	suitePath := filepath.Join(root, filepath.FromSlash(lock.SandboxSuite.Path))
	suite, err := loadSuite(suitePath)
	if err != nil {
		return Report{}, err
	}
	profile, err := requiredProfile(suite, lock.SandboxSuite.RequiredProfile)
	if err != nil {
		return Report{}, err
	}
	if err := validateCases(profile.Tests); err != nil {
		return Report{}, err
	}

	report := Report{
		SuiteID: suite.SuiteID, SuiteVersion: suite.SuiteVersion,
		ProfileID: profile.ProfileID, Cases: append([]string(nil), profile.Tests...),
	}
	for _, id := range profile.Tests {
		caseSpec := testCases[id]
		args := []string{"test", "-count=1"}
		if options.Race {
			args = append(args, "-race")
		}
		if options.Shuffle {
			args = append(args, "-shuffle=on")
		}
		args = append(args, caseSpec.Package, "-run", caseSpec.Run)
		command := exec.CommandContext(ctx, "go", args...)
		command.Dir = root
		command.Stdout = stdout
		command.Stderr = stderr
		command.Env = withSourceRootEnv(root)
		if err := command.Run(); err != nil {
			return Report{}, fmt.Errorf("Suite case %q failed: %w", id, err)
		}
	}
	return report, nil
}

func withSourceRootEnv(root string) []string {
	const key = "SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT="
	current := os.Environ()
	env := make([]string, 0, len(current)+1)
	for _, value := range current {
		if strings.HasPrefix(value, key) {
			continue
		}
		env = append(env, value)
	}
	return append(env, key+root)
}

func loadSuite(path string) (suiteDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return suiteDocument{}, fmt.Errorf("open local Conformance Suite: %w", err)
	}
	defer file.Close()
	var suite suiteDocument
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&suite); err != nil {
		return suiteDocument{}, fmt.Errorf("decode local Conformance Suite: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return suiteDocument{}, errors.New("local Conformance Suite contains multiple JSON values")
		}
		return suiteDocument{}, fmt.Errorf("decode local Conformance Suite trailer: %w", err)
	}
	if suite.SuiteID == "" || suite.SuiteVersion == "" {
		return suiteDocument{}, errors.New("local Conformance Suite identity is required")
	}
	return suite, nil
}

func requiredProfile(suite suiteDocument, profileID string) (suiteProfile, error) {
	var found *suiteProfile
	for _, profile := range suite.Profiles {
		if profile.ProfileID != profileID {
			continue
		}
		if found != nil {
			return suiteProfile{}, fmt.Errorf("local Conformance Suite contains duplicate profile %q", profileID)
		}
		copy := profile
		found = &copy
	}
	if found == nil {
		return suiteProfile{}, fmt.Errorf("local Conformance Suite is missing required profile %q", profileID)
	}
	return *found, nil
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
