// Package remoteconformance executes the locked, read-only remote Provider
// discovery profile over its public HTTPS interface.
package remoteconformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
)

const (
	ReportSchemaVersion = 2
	EvidenceName        = "Sandbox Provider remote discovery conformance"
	runnerMainPath      = "github.com/shell-echo/sandbox-runtime/cmd/run-remote-conformance"
)

var requiredCases = []string{
	"remote-capability-discovery-mtls-success",
	"remote-capability-discovery-client-certificate-required",
	"remote-capability-discovery-schema",
	"remote-capability-discovery-immutable",
	"remote-capability-discovery-empty-request",
	"remote-capability-discovery-get-only",
}

// Options identifies one remote Provider and its mTLS client material.
type Options struct {
	SourceRoot       string
	LockPath         string
	Target           string
	CAFile           string
	ClientCAFile     string
	ClientCert       string
	ClientKey        string
	DeniedClientCert string
	DeniedClientKey  string
	ServerName       string
	ProviderRevision string
}

// Report is the stable, secret-free result written by the CLI.
type Report struct {
	SchemaVersion                int              `json:"schema_version"`
	EvidenceName                 string           `json:"evidence_name"`
	StartedAt                    string           `json:"started_at"`
	CompletedAt                  string           `json:"completed_at"`
	Runner                       RunnerIdentity   `json:"runner"`
	Contract                     ContractIdentity `json:"contract"`
	Suite                        SuiteIdentity    `json:"suite"`
	TargetOrigin                 string           `json:"target_origin"`
	TargetOriginDigest           string           `json:"target_origin_digest"`
	Provider                     ProviderIdentity `json:"provider"`
	Cases                        []CaseResult     `json:"cases"`
	Summary                      Summary          `json:"summary"`
	SuiteExercised               bool             `json:"suite_exercised"`
	ProfilePassed                bool             `json:"profile_passed"`
	ContractMutationRoutesCalled bool             `json:"contract_mutation_routes_called"`
	UnsafeMethodProbesSent       bool             `json:"unsafe_method_probes_sent"`
	EvidenceBoundary             string           `json:"evidence_boundary"`
}

// RunnerIdentity pins the exact clean executable that produced the report.
type RunnerIdentity struct {
	MainPath  string `json:"main_path"`
	Revision  string `json:"revision"`
	GoVersion string `json:"go_version"`
	Modified  bool   `json:"modified"`
}

type ContractIdentity struct {
	Namespace      string `json:"namespace"`
	Version        string `json:"version"`
	LockedRevision string `json:"locked_revision"`
	CheckoutHead   string `json:"checkout_head"`
	ContractTree   string `json:"contract_tree"`
	ManifestDigest string `json:"manifest_digest"`
	OpenAPIDigest  string `json:"openapi_digest"`
}

type SuiteIdentity struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	Digest        string `json:"digest"`
	DigestProfile string `json:"digest_profile"`
	ProfileID     string `json:"profile_id"`
}

type ProviderIdentity struct {
	ExpectedRevisionID       string `json:"expected_revision_id"`
	ObservedRevisionID       string `json:"observed_revision_id,omitempty"`
	CapabilityDocumentDigest string `json:"capability_document_digest,omitempty"`
}

type CaseResult struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	FailureCode string `json:"failure_code,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

type Summary struct {
	Total       int `json:"total"`
	Passed      int `json:"passed"`
	Failed      int `json:"failed"`
	NotExecuted int `json:"not_executed"`
}

// Error exposes only a stable classification. Underlying paths, endpoints,
// response bodies, and transport diagnostics deliberately stay private.
type Error struct {
	Code  string
	cause error
}

func (e *Error) Error() string {
	if e == nil || e.Code == "" {
		return "remote conformance failed"
	}
	return "remote conformance failed: " + e.Code
}

// Unwrap preserves only the stable context cancellation cause. Private
// transport and filesystem diagnostics are never attached to Error.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func errorCode(err error) string {
	var remoteError *Error
	if errors.As(err, &remoteError) {
		return remoteError.Code
	}
	return "runner_internal_error"
}

// ExitCode maps stable failures to CLI exit status without inspecting private
// diagnostics.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	switch errorCode(err) {
	case "cases_failed":
		return 1
	case "invalid_configuration", "runner_identity_unverified", "contract_verification_failed", "remote_suite_invalid", "schema_projection_failed":
		return 2
	default:
		return 1
	}
}

// Run verifies the locked local Contract, then exercises exactly the remote
// Suite cases selected by that verified Contract.
func Run(ctx context.Context, options Options) (Report, error) {
	if ctx == nil {
		return Report{}, &Error{Code: "invalid_configuration"}
	}
	identity, err := readRunnerIdentity()
	if err != nil {
		return Report{}, err
	}
	return run(ctx, options, identity)
}

func run(ctx context.Context, options Options, identity RunnerIdentity) (Report, error) {
	if ctx == nil || !validRunnerIdentity(identity) {
		return Report{}, &Error{Code: "invalid_configuration"}
	}
	if err := ctx.Err(); err != nil {
		return Report{}, contextFailure(err)
	}
	root, err := filepath.Abs(options.SourceRoot)
	if err != nil {
		return Report{}, &Error{Code: "invalid_configuration"}
	}
	lockPath := options.LockPath
	if !filepath.IsAbs(lockPath) {
		lockPath = filepath.Join(root, lockPath)
	}
	lock, err := contractlock.Load(lockPath)
	if err != nil {
		return Report{}, &Error{Code: "contract_verification_failed"}
	}
	verified, err := contractlock.Verify(ctx, lock, root)
	if err != nil {
		if ctx.Err() != nil {
			return Report{}, contextFailure(ctx.Err())
		}
		return Report{}, &Error{Code: "contract_verification_failed"}
	}
	if err := validateRemoteSuite(verified.RemoteSuite); err != nil {
		return Report{}, err
	}
	projection, err := providercontract.LoadVerified(lock, verified)
	if err != nil {
		return Report{}, &Error{Code: "schema_projection_failed"}
	}
	executor, err := newExecutor(options, projection)
	if err != nil {
		return Report{}, err
	}
	defer executor.close()

	started := time.Now().UTC()
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		EvidenceName:  EvidenceName,
		StartedAt:     started.Format(time.RFC3339Nano),
		Runner:        identity,
		Contract: ContractIdentity{
			Namespace: lock.Contract.Namespace, Version: lock.Contract.Version,
			LockedRevision: verified.LockedRevision, CheckoutHead: verified.CheckoutHead,
			ContractTree: verified.ContractTree, ManifestDigest: verified.ManifestDigest,
			OpenAPIDigest: verified.OpenAPISHA256,
		},
		Suite: SuiteIdentity{
			ID: verified.RemoteSuite.ID, Version: verified.RemoteSuite.Version,
			Digest: verified.RemoteSuite.Digest, DigestProfile: verified.RemoteSuite.DigestProfile,
			ProfileID: verified.RemoteSuite.ProfileID,
		},
		TargetOrigin:       executor.target.String(),
		TargetOriginDigest: digestString(executor.target.String()),
		Provider: ProviderIdentity{
			ExpectedRevisionID: executor.expectedProviderRevision,
		},
		Cases:                        make([]CaseResult, 0, len(verified.RemoteSuite.Cases)),
		ContractMutationRoutesCalled: false,
		EvidenceBoundary:             "runner host, filesystem, and Git executable are trusted local inputs; remote Provider capability discovery uses TLS 1.3 mTLS; method probes are sent only to /v1/capabilities, but a non-conforming target could produce side effects; this report does not claim zero side effects and is not protected admission, lifecycle, runtime, aggregate, multi-controller, multi-tenant, deployment, or production evidence",
	}

	for caseIndex, id := range verified.RemoteSuite.Cases {
		if err := ctx.Err(); err != nil {
			appendNotExecuted(&report, verified.RemoteSuite.Cases[caseIndex:], errorCode(contextFailure(err)))
			finalizeReport(&report, executor)
			return report, contextFailure(err)
		}
		caseStarted := time.Now()
		result := CaseResult{ID: id}
		caseErr := executor.runCase(ctx, id)
		switch {
		case errors.Is(caseErr, context.Canceled), errors.Is(caseErr, context.DeadlineExceeded):
			result.Status = "not_executed"
			result.FailureCode = errorCode(caseErr)
			result.DurationMS = time.Since(caseStarted).Milliseconds()
			report.Cases = append(report.Cases, result)
			appendNotExecuted(&report, verified.RemoteSuite.Cases[caseIndex+1:], errorCode(caseErr))
			finalizeReport(&report, executor)
			return report, caseErr
		case caseErr != nil && errorCode(caseErr) == "baseline_unavailable":
			result.Status = "not_executed"
			result.FailureCode = errorCode(caseErr)
		case caseErr != nil:
			result.Status = "failed"
			result.FailureCode = errorCode(caseErr)
		default:
			result.Status = "passed"
		}
		result.DurationMS = time.Since(caseStarted).Milliseconds()
		report.Cases = append(report.Cases, result)
	}
	finalizeReport(&report, executor)
	if !report.ProfilePassed {
		if report.Summary.NotExecuted > 0 {
			return report, &Error{Code: "cases_incomplete"}
		}
		return report, &Error{Code: "cases_failed"}
	}
	return report, nil
}

func appendNotExecuted(report *Report, cases []string, code string) {
	for _, id := range cases {
		report.Cases = append(report.Cases, CaseResult{ID: id, Status: "not_executed", FailureCode: code})
	}
}

func finalizeReport(report *Report, executor *executor) {
	report.Provider.ObservedRevisionID = executor.providerRevision
	report.Provider.CapabilityDocumentDigest = executor.capabilityDigest
	report.UnsafeMethodProbesSent = executor.unsafeMethodProbesSent
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.Summary = summarize(report.Cases)
	report.SuiteExercised = suiteExercised(report.Cases)
	report.ProfilePassed = report.SuiteExercised && report.Summary.Passed == len(requiredCases)
}

func validateRemoteSuite(suite contractlock.VerifiedSuite) error {
	if suite.ID == "" || suite.Version == "" || suite.Digest == "" || suite.DigestProfile == "" || suite.ProfileID == "" || len(suite.Cases) != len(requiredCases) {
		return &Error{Code: "remote_suite_invalid"}
	}
	for index, id := range requiredCases {
		if suite.Cases[index] != id {
			return &Error{Code: "remote_suite_invalid"}
		}
	}
	return nil
}

func summarize(cases []CaseResult) Summary {
	result := Summary{Total: len(cases)}
	for _, item := range cases {
		switch item.Status {
		case "passed":
			result.Passed++
		case "failed":
			result.Failed++
		case "not_executed":
			result.NotExecuted++
		}
	}
	return result
}

func suiteExercised(cases []CaseResult) bool {
	if len(cases) != len(requiredCases) {
		return false
	}
	for index, result := range cases {
		if result.ID != requiredCases[index] || (result.Status != "passed" && result.Status != "failed") {
			return false
		}
	}
	return true
}

func readRunnerIdentity() (RunnerIdentity, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return RunnerIdentity{}, &Error{Code: "runner_identity_unverified"}
	}
	identity, err := parseRunnerIdentity(info)
	if err != nil {
		return RunnerIdentity{}, &Error{Code: "runner_identity_unverified"}
	}
	return identity, nil
}

func parseRunnerIdentity(info *debug.BuildInfo) (RunnerIdentity, error) {
	if info == nil || info.Path != runnerMainPath || strings.TrimSpace(info.GoVersion) == "" {
		return RunnerIdentity{}, errors.New("invalid runner build information")
	}
	var vcs, revision, modified string
	var seenVCS, seenRevision, seenModified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs":
			if seenVCS {
				return RunnerIdentity{}, errors.New("duplicate runner VCS")
			}
			seenVCS = true
			vcs = setting.Value
		case "vcs.revision":
			if seenRevision {
				return RunnerIdentity{}, errors.New("duplicate runner revision")
			}
			seenRevision = true
			revision = setting.Value
		case "vcs.modified":
			if seenModified {
				return RunnerIdentity{}, errors.New("duplicate runner modified state")
			}
			seenModified = true
			modified = setting.Value
		}
	}
	identity := RunnerIdentity{MainPath: info.Path, Revision: revision, GoVersion: info.GoVersion, Modified: modified == "true"}
	if vcs != "git" || modified != "false" || !validRunnerIdentity(identity) {
		return RunnerIdentity{}, errors.New("runner build identity is not a clean VCS revision")
	}
	return identity, nil
}

func validRunnerIdentity(identity RunnerIdentity) bool {
	if identity.MainPath != runnerMainPath || strings.TrimSpace(identity.GoVersion) == "" || identity.Modified {
		return false
	}
	if len(identity.Revision) != 40 && len(identity.Revision) != 64 {
		return false
	}
	for _, character := range identity.Revision {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func contextFailure(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return &Error{Code: "run_deadline_exceeded", cause: context.DeadlineExceeded}
	case errors.Is(err, context.Canceled):
		return &Error{Code: "run_canceled", cause: context.Canceled}
	default:
		return &Error{Code: "runner_internal_error"}
	}
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func failure(code string) error {
	if code == "" {
		panic(fmt.Errorf("remote conformance failure requires a code"))
	}
	return &Error{Code: code}
}
