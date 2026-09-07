// Package qualificationprofile verifies the repository-owned external-caller
// qualification profile definition without claiming that any caller passed it.
package qualificationprofile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
	"go.yaml.in/yaml/v3"
)

const (
	ProfileID            = "sandbox-runtime-external-caller-coding-shell-v1"
	ProfileVersion       = "1.0.0"
	ProfileDigestProfile = "rfc8785-full-document-excluding-profile-digest-v1"
	ProfileSchemaID      = "urn:shell-echo:sandbox-runtime:qualification:external-caller-coding-shell-profile:v1"

	ProfilePath       = "qualification/external-caller-coding-shell-v1/profile.json"
	ProfileSchemaPath = "qualification/external-caller-coding-shell-v1/profile.schema.json"
	ContractLockPath  = "compatibility/sandbox-runtime/contract.lock.json"

	// These repository trust anchors are updated only after the complete profile
	// and schema pass review and validation.
	ExpectedProfileDigest = "sha256:baee769c0acc395448af61faef99cd97fbb63ccb83c70eb51915952be519991a"
	ExpectedSchemaDigest  = "sha256:2ad01731b69246399d6f04048593f31da9e4118b1dff99a81551b0c9b5972d77"

	maxProfileBytes = 2 << 20
	maxSchemaBytes  = 2 << 20
)

var qualificationV1ExactErrorCodes = map[string]struct{}{
	"SANDBOX_CONFLICT":            {},
	"SANDBOX_FORBIDDEN":           {},
	"SANDBOX_NOT_FOUND":           {},
	"SANDBOX_STALE_FENCING_TOKEN": {},
}

type providerOperation struct {
	method string
	route  string
}

var codingShellV1ProviderOperations = map[providerOperation]struct{}{
	{method: "GET", route: "/v1/capabilities"}:                                        {},
	{method: "GET", route: "/v1/operations/{operation_id}"}:                           {},
	{method: "GET", route: "/v1/operations/{operation_id}/artifact-staging-evidence"}: {},
	{method: "GET", route: "/v1/operations/{operation_id}/exec-result"}:               {},
	{method: "GET", route: "/v1/operations/{operation_id}/runtime-session"}:           {},
	{method: "GET", route: "/v1/operations/{operation_id}/usage-evidence"}:            {},
	{method: "GET", route: "/v1/sandboxes/{sandbox_id}"}:                              {},
	{method: "POST", route: "/v1/sandboxes"}:                                          {},
	{method: "POST", route: "/v1/sandboxes/{sandbox_id}/artifacts:stage"}:             {},
	{method: "POST", route: "/v1/sandboxes/{sandbox_id}/exec"}:                        {},
	{method: "POST", route: "/v1/sandboxes/{sandbox_id}/exec:cancel"}:                 {},
	{method: "POST", route: "/v1/sandboxes/{sandbox_id}/runtime-sessions"}:            {},
}

// Report describes a verified definition lock. It is not a qualification run
// report and carries no external-caller result.
type Report struct {
	ProfileID      string
	ProfileVersion string
	ProfileDigest  string
	SchemaDigest   string
	InitialCases   int
	RestartCases   int
	Interactions   int
}

type profileDocument struct {
	FormatVersion        int                           `json:"format_version"`
	ProfileID            string                        `json:"profile_id"`
	ProfileVersion       string                        `json:"profile_version"`
	ProfileDigestProfile string                        `json:"profile_digest_profile"`
	ProfileSchema        fileIdentity                  `json:"profile_schema"`
	Contract             contractIdentity              `json:"contract"`
	MutationsPerformed   bool                          `json:"mutations_performed"`
	Topology             topology                      `json:"topology"`
	Artifacts            []artifactIdentityRequirement `json:"artifact_identity_requirements"`
	ObserverRequirements []string                      `json:"observer_requirements"`
	Limits               limits                        `json:"limits"`
	Reconstruction       reconstruction                `json:"reconstruction"`
	Phases               []phase                       `json:"phases"`
	ProfileDigest        string                        `json:"profile_digest"`
}

type fileIdentity struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type contractIdentity struct {
	Namespace            string        `json:"namespace"`
	Version              string        `json:"version"`
	Revision             string        `json:"revision"`
	Tree                 string        `json:"tree"`
	ManifestDigest       string        `json:"manifest_digest"`
	OpenAPIDigest        string        `json:"openapi_digest"`
	SemanticRulesDigest  string        `json:"semantic_rules_digest"`
	LocalSuite           suiteIdentity `json:"local_suite"`
	RemoteDiscoverySuite suiteIdentity `json:"remote_discovery_suite"`
}

type suiteIdentity struct {
	SuiteID            string `json:"suite_id"`
	SuiteVersion       string `json:"suite_version"`
	SuiteDigest        string `json:"suite_digest"`
	SuiteDigestProfile string `json:"suite_digest_profile"`
	ProfileID          string `json:"profile_id"`
	CaseCount          int    `json:"case_count"`
	ExecutionRequired  bool   `json:"execution_required"`
}

type topology struct {
	Actors                 []actor    `json:"actors"`
	ProcessIsolationGroups [][]string `json:"process_isolation_groups"`
}

type actor struct {
	ActorID string `json:"actor_id"`
}

type artifactIdentityRequirement struct {
	ArtifactID             string `json:"artifact_id"`
	Owner                  string `json:"owner"`
	TrustDomain            string `json:"trust_domain"`
	DigestSubject          string `json:"digest_subject"`
	ObservedBy             string `json:"observed_by"`
	SourceIdentityRequired bool   `json:"source_identity_required"`
}

type limits struct {
	MaxSandboxes                     int `json:"max_sandboxes"`
	MaxExecRequests                  int `json:"max_exec_requests"`
	MaxAdmittedExecOperations        int `json:"max_admitted_exec_operations"`
	MaxTerminalSessions              int `json:"max_terminal_sessions"`
	MaxArtifactRequests              int `json:"max_artifact_requests"`
	MaxAdmittedArtifactOperations    int `json:"max_admitted_artifact_operations"`
	MaxDistinctProviderMutations     int `json:"max_distinct_provider_mutations"`
	MaxProviderMutationWriteAttempts int `json:"max_provider_mutation_write_attempts"`
	MaxGatewayMutationWriteAttempts  int `json:"max_gateway_mutation_write_attempts"`
	MaxProviderHTTPRequests          int `json:"max_provider_http_requests"`
	MaxGatewayConnectionAttempts     int `json:"max_gateway_connection_attempts"`
	MaxCaseSeconds                   int `json:"max_case_seconds"`
	MaxExecutionSeconds              int `json:"max_execution_seconds"`
	MaxCleanupSeconds                int `json:"max_cleanup_seconds"`
	MaxTotalWallClockSeconds         int `json:"max_total_wall_clock_seconds"`
	MaxEvidenceFiles                 int `json:"max_evidence_files"`
	MaxEvidenceFileBytes             int `json:"max_evidence_file_bytes"`
	MaxEvidenceTotalBytes            int `json:"max_evidence_total_bytes"`
}

type reconstruction struct {
	ShellContinuityChallenge shellContinuityChallenge `json:"shell_continuity_challenge"`
}

type shellContinuityChallenge struct {
	EstablishedInCase string `json:"established_in_case"`
	VerifiedInCase    string `json:"verified_in_case"`
}

type phase struct {
	PhaseID        string           `json:"phase_id"`
	DependsOnPhase *string          `json:"depends_on_phase"`
	Cases          []caseDefinition `json:"cases"`
}

type caseDefinition struct {
	CaseID             string        `json:"case_id"`
	TimeoutSeconds     int           `json:"timeout_seconds"`
	DependsOn          []string      `json:"depends_on"`
	Interactions       []interaction `json:"interactions"`
	ObservationSources []string      `json:"observation_sources"`
}

type interaction struct {
	InteractionID        string                `json:"interaction_id"`
	Surface              string                `json:"surface"`
	Actor                string                `json:"actor"`
	Method               string                `json:"method"`
	RouteTemplate        string                `json:"route_template"`
	LogicalRequestID     string                `json:"logical_request_id"`
	ReplayOf             *string               `json:"replay_of"`
	CountsToward         []string              `json:"counts_toward"`
	MaxWireAttempts      int                   `json:"max_wire_attempts"`
	Outcomes             []outcome             `json:"outcomes"`
	TransientOutcomes    []outcome             `json:"transient_outcomes"`
	RequiredObservations []requiredObservation `json:"required_observations"`
}

type requiredObservation struct {
	ObservationID string `json:"observation_id"`
	Source        string `json:"source"`
	Actor         string `json:"actor"`
	Subject       string `json:"subject"`
	Correlation   string `json:"correlation"`
}

type outcome struct {
	Transport          string   `json:"transport"`
	StatusCode         *int     `json:"status_code"`
	ErrorCodePolicy    string   `json:"error_code_policy"`
	ErrorCodes         []string `json:"error_codes"`
	Retryable          *bool    `json:"retryable,omitempty"`
	RetryAfterRequired *bool    `json:"retry_after_required,omitempty"`
}

// VerifyCodingShellV1 verifies the exact repository trust anchors, closed JSON
// Schema, semantic invariants, and locked Provider Contract projection.
func VerifyCodingShellV1(ctx context.Context, sourceRoot string) (Report, error) {
	profileBytes, err := readRepositoryFile(sourceRoot, ProfilePath, maxProfileBytes)
	if err != nil {
		return Report{}, fmt.Errorf("read qualification profile: %w", err)
	}
	schemaBytes, err := readRepositoryFile(sourceRoot, ProfileSchemaPath, maxSchemaBytes)
	if err != nil {
		return Report{}, fmt.Errorf("read qualification profile schema: %w", err)
	}
	if got := rawDigest(schemaBytes); got != ExpectedSchemaDigest {
		return Report{}, fmt.Errorf("qualification profile schema digest %s does not match trust anchor %s", got, ExpectedSchemaDigest)
	}

	profileValue, profile, err := verifyProfileIdentity(profileBytes)
	if err != nil {
		return Report{}, err
	}
	if profile.ProfileSchema.Path != ProfileSchemaPath || profile.ProfileSchema.Digest != ExpectedSchemaDigest {
		return Report{}, errors.New("qualification profile schema identity does not match the repository trust anchor")
	}
	if err := validateSchema(schemaBytes, profileValue); err != nil {
		return Report{}, err
	}

	lock, err := contractlock.Load(filepath.Join(sourceRoot, filepath.FromSlash(ContractLockPath)))
	if err != nil {
		return Report{}, fmt.Errorf("load Provider Contract lock: %w", err)
	}
	contractReport, err := contractlock.Verify(ctx, lock, sourceRoot)
	if err != nil {
		return Report{}, fmt.Errorf("verify Provider Contract before qualification profile: %w", err)
	}
	if err := validateContractIdentity(profile.Contract, lock, contractReport); err != nil {
		return Report{}, err
	}
	openAPI, err := contractReport.Resource(lock, lock.Contract.OpenAPIPath)
	if err != nil {
		return Report{}, fmt.Errorf("read verified Provider OpenAPI: %w", err)
	}
	interactionCount, err := validateSemantics(profile, openAPI)
	if err != nil {
		return Report{}, err
	}

	return Report{
		ProfileID:      profile.ProfileID,
		ProfileVersion: profile.ProfileVersion,
		ProfileDigest:  profile.ProfileDigest,
		SchemaDigest:   profile.ProfileSchema.Digest,
		InitialCases:   len(profile.Phases[0].Cases),
		RestartCases:   len(profile.Phases[1].Cases),
		Interactions:   interactionCount,
	}, nil
}

func verifyProfileIdentity(document []byte) (any, profileDocument, error) {
	var value any
	if err := decodeStrictJSON(document, &value); err != nil {
		return nil, profileDocument{}, fmt.Errorf("decode qualification profile: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, profileDocument{}, errors.New("qualification profile must be a JSON object")
	}
	declared, ok := object["profile_digest"].(string)
	if !ok {
		return nil, profileDocument{}, errors.New("qualification profile has no string profile_digest")
	}
	computed, err := computeProfileDigest(object)
	if err != nil {
		return nil, profileDocument{}, err
	}
	if declared != computed {
		return nil, profileDocument{}, fmt.Errorf("qualification profile declares digest %s but computes %s", declared, computed)
	}
	if computed != ExpectedProfileDigest {
		return nil, profileDocument{}, fmt.Errorf("qualification profile digest %s does not match trust anchor %s", computed, ExpectedProfileDigest)
	}

	var profile profileDocument
	if err := json.Unmarshal(document, &profile); err != nil {
		return nil, profileDocument{}, fmt.Errorf("decode qualification profile identity: %w", err)
	}
	if profile.FormatVersion != 1 || profile.ProfileID != ProfileID || profile.ProfileVersion != ProfileVersion ||
		profile.ProfileDigestProfile != ProfileDigestProfile {
		return nil, profileDocument{}, errors.New("qualification profile identity is not the locked coding/shell v1 identity")
	}
	return value, profile, nil
}

func computeProfileDigest(object map[string]any) (string, error) {
	copyObject := make(map[string]any, len(object)-1)
	for key, value := range object {
		if key != "profile_digest" {
			copyObject[key] = value
		}
	}
	encoded, err := json.Marshal(copyObject)
	if err != nil {
		return "", fmt.Errorf("encode qualification profile for digest: %w", err)
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return "", fmt.Errorf("canonicalize qualification profile: %w", err)
	}
	return rawDigest(canonical), nil
}

func validateSchema(schemaDocument []byte, profileValue any) error {
	var schemaValue any
	if err := decodeStrictJSON(schemaDocument, &schemaValue); err != nil {
		return fmt.Errorf("decode qualification profile schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	if err := compiler.AddResource(ProfileSchemaID, schemaValue); err != nil {
		return fmt.Errorf("register qualification profile schema: %w", err)
	}
	schema, err := compiler.Compile(ProfileSchemaID)
	if err != nil {
		return fmt.Errorf("compile qualification profile schema: %w", err)
	}
	if err := schema.Validate(profileValue); err != nil {
		return fmt.Errorf("validate qualification profile schema: %w", err)
	}
	return nil
}

func validateContractIdentity(profile contractIdentity, lock contractlock.Lock, report contractlock.Report) error {
	if profile.Namespace != lock.Contract.Namespace || profile.Version != lock.Contract.Version ||
		profile.Revision != report.LockedRevision || profile.Tree != report.ContractTree ||
		profile.ManifestDigest != report.ManifestDigest || profile.OpenAPIDigest != report.OpenAPISHA256 ||
		profile.SemanticRulesDigest != lock.Contract.SemanticRulesSHA256 {
		return errors.New("qualification profile Contract identity differs from the verified lock")
	}
	if err := compareSuiteIdentity("local", profile.LocalSuite, report.SandboxSuite); err != nil {
		return err
	}
	if err := compareSuiteIdentity("remote discovery", profile.RemoteDiscoverySuite, report.RemoteSuite); err != nil {
		return err
	}
	return nil
}

func compareSuiteIdentity(name string, profile suiteIdentity, verified contractlock.VerifiedSuite) error {
	if profile.SuiteID != verified.ID || profile.SuiteVersion != verified.Version ||
		profile.SuiteDigest != verified.Digest || profile.SuiteDigestProfile != verified.DigestProfile ||
		profile.ProfileID != verified.ProfileID || profile.CaseCount != len(verified.Cases) || profile.ExecutionRequired {
		return fmt.Errorf("qualification profile %s Suite identity differs from the verified lock", name)
	}
	return nil
}

func validateSemantics(profile profileDocument, openAPI []byte) (int, error) {
	if len(profile.Phases) != 2 || profile.Phases[0].PhaseID != "initial" || profile.Phases[0].DependsOnPhase != nil ||
		profile.Phases[1].PhaseID != "reconstruction" || profile.Phases[1].DependsOnPhase == nil || *profile.Phases[1].DependsOnPhase != "initial" ||
		len(profile.Phases[0].Cases) != 15 || len(profile.Phases[1].Cases) != 5 {
		return 0, errors.New("qualification profile must contain ordered 15-case initial and 5-case reconstruction phases")
	}
	if err := validateLimits(profile.Limits); err != nil {
		return 0, err
	}
	actors := make(map[string]struct{}, len(profile.Topology.Actors))
	for _, actor := range profile.Topology.Actors {
		if _, duplicate := actors[actor.ActorID]; duplicate {
			return 0, fmt.Errorf("qualification profile duplicates actor %q", actor.ActorID)
		}
		actors[actor.ActorID] = struct{}{}
	}
	if err := validateArtifacts(profile.Artifacts, profile.Topology.ProcessIsolationGroups); err != nil {
		return 0, err
	}

	var openAPIDocument any
	if err := yaml.Unmarshal(openAPI, &openAPIDocument); err != nil {
		return 0, fmt.Errorf("decode verified Provider OpenAPI: %w", err)
	}
	seenCases := make(map[string]caseDefinition, 20)
	seenInteractions := make(map[string]interaction)
	seenLogicalRequests := make(map[string]interaction)
	accounting := make(map[string]int)
	previousCaseID := ""
	for _, phase := range profile.Phases {
		for _, candidate := range phase.Cases {
			if !strings.HasPrefix(candidate.CaseID, phase.PhaseID+".") {
				return 0, fmt.Errorf("case %q does not belong to phase %q", candidate.CaseID, phase.PhaseID)
			}
			if _, duplicate := seenCases[candidate.CaseID]; duplicate {
				return 0, fmt.Errorf("qualification profile duplicates case %q", candidate.CaseID)
			}
			if previousCaseID == "" {
				if len(candidate.DependsOn) != 0 {
					return 0, fmt.Errorf("first case %q must have no dependency", candidate.CaseID)
				}
			} else if len(candidate.DependsOn) != 1 || candidate.DependsOn[0] != previousCaseID {
				return 0, fmt.Errorf("case %q must depend exactly on preceding case %q", candidate.CaseID, previousCaseID)
			}
			if candidate.TimeoutSeconds > profile.Limits.MaxCaseSeconds {
				return 0, fmt.Errorf("case %q exceeds the profile case deadline", candidate.CaseID)
			}
			seenCases[candidate.CaseID] = candidate
			previousCaseID = candidate.CaseID
			caseSources := stringSet(candidate.ObservationSources)
			if _, ok := caseSources["caller_assertion"]; !ok {
				return 0, fmt.Errorf("case %q has no caller assertion source", candidate.CaseID)
			}
			for _, interaction := range candidate.Interactions {
				if _, duplicate := seenInteractions[interaction.InteractionID]; duplicate {
					return 0, fmt.Errorf("qualification profile duplicates interaction %q", interaction.InteractionID)
				}
				seenInteractions[interaction.InteractionID] = interaction
				if _, ok := actors[interaction.Actor]; !ok {
					return 0, fmt.Errorf("interaction %q uses undefined actor %q", interaction.InteractionID, interaction.Actor)
				}
				if err := validateReplay(interaction, seenLogicalRequests); err != nil {
					return 0, err
				}
				if interaction.ReplayOf == nil {
					seenLogicalRequests[interaction.LogicalRequestID] = interaction
				}
				if err := validateObservations(interaction, caseSources); err != nil {
					return 0, err
				}
				if err := validateInteraction(interaction, openAPIDocument); err != nil {
					return 0, err
				}
				for _, counter := range interaction.CountsToward {
					accounting[counter]++
				}
			}
		}
	}
	if err := validateAccounting(profile.Limits, accounting); err != nil {
		return 0, err
	}
	establishedCase, established := seenCases[profile.Reconstruction.ShellContinuityChallenge.EstablishedInCase]
	if !established || !strings.HasPrefix(profile.Reconstruction.ShellContinuityChallenge.EstablishedInCase, "initial.") ||
		!caseHasObservation(establishedCase, "shell-continuity-challenge-established") {
		return 0, errors.New("shell continuity challenge establishment case is missing from the initial phase")
	}
	verifiedCase, verified := seenCases[profile.Reconstruction.ShellContinuityChallenge.VerifiedInCase]
	if !verified || !strings.HasPrefix(profile.Reconstruction.ShellContinuityChallenge.VerifiedInCase, "reconstruction.") ||
		!caseHasObservation(verifiedCase, "shell-continuity-challenge-digest-matched") {
		return 0, errors.New("shell continuity challenge verification case is missing from the reconstruction phase")
	}
	if len(seenInteractions) != 41 {
		return 0, fmt.Errorf("qualification profile has %d interactions, want 41", len(seenInteractions))
	}
	return len(seenInteractions), nil
}

func validateLimits(limits limits) error {
	if limits.MaxAdmittedExecOperations > limits.MaxExecRequests ||
		limits.MaxAdmittedArtifactOperations > limits.MaxArtifactRequests ||
		limits.MaxDistinctProviderMutations > limits.MaxProviderMutationWriteAttempts ||
		limits.MaxExecutionSeconds+limits.MaxCleanupSeconds != limits.MaxTotalWallClockSeconds ||
		limits.MaxEvidenceTotalBytes < limits.MaxEvidenceFileBytes || limits.MaxEvidenceFiles < 2 {
		return errors.New("qualification profile contains incoherent cross-field limits")
	}
	return nil
}

func validateArtifacts(artifacts []artifactIdentityRequirement, groups [][]string) error {
	seen := make(map[string]artifactIdentityRequirement, len(artifacts))
	for _, artifact := range artifacts {
		if _, duplicate := seen[artifact.ArtifactID]; duplicate {
			return fmt.Errorf("qualification profile duplicates artifact identity %q", artifact.ArtifactID)
		}
		seen[artifact.ArtifactID] = artifact
	}
	expected := map[string]artifactIdentityRequirement{
		"provider":              {Owner: "sandbox_runtime_repository", TrustDomain: "provider_release", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"external_caller":       {Owner: "external_caller_owner", TrustDomain: "external_caller_release", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"qualification_adapter": {Owner: "external_caller_owner", TrustDomain: "external_caller_release", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"caller_gateway":        {Owner: "external_caller_owner", TrustDomain: "external_caller_release", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"runtime_image":         {Owner: "sandbox_runtime_repository", TrustDomain: "provider_release", DigestSubject: "oci_manifest_or_index", ObservedBy: "resource_inspector", SourceIdentityRequired: true},
		"qualification_harness": {Owner: "sandbox_runtime_repository", TrustDomain: "qualification_operator", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"provider_observer":     {Owner: "sandbox_runtime_repository", TrustDomain: "qualification_operator", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"gateway_observer":      {Owner: "sandbox_runtime_repository", TrustDomain: "qualification_operator", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"process_supervisor":    {Owner: "sandbox_runtime_repository", TrustDomain: "qualification_operator", DigestSubject: "executable_raw_bytes", ObservedBy: "resource_inspector", SourceIdentityRequired: true},
		"resource_inspector":    {Owner: "sandbox_runtime_repository", TrustDomain: "qualification_operator", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
		"teardown":              {Owner: "qualification_operator", TrustDomain: "qualification_operator", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceIdentityRequired: true},
	}
	for artifactID, want := range expected {
		got, ok := seen[artifactID]
		if !ok {
			return fmt.Errorf("qualification profile is missing artifact identity %q", artifactID)
		}
		got.ArtifactID = ""
		if got != want {
			return fmt.Errorf("qualification profile artifact %q has an invalid ownership, trust, digest, or observer binding", artifactID)
		}
	}
	isolated := make(map[string]struct{})
	for _, group := range groups {
		if len(group) != 1 {
			return errors.New("qualification profile process isolation groups must be singletons")
		}
		if _, duplicate := isolated[group[0]]; duplicate {
			return fmt.Errorf("qualification profile duplicates process isolation member %q", group[0])
		}
		isolated[group[0]] = struct{}{}
	}
	for _, required := range []string{"provider", "external_caller", "qualification_adapter", "caller_gateway", "qualification_harness", "provider_observer", "gateway_observer", "process_supervisor", "resource_inspector", "teardown"} {
		if _, ok := isolated[required]; !ok {
			return fmt.Errorf("qualification profile does not isolate process %q", required)
		}
	}
	return nil
}

func validateReplay(candidate interaction, originals map[string]interaction) error {
	original, exists := originals[candidate.LogicalRequestID]
	if candidate.ReplayOf == nil {
		if exists {
			return fmt.Errorf("interaction %q repeats logical request %q without replay_of", candidate.InteractionID, candidate.LogicalRequestID)
		}
		if candidate.Surface == "provider_http" && candidate.Method == "POST" && !contains(candidate.CountsToward, "distinct_provider_mutations") {
			return fmt.Errorf("Provider mutation %q is not counted as a distinct logical mutation", candidate.InteractionID)
		}
		return nil
	}
	if !exists {
		return fmt.Errorf("interaction %q replays missing or future logical request %q", candidate.InteractionID, candidate.LogicalRequestID)
	}
	if candidate.Surface != "provider_http" || candidate.Method != "POST" || candidate.RouteTemplate != "/v1/sandboxes" {
		return fmt.Errorf("interaction %q replays an operation outside the coding/shell sandbox-create replay", candidate.InteractionID)
	}
	if *candidate.ReplayOf != candidate.LogicalRequestID || candidate.Actor != original.Actor ||
		candidate.Surface != original.Surface || candidate.Method != original.Method || candidate.RouteTemplate != original.RouteTemplate {
		return fmt.Errorf("interaction %q changes actor or target across replay", candidate.InteractionID)
	}
	if contains(candidate.CountsToward, "distinct_provider_mutations") {
		return fmt.Errorf("interaction %q counts a replay as a distinct mutation", candidate.InteractionID)
	}
	return nil
}

func validateObservations(interaction interaction, caseSources map[string]struct{}) error {
	seen := make(map[string]struct{}, len(interaction.RequiredObservations))
	requiredOracle := "provider_observer"
	if interaction.Surface == "caller_gateway" {
		requiredOracle = "gateway_observer"
	}
	hasRequiredOracle := false
	for _, observation := range interaction.RequiredObservations {
		if _, duplicate := seen[observation.ObservationID]; duplicate {
			return fmt.Errorf("interaction %q duplicates observation %q", interaction.InteractionID, observation.ObservationID)
		}
		seen[observation.ObservationID] = struct{}{}
		if _, ok := caseSources[observation.Source]; !ok {
			return fmt.Errorf("interaction %q observation %q uses source %q absent from its case", interaction.InteractionID, observation.ObservationID, observation.Source)
		}
		if observation.Actor != interaction.Actor || observation.Subject != interaction.InteractionID || observation.Correlation != interaction.LogicalRequestID {
			return fmt.Errorf("interaction %q observation %q has an invalid actor, subject, or correlation binding", interaction.InteractionID, observation.ObservationID)
		}
		if observation.Source == requiredOracle {
			hasRequiredOracle = true
		}
	}
	if !hasRequiredOracle {
		return fmt.Errorf("interaction %q has no %s observation", interaction.InteractionID, requiredOracle)
	}
	return nil
}

func validateInteraction(interaction interaction, openAPI any) error {
	if interaction.MaxWireAttempts < 1 || interaction.LogicalRequestID == "" {
		return fmt.Errorf("interaction %q has invalid occurrence accounting", interaction.InteractionID)
	}
	if interaction.ReplayOf != nil && *interaction.ReplayOf != interaction.LogicalRequestID {
		return fmt.Errorf("interaction %q replay target differs from its logical request", interaction.InteractionID)
	}
	if err := validateInteractionAccounting(interaction); err != nil {
		return err
	}
	switch interaction.Surface {
	case "provider_http":
		if _, ok := codingShellV1ProviderOperations[providerOperation{method: interaction.Method, route: interaction.RouteTemplate}]; !ok {
			return fmt.Errorf("interaction %q uses a Provider operation outside the coding/shell profile", interaction.InteractionID)
		}
		for _, outcome := range interaction.Outcomes {
			if outcome.Transport == "tls-rejected" {
				if outcome.StatusCode != nil || interaction.RouteTemplate != "/v1/capabilities" {
					return fmt.Errorf("interaction %q has an invalid TLS outcome", interaction.InteractionID)
				}
			} else if err := validateProviderOutcome(interaction, outcome, false, openAPI); err != nil {
				return err
			}
		}
		for _, outcome := range interaction.TransientOutcomes {
			if err := validateProviderOutcome(interaction, outcome, true, openAPI); err != nil {
				return err
			}
		}
	case "caller_gateway":
		if !strings.HasPrefix(interaction.RouteTemplate, "consumer-defined:") || len(interaction.TransientOutcomes) != 0 {
			return fmt.Errorf("interaction %q has an invalid caller Gateway boundary", interaction.InteractionID)
		}
		for _, outcome := range interaction.Outcomes {
			if outcome.StatusCode != nil || outcome.ErrorCodePolicy != "none" || len(outcome.ErrorCodes) != 0 {
				return fmt.Errorf("interaction %q standardizes caller-owned Gateway HTTP behavior", interaction.InteractionID)
			}
		}
	default:
		return fmt.Errorf("interaction %q uses unsupported surface %q", interaction.InteractionID, interaction.Surface)
	}
	for _, outcome := range interaction.Outcomes {
		if outcome.Retryable == nil || *outcome.Retryable {
			return fmt.Errorf("interaction %q has a retryable final outcome", interaction.InteractionID)
		}
		if err := validateErrorPolicy(interaction.InteractionID, outcome); err != nil {
			return err
		}
	}
	for _, outcome := range interaction.TransientOutcomes {
		if outcome.Retryable == nil || !*outcome.Retryable {
			return fmt.Errorf("interaction %q has a non-retryable transient outcome", interaction.InteractionID)
		}
		if err := validateErrorPolicy(interaction.InteractionID, outcome); err != nil {
			return err
		}
	}
	return nil
}

func validateProviderOutcome(interaction interaction, outcome outcome, transient bool, openAPI any) error {
	if outcome.Transport == "transport-unavailable" || outcome.Transport == "deadline-exceeded" {
		if !transient || outcome.StatusCode != nil || outcome.ErrorCodePolicy != "none" || len(outcome.ErrorCodes) != 0 ||
			outcome.RetryAfterRequired == nil || *outcome.RetryAfterRequired {
			return fmt.Errorf("interaction %q has an invalid non-HTTP transient outcome", interaction.InteractionID)
		}
		return nil
	}
	if outcome.Transport != "http-response" || outcome.StatusCode == nil || !openAPIResponseExists(openAPI, interaction.RouteTemplate, interaction.Method, *outcome.StatusCode) {
		return fmt.Errorf("interaction %q expects a response absent from locked OpenAPI", interaction.InteractionID)
	}
	status := *outcome.StatusCode
	isTransientStatus := status == 429 || status == 503
	if transient != isTransientStatus {
		return fmt.Errorf("interaction %q misclassifies HTTP %d as a %s outcome", interaction.InteractionID, status, map[bool]string{true: "transient", false: "final"}[transient])
	}
	if status >= 200 && status < 300 {
		if outcome.ErrorCodePolicy != "none" {
			return fmt.Errorf("interaction %q assigns error policy %q to successful HTTP %d", interaction.InteractionID, outcome.ErrorCodePolicy, status)
		}
	} else if outcome.ErrorCodePolicy == "none" {
		return fmt.Errorf("interaction %q omits the error policy for HTTP %d", interaction.InteractionID, status)
	}
	if outcome.RetryAfterRequired != nil && *outcome.RetryAfterRequired != openAPIResponseHasRetryAfter(openAPI, interaction.RouteTemplate, interaction.Method, status) {
		return fmt.Errorf("interaction %q has an incorrect Retry-After requirement", interaction.InteractionID)
	}
	return nil
}

func validateErrorPolicy(interactionID string, outcome outcome) error {
	switch outcome.ErrorCodePolicy {
	case "none", "contract-unconstrained":
		if len(outcome.ErrorCodes) != 0 {
			return fmt.Errorf("interaction %q has error codes under policy %q", interactionID, outcome.ErrorCodePolicy)
		}
	case "exact":
		if len(outcome.ErrorCodes) != 1 {
			return fmt.Errorf("interaction %q exact error policy requires one code", interactionID)
		}
	case "one-of-exact":
		if len(outcome.ErrorCodes) < 2 {
			return fmt.Errorf("interaction %q one-of-exact error policy requires multiple codes", interactionID)
		}
	default:
		return fmt.Errorf("interaction %q has unknown error policy %q", interactionID, outcome.ErrorCodePolicy)
	}
	for _, code := range outcome.ErrorCodes {
		if _, ok := qualificationV1ExactErrorCodes[code]; !ok {
			return fmt.Errorf("interaction %q uses error code %q outside the locked qualification profile", interactionID, code)
		}
		if outcome.StatusCode == nil || !errorCodeAllowedForStatus(code, *outcome.StatusCode) {
			return fmt.Errorf("interaction %q binds error code %q to an invalid status", interactionID, code)
		}
	}
	return nil
}

func validateInteractionAccounting(interaction interaction) error {
	want := make(map[string]struct{})
	add := func(counter string) { want[counter] = struct{}{} }
	switch interaction.Surface {
	case "provider_http":
		add("provider_http_requests")
		if interaction.Method == "POST" {
			add("provider_mutation_write_attempts")
			if interaction.ReplayOf == nil {
				add("distinct_provider_mutations")
			}
			switch interaction.RouteTemplate {
			case "/v1/sandboxes":
				if interaction.ReplayOf == nil && hasFinalStatus(interaction, 202) {
					add("sandboxes")
				}
			case "/v1/sandboxes/{sandbox_id}/exec":
				add("exec_requests")
				if hasFinalStatus(interaction, 202) {
					add("admitted_exec_operations")
				}
			case "/v1/sandboxes/{sandbox_id}/runtime-sessions":
				if hasFinalStatus(interaction, 202) {
					add("terminal_sessions")
				}
			case "/v1/sandboxes/{sandbox_id}/artifacts:stage":
				add("artifact_requests")
				if hasFinalStatus(interaction, 202) {
					add("admitted_artifact_operations")
				}
			}
		}
	case "caller_gateway":
		if interaction.Method == "CONNECT" {
			add("gateway_connection_attempts")
		} else if interaction.Method == "CONTROL" {
			add("gateway_mutation_write_attempts")
		}
	}
	got := stringSet(interaction.CountsToward)
	if len(got) != len(want) {
		return fmt.Errorf("interaction %q has counters unrelated to its route or outcome", interaction.InteractionID)
	}
	for counter := range want {
		if _, ok := got[counter]; !ok {
			return fmt.Errorf("interaction %q is missing counter %q", interaction.InteractionID, counter)
		}
	}
	return nil
}

func hasFinalStatus(interaction interaction, status int) bool {
	for _, outcome := range interaction.Outcomes {
		if outcome.StatusCode != nil && *outcome.StatusCode == status {
			return true
		}
	}
	return false
}

func caseHasObservation(candidate caseDefinition, observationID string) bool {
	for _, interaction := range candidate.Interactions {
		for _, observation := range interaction.RequiredObservations {
			if observation.ObservationID == observationID {
				return true
			}
		}
	}
	return false
}

func errorCodeAllowedForStatus(code string, status int) bool {
	switch status {
	case 403:
		return code == "SANDBOX_FORBIDDEN"
	case 404:
		return code == "SANDBOX_NOT_FOUND"
	case 409:
		return code == "SANDBOX_CONFLICT" || code == "SANDBOX_STALE_FENCING_TOKEN"
	default:
		return false
	}
}

func validateAccounting(limits limits, counts map[string]int) error {
	exact := map[string]int{
		"sandboxes":                       limits.MaxSandboxes,
		"distinct_provider_mutations":     limits.MaxDistinctProviderMutations,
		"exec_requests":                   limits.MaxExecRequests,
		"admitted_exec_operations":        limits.MaxAdmittedExecOperations,
		"terminal_sessions":               limits.MaxTerminalSessions,
		"artifact_requests":               limits.MaxArtifactRequests,
		"admitted_artifact_operations":    limits.MaxAdmittedArtifactOperations,
		"gateway_mutation_write_attempts": limits.MaxGatewayMutationWriteAttempts,
	}
	for counter, want := range exact {
		if counts[counter] != want {
			return fmt.Errorf("qualification profile counter %q has %d logical interactions, want %d", counter, counts[counter], want)
		}
	}
	if counts["provider_mutation_write_attempts"] > limits.MaxProviderMutationWriteAttempts ||
		counts["provider_http_requests"] > limits.MaxProviderHTTPRequests ||
		counts["gateway_connection_attempts"] > limits.MaxGatewayConnectionAttempts {
		return errors.New("qualification profile base interactions exceed a global attempt limit")
	}
	return nil
}

func openAPIResponseExists(document any, route, method string, status int) bool {
	response, ok := openAPIResponse(document, route, method, status)
	return ok && response != nil
}

func openAPIResponseHasRetryAfter(document any, route, method string, status int) bool {
	response, ok := openAPIResponse(document, route, method, status)
	if !ok {
		return false
	}
	headers, ok := response["headers"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = headers["Retry-After"]
	return ok
}

func openAPIResponse(document any, route, method string, status int) (map[string]any, bool) {
	root, ok := document.(map[string]any)
	if !ok {
		return nil, false
	}
	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return nil, false
	}
	pathItem, ok := paths[route].(map[string]any)
	if !ok {
		return nil, false
	}
	operation, ok := pathItem[strings.ToLower(method)].(map[string]any)
	if !ok {
		return nil, false
	}
	responses, ok := operation["responses"].(map[string]any)
	if !ok {
		return nil, false
	}
	response, ok := responses[strconv.Itoa(status)].(map[string]any)
	return response, ok
}

func readRepositoryFile(root, relative string, maximum int64) ([]byte, error) {
	if !fs.ValidPath(relative) || relative == "." || filepath.IsAbs(relative) {
		return nil, errors.New("repository path must be a normalized relative path")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root symlinks: %w", err)
	}
	candidate := filepath.Join(root, filepath.FromSlash(relative))
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, fmt.Errorf("resolve repository file: %w", err)
	}
	if resolved != candidate {
		return nil, errors.New("repository file path must not contain symlinks")
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("repository file escapes the source root")
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maximum {
		return nil, fmt.Errorf("repository file must be regular and between 1 and %d bytes", maximum)
	}
	file, err := os.Open(candidate)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > maximum {
		return nil, errors.New("repository file changed while opening")
	}
	document, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(document)) > maximum {
		return nil, fmt.Errorf("repository file exceeds %d bytes", maximum)
	}
	return document, nil
}

func decodeStrictJSON(document []byte, destination any) error {
	if !utf8.Valid(document) {
		return errors.New("JSON must be valid UTF-8")
	}
	if err := validateUnicodeEscapes(document); err != nil {
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
	decoder = json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func validateUnicodeEscapes(document []byte) error {
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
			codePoint, ok := decodeHexQuad(document, index+2)
			if !ok {
				continue
			}
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if index+11 >= len(document) || document[index+6] != '\\' || document[index+7] != 'u' {
					return errors.New("JSON contains an invalid Unicode surrogate escape")
				}
				low, ok := decodeHexQuad(document, index+8)
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

func decodeHexQuad(document []byte, start int) (uint16, bool) {
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
		return consumeDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeDelimiter(decoder, ']')
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func consumeDelimiter(decoder *json.Decoder, expected json.Delim) error {
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

func rawDigest(document []byte) string {
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
