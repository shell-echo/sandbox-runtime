// Package qualificationreport validates a coding/shell external-caller report
// against the repository-owned profile and its bounded evidence root.
package qualificationreport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/evidencefiles"
	"github.com/shell-echo/sandbox-runtime/internal/jsonschemaecma"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const (
	ReportSchemaPath             = "qualification/external-caller-coding-shell-v1/report.schema.json"
	ReportSchemaID               = "urn:shell-echo:sandbox-runtime:qualification:external-caller-coding-shell-report:v1"
	ValidatorSemanticsPath       = "qualification/external-caller-coding-shell-v1/validator.semantics.json"
	AdapterProtocolID            = "sandbox-runtime-external-caller-adapter-v1"
	AdapterProtocolVersion       = "1.0.0"
	AdapterProtocolSchemaPath    = "qualification/external-caller-coding-shell-v1/adapter-protocol.schema.json"
	AdapterProtocolSemanticsPath = "qualification/external-caller-coding-shell-v1/adapter-protocol.semantics.json"

	ExpectedReportSchemaDigest             = "sha256:5d97e10c8b5b2f365e275e78868d5a35d78bbdffdec05ea2f18b5c947cd429f6"
	ExpectedValidatorSemanticsDigest       = "sha256:bc0b5be7aefcebb6a71871d9724cd671235b6ef2bf453a1954313547ad379ed9"
	ExpectedAdapterProtocolSchemaDigest    = "sha256:fdee270ca27003693b2ce504da769c9779825312e1dd4e06b5caf8578f5ee03c"
	ExpectedAdapterProtocolSemanticsDigest = "sha256:997c49cd1a5b2c050d48333a973dd78b611221f869bf709cf6d1a8d771795a99"
	ReportFileName                         = "report.json"
	TranscriptSchemaPath                   = "qualification/external-caller-coding-shell-v1/adapter-transcript.schema.json"
	ExpectedTranscriptSchemaDigest         = "sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293"
	ReceiptFileName                        = "receipt.json"
	maxReportBytes                         = 2 << 20
)

// Result is the sanitized result of validating one report and its evidence
// root. It intentionally contains no caller-owned secrets or raw diagnostics.
type Result struct {
	ReportID          string
	InvocationID      string
	RuntimeCommitment string
	ReportDigest      string
	PayloadInventory  string
	ReceiptFile       string
	RunOutcome        string
	ValidationOutcome string
	FileCount         int
	TotalBytes        int64
}

type reportDocument struct {
	FormatVersion    int                `json:"format_version"`
	ReportType       string             `json:"report_type"`
	ReportVersion    string             `json:"report_version"`
	ReportID         string             `json:"report_id"`
	Profile          profileIdentity    `json:"profile"`
	Contract         contractIdentity   `json:"contract"`
	Capability       map[string]any     `json:"capability_selection"`
	SandboxResources *sandboxResources  `json:"sandbox_resources"`
	Topology         map[string]any     `json:"topology"`
	Artifacts        []artifactIdentity `json:"artifacts"`
	Configurations   []configuration    `json:"configurations"`
	Invocation       invocation         `json:"invocation"`
	Phases           []phase            `json:"phases"`
	ScenarioResults  []scenarioResult   `json:"scenario_results"`
	Observations     []observation      `json:"observations"`
	Counters         counters           `json:"counters"`
	Cleanup          cleanup            `json:"cleanup"`
	Evidence         evidence           `json:"evidence"`
	Claims           claims             `json:"claims"`
	RunOutcome       runOutcome         `json:"run_outcome"`
	Timestamps       timestamps         `json:"timestamps"`
}

type profileIdentity struct {
	ProfileID           string `json:"profile_id"`
	ProfileVersion      string `json:"profile_version"`
	ProfileDigest       string `json:"profile_digest"`
	SchemaDigest        string `json:"schema_digest"`
	SchemaDigestProfile string `json:"schema_digest_profile"`
}

type suiteIdentity struct {
	SuiteID            string `json:"suite_id"`
	SuiteVersion       string `json:"suite_version"`
	SuiteDigest        string `json:"suite_digest"`
	SuiteDigestProfile string `json:"suite_digest_profile"`
	ProfileID          string `json:"profile_id"`
	CaseCount          int    `json:"case_count"`
	Exercised          bool   `json:"exercised"`
	Outcome            string `json:"outcome"`
}

type contractIdentity struct {
	Namespace           string        `json:"namespace"`
	Version             string        `json:"version"`
	Revision            string        `json:"revision"`
	Tree                string        `json:"tree"`
	ManifestDigest      string        `json:"manifest_digest"`
	OpenAPIDigest       string        `json:"openapi_digest"`
	SemanticRulesDigest string        `json:"semantic_rules_digest"`
	LocalSuite          suiteIdentity `json:"local_suite"`
	RemoteSuite         suiteIdentity `json:"remote_discovery_suite"`
}

type artifactIdentity struct {
	ArtifactID    string          `json:"artifact_id"`
	Owner         string          `json:"owner"`
	TrustDomain   string          `json:"trust_domain"`
	DigestSubject string          `json:"digest_subject"`
	Digest        *string         `json:"digest"`
	ObservedBy    string          `json:"observed_by"`
	Source        *sourceIdentity `json:"source_identity"`
}

type sourceIdentity struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Immutable bool   `json:"immutable"`
}

type configuration struct {
	ID            string  `json:"configuration_id"`
	Digest        *string `json:"digest"`
	DigestProfile string  `json:"digest_profile"`
	Sanitized     bool    `json:"sanitized"`
	ObservedBy    string  `json:"observed_by"`
}

type processIdentity struct {
	Component           string `json:"component"`
	ProcessID           string `json:"process_id"`
	ExecutableDigest    string `json:"executable_digest"`
	ConfigurationDigest string `json:"configuration_digest"`
	ObservedBy          string `json:"observed_by"`
}

type startupIdentity struct {
	CallerRelease                  *sourceIdentity `json:"caller_release_identity"`
	AdapterRelease                 *sourceIdentity `json:"adapter_release_identity"`
	ContractRevision               string          `json:"contract_revision"`
	ContractTree                   string          `json:"contract_tree"`
	ProfileID                      string          `json:"profile_id"`
	ProfileDigest                  string          `json:"profile_digest"`
	AdapterProtocolID              string          `json:"adapter_protocol_id"`
	AdapterProtocolVersion         string          `json:"adapter_protocol_version"`
	AdapterProtocolSchemaDigest    string          `json:"adapter_protocol_schema_digest"`
	AdapterProtocolSemanticsDigest string          `json:"adapter_protocol_semantics_digest"`
	HarnessInjected                bool            `json:"expected_values_injected_by_harness"`
}

type adapterTranscript struct {
	Digest          string   `json:"transcript_digest"`
	DigestProfile   string   `json:"transcript_digest_profile"`
	InvocationIDs   []string `json:"invocation_ids"`
	AllowedFields   []string `json:"allowed_fields"`
	ForbiddenFields []string `json:"forbidden_fields"`
	Sanitized       bool     `json:"sanitized"`
	ObservedBy      string   `json:"observed_by"`
}

type shellChallenge struct {
	Digest                 string `json:"challenge_digest"`
	DigestProfile          string `json:"challenge_digest_profile"`
	EstablishedInCase      string `json:"established_in_case"`
	VerifiedInCase         string `json:"verified_in_case"`
	RawChallengeInEvidence bool   `json:"raw_challenge_in_evidence"`
}

type invocation struct {
	InvocationID               string             `json:"invocation_id"`
	RuntimeCommitmentDigest    string             `json:"runtime_commitment_digest"`
	InitialInvocationID        *string            `json:"initial_invocation_id"`
	ReconstructionInvocationID *string            `json:"reconstruction_invocation_id"`
	HarnessArtifactDigest      *string            `json:"harness_artifact_digest"`
	StartupIdentity            *startupIdentity   `json:"startup_identity"`
	InitialProcesses           []processIdentity  `json:"initial_processes"`
	ReconstructionProcesses    []processIdentity  `json:"reconstruction_processes"`
	RestartedComponents        []string           `json:"restarted_components"`
	PreservedStores            []string           `json:"preserved_stores"`
	HarnessReinjected          *bool              `json:"harness_reinjected_forbidden_bindings"`
	AdapterTranscript          *adapterTranscript `json:"adapter_transcript"`
	ShellChallenge             *shellChallenge    `json:"shell_continuity_challenge"`
}

type phase struct {
	PhaseID     string   `json:"phase_id"`
	Status      string   `json:"status"`
	ScenarioIDs []string `json:"scenario_ids"`
	StartedAt   *string  `json:"started_at"`
	FinishedAt  *string  `json:"finished_at"`
}

type reportOutcome struct {
	Transport         string  `json:"transport"`
	StatusCode        *int    `json:"status_code"`
	ErrorCode         *string `json:"error_code"`
	Retryable         bool    `json:"retryable"`
	RetryAfterPresent bool    `json:"retry_after_present"`
}

type interactionResult struct {
	InteractionID         string          `json:"interaction_id"`
	Surface               string          `json:"surface"`
	Actor                 string          `json:"actor"`
	Method                string          `json:"method"`
	RouteTemplate         string          `json:"route_template"`
	LogicalRequestID      string          `json:"logical_request_id"`
	ReplayOf              *string         `json:"replay_of"`
	WireAttempts          int             `json:"wire_attempts"`
	TransientOutcomes     []reportOutcome `json:"transient_outcomes"`
	FinalOutcome          reportOutcome   `json:"final_outcome"`
	MutationWriteObserved bool            `json:"mutation_write_observed"`
	ObservationIDs        []string        `json:"observation_ids"`
}

type assertionResult struct {
	ID     string `json:"assertion_id"`
	Result string `json:"result"`
}

type scenarioResult struct {
	CaseID         string              `json:"case_id"`
	PhaseID        string              `json:"phase_id"`
	Status         string              `json:"status"`
	StartedAt      *string             `json:"started_at"`
	FinishedAt     *string             `json:"finished_at"`
	Interactions   []interactionResult `json:"interactions"`
	Assertions     []assertionResult   `json:"assertions"`
	ObservationIDs []string            `json:"observation_ids"`
}

type observation struct {
	ID             string  `json:"observation_id"`
	Source         string  `json:"source"`
	Actor          string  `json:"actor"`
	Subject        string  `json:"subject"`
	Correlation    string  `json:"correlation"`
	Result         string  `json:"result"`
	EvidenceDigest *string `json:"evidence_digest"`
}

type counters struct {
	ProviderHTTPRequests          int `json:"provider_http_requests"`
	ProviderMutationWriteAttempts int `json:"provider_mutation_write_attempts"`
	DistinctProviderMutations     int `json:"distinct_provider_mutations"`
	Sandboxes                     int `json:"sandboxes"`
	ExecRequests                  int `json:"exec_requests"`
	AdmittedExecOperations        int `json:"admitted_exec_operations"`
	TerminalSessions              int `json:"terminal_sessions"`
	ArtifactRequests              int `json:"artifact_requests"`
	AdmittedArtifactOperations    int `json:"admitted_artifact_operations"`
	GatewayConnectionAttempts     int `json:"gateway_connection_attempts"`
	GatewayMutationWriteAttempts  int `json:"gateway_mutation_write_attempts"`
}

type sandboxResources struct {
	CPUMillis             int `json:"cpu_millis"`
	MemoryBytes           int `json:"memory_bytes"`
	EphemeralStorageBytes int `json:"ephemeral_storage_bytes"`
	PIDs                  int `json:"pids"`
}

type queryScope struct {
	Digest                       *string  `json:"scope_digest"`
	DigestProfile                string   `json:"scope_digest_profile"`
	TargetDigest                 *string  `json:"target_digest"`
	RunNamespaceDigest           *string  `json:"run_namespace_digest"`
	OwnershipSelectorDigest      *string  `json:"ownership_selector_digest"`
	ResourceKinds                []string `json:"resource_kinds"`
	InspectorArtifactDigest      *string  `json:"inspector_artifact_digest"`
	InspectorConfigurationDigest *string  `json:"inspector_configuration_digest"`
	ExcludesHarnessControlPlane  bool     `json:"excludes_harness_control_plane"`
}

type resourceInventory struct {
	QueryScopeDigest *string  `json:"query_scope_digest"`
	Digest           *string  `json:"inventory_digest"`
	DigestProfile    string   `json:"inventory_digest_profile"`
	RunOwnedCount    int      `json:"run_owned_resource_count"`
	Stable           bool     `json:"stable"`
	SampledAt        []string `json:"sampled_at"`
}

type cleanup struct {
	Authority             string             `json:"authority"`
	MutationWriteObserved bool               `json:"mutation_write_observed"`
	CleanupRequired       bool               `json:"cleanup_required"`
	QueryScope            *queryScope        `json:"query_scope"`
	Baseline              *resourceInventory `json:"baseline"`
	TeardownAttempts      int                `json:"teardown_attempts"`
	TeardownCompleted     bool               `json:"teardown_completed"`
	PostTeardown          *resourceInventory `json:"post_teardown"`
	StabilitySamples      int                `json:"stability_samples"`
	StabilityIntervalMS   int                `json:"stability_interval_milliseconds"`
	Outcome               string             `json:"outcome"`
}

type sanitization struct {
	Required                  bool   `json:"required"`
	Status                    string `json:"status"`
	ForbiddenMaterialDetected bool   `json:"forbidden_material_detected"`
	ScannerIdentity           string `json:"scanner_identity"`
}

type evidence struct {
	RootRelative                  string                `json:"root_relative"`
	PayloadInventory              []evidencefiles.Entry `json:"payload_inventory"`
	PayloadInventoryDigest        string                `json:"payload_inventory_digest"`
	PayloadInventoryDigestProfile string                `json:"payload_inventory_digest_profile"`
	FileCount                     int                   `json:"file_count_including_report_and_receipt"`
	TotalBytes                    int64                 `json:"total_bytes_including_report_and_receipt"`
	Sanitization                  sanitization          `json:"sanitization"`
	Boundary                      string                `json:"boundary"`
}

type claimAssertion struct {
	ID     string `json:"assertion_id"`
	Owner  string `json:"owner"`
	Result string `json:"result"`
}
type trustedInput struct {
	ID     string `json:"input_id"`
	Source string `json:"source"`
	Digest string `json:"digest"`
}
type claims struct {
	CallerAssertions []claimAssertion `json:"caller_assertions"`
	TrustedInputs    []trustedInput   `json:"trusted_inputs"`
	SuiteExecution   struct {
		Local  bool `json:"local_suite_exercised"`
		Remote bool `json:"remote_discovery_suite_exercised"`
	} `json:"suite_execution"`
	NonClaims []string `json:"non_claims"`
}

type runOutcome struct {
	Outcome            string         `json:"outcome"`
	ReasonCodes        []string       `json:"reason_codes"`
	ScenarioCounts     scenarioCounts `json:"scenario_counts"`
	CleanupSatisfied   bool           `json:"cleanup_satisfied"`
	IdentityComplete   bool           `json:"identity_complete"`
	SanitizationPassed bool           `json:"sanitization_passed"`
}

type scenarioCounts struct {
	Passed      int `json:"passed"`
	Failed      int `json:"failed"`
	Incomplete  int `json:"incomplete"`
	NotExecuted int `json:"not_executed"`
}

type timestamps struct {
	RunStartedAt        *string `json:"run_started_at"`
	ExecutionStartedAt  *string `json:"execution_started_at"`
	ExecutionFinishedAt *string `json:"execution_finished_at"`
	CleanupStartedAt    *string `json:"cleanup_started_at"`
	CleanupFinishedAt   *string `json:"cleanup_finished_at"`
	RunFinishedAt       *string `json:"run_finished_at"`
}

type scenarioTiming struct {
	CaseID     string  `json:"case_id"`
	PhaseID    string  `json:"phase_id"`
	StartedAt  *string `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
}

type cleanupTimestamps struct {
	StartedAt  *string `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
}

type profileDocument struct {
	CapabilitySelection map[string]any        `json:"capability_selection"`
	Topology            map[string]any        `json:"topology"`
	Artifacts           []profileArtifact     `json:"artifact_identity_requirements"`
	Limits              profileLimits         `json:"limits"`
	Reconstruction      profileReconstruction `json:"reconstruction"`
	Contract            profileContract       `json:"contract"`
	Cleanup             profileCleanup        `json:"cleanup"`
	Evidence            profileEvidence       `json:"evidence"`
	Phases              []profilePhase        `json:"phases"`
	RequiredNonClaims   []string              `json:"required_non_claims"`
}

type profileContract struct {
	Namespace           string       `json:"namespace"`
	Version             string       `json:"version"`
	Revision            string       `json:"revision"`
	Tree                string       `json:"tree"`
	ManifestDigest      string       `json:"manifest_digest"`
	OpenAPIDigest       string       `json:"openapi_digest"`
	SemanticRulesDigest string       `json:"semantic_rules_digest"`
	LocalSuite          profileSuite `json:"local_suite"`
	RemoteSuite         profileSuite `json:"remote_discovery_suite"`
}

type profileSuite struct {
	SuiteID            string `json:"suite_id"`
	SuiteVersion       string `json:"suite_version"`
	SuiteDigest        string `json:"suite_digest"`
	SuiteDigestProfile string `json:"suite_digest_profile"`
	ProfileID          string `json:"profile_id"`
	CaseCount          int    `json:"case_count"`
}

type profileCleanup struct {
	Authority              string   `json:"authority"`
	PreRunBaselineRequired bool     `json:"pre_run_baseline_required"`
	QueryDigestProfile     string   `json:"query_scope_digest_profile"`
	ExcludesControlPlane   bool     `json:"query_scope_excludes_harness_control_plane"`
	InspectorScope         []string `json:"inspector_scope"`
	InventoryDigestProfile string   `json:"inventory_digest_profile"`
	BaselineCount          int      `json:"pre_run_run_owned_resource_count"`
	PostTeardownCount      int      `json:"post_teardown_run_owned_resource_count"`
	StabilitySamples       int      `json:"post_teardown_stability_samples"`
	StabilityIntervalMS    int      `json:"post_teardown_stability_interval_milliseconds"`
}

type profileEvidence struct {
	PayloadDigestProfile       string   `json:"payload_inventory_digest_profile"`
	FileDigestProfile          string   `json:"file_digest_profile"`
	ExcludedFiles              []string `json:"payload_inventory_excludes"`
	RequiredInventories        []string `json:"required_identity_inventories"`
	ConfigurationDigestProfile string   `json:"configuration_digest_profile"`
}
type profileArtifact struct {
	ID             string `json:"artifact_id"`
	Owner          string `json:"owner"`
	TrustDomain    string `json:"trust_domain"`
	DigestSubject  string `json:"digest_subject"`
	ObservedBy     string `json:"observed_by"`
	SourceRequired bool   `json:"source_identity_required"`
}

type profileLimits struct {
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
	MaxExecutionSeconds              int `json:"max_execution_seconds"`
	MaxCleanupSeconds                int `json:"max_cleanup_seconds"`
	MaxTotalWallClockSeconds         int `json:"max_total_wall_clock_seconds"`
	MaxEvidenceFiles                 int `json:"max_evidence_files"`
	MaxEvidenceFileBytes             int `json:"max_evidence_file_bytes"`
	MaxEvidenceTotalBytes            int `json:"max_evidence_total_bytes"`
	SandboxCPUMillis                 int `json:"sandbox_cpu_millis"`
	SandboxMemoryBytes               int `json:"sandbox_memory_bytes"`
	SandboxEphemeralStorageBytes     int `json:"sandbox_ephemeral_storage_bytes"`
	SandboxPIDs                      int `json:"sandbox_pids"`
}

type profileReconstruction struct {
	RestartComponents    []string `json:"restart_components"`
	PreserveStores       []string `json:"preserve_stores"`
	ReinjectionForbidden []string `json:"harness_reinjection_forbidden"`
	AdapterInvocation    struct {
		AllowedFields  []string `json:"allowed_harness_fields"`
		ForbiddenMatch bool     `json:"forbidden_correlation_fields_match_harness_reinjection_forbidden"`
	} `json:"adapter_invocation"`
	ShellChallenge struct {
		Established string `json:"established_in_case"`
		Verified    string `json:"verified_in_case"`
	} `json:"shell_continuity_challenge"`
}

type profilePhase struct {
	PhaseID string        `json:"phase_id"`
	Cases   []profileCase `json:"cases"`
}

type profileCase struct {
	CaseID         string               `json:"case_id"`
	TimeoutSeconds int                  `json:"timeout_seconds"`
	DependsOn      []string             `json:"depends_on"`
	Assertions     []string             `json:"assertions"`
	Interactions   []profileInteraction `json:"interactions"`
}

type profileInteraction struct {
	ID              string               `json:"interaction_id"`
	Surface         string               `json:"surface"`
	Actor           string               `json:"actor"`
	Method          string               `json:"method"`
	Route           string               `json:"route_template"`
	Logical         string               `json:"logical_request_id"`
	Replay          *string              `json:"replay_of"`
	Counts          []string             `json:"counts_toward"`
	MaxWireAttempts int                  `json:"max_wire_attempts"`
	Outcomes        []profileOutcome     `json:"outcomes"`
	Transient       []profileOutcome     `json:"transient_outcomes"`
	Observations    []profileObservation `json:"required_observations"`
}

type profileObservation struct {
	ID          string `json:"observation_id"`
	Source      string `json:"source"`
	Actor       string `json:"actor"`
	Subject     string `json:"subject"`
	Correlation string `json:"correlation"`
}

type profileOutcome struct {
	Transport   string   `json:"transport"`
	StatusCode  *int     `json:"status_code"`
	ErrorPolicy string   `json:"error_code_policy"`
	ErrorCodes  []string `json:"error_codes"`
	Retryable   *bool    `json:"retryable"`
	RetryAfter  *bool    `json:"retry_after_required"`
}

// Verify validates evidenceRoot/report.json and emits receipt.json only after
// all schema, identity, semantic, inventory, and sanitization checks pass.
func Verify(ctx context.Context, evidenceRoot, sourceRoot string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	definition, err := qualificationprofile.VerifyCodingShellV1(ctx, sourceRoot)
	if err != nil {
		return Result{}, fmt.Errorf("qualification definition is not locked: %w", err)
	}
	if definition.ProfileDigest != qualificationprofile.ExpectedProfileDigest {
		return Result{}, errors.New("qualification profile identity mismatch")
	}
	schemaBytes, err := readSourceFile(sourceRoot, ReportSchemaPath, 2<<20)
	if err != nil {
		return Result{}, fmt.Errorf("read qualification report schema: %w", err)
	}
	schemaDigest := evidencefiles.RawDigest(schemaBytes)
	if schemaDigest != ExpectedReportSchemaDigest {
		return Result{}, fmt.Errorf("qualification report schema digest %s does not match trust anchor", schemaDigest)
	}
	semantics, err := loadValidatorSemantics(sourceRoot, schemaDigest)
	if err != nil {
		return Result{}, err
	}
	if err := validateEmbeddedTranscriptAuthority(sourceRoot, schemaBytes); err != nil {
		return Result{}, err
	}
	root, err := evidencefiles.OpenRoot(evidenceRoot)
	if err != nil {
		return Result{}, fmt.Errorf("open qualification evidence root: %w", err)
	}
	defer root.Close()
	if _, err := root.ReadFile(ReceiptFileName, evidencefiles.DefaultMaxFileBytes); err == nil {
		return Result{}, errors.New("qualification evidence already contains receipt.json")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, errors.New("qualification receipt path is not available")
	}
	reportBytes, err := root.ReadFile(ReportFileName, maxReportBytes)
	if err != nil {
		return Result{}, fmt.Errorf("read qualification report: %w", err)
	}
	var reportValue any
	if err := decodeStrictJSON(reportBytes, &reportValue); err != nil {
		return Result{}, fmt.Errorf("decode qualification report: %w", err)
	}
	if err := validateReportSchema(schemaBytes, reportValue); err != nil {
		return Result{}, err
	}
	encoded, err := json.Marshal(reportValue)
	if err != nil {
		return Result{}, errors.New("encode qualification report")
	}
	var report reportDocument
	if err := json.Unmarshal(encoded, &report); err != nil {
		return Result{}, errors.New("decode qualification report model")
	}
	profileBytes, err := readSourceFile(sourceRoot, qualificationprofile.ProfilePath, 2<<20)
	if err != nil {
		return Result{}, errors.New("read qualification profile")
	}
	locked, err := decodeLockedProfile(profileBytes)
	if err != nil {
		return Result{}, err
	}
	inventory, err := root.Read([]string{ReportFileName, ReceiptFileName}, evidencefiles.DefaultOptions())
	if err != nil {
		return Result{}, fmt.Errorf("read qualification evidence inventory: %w", err)
	}
	payloads, err := loadPayloads(root, inventory, schemaBytes, semantics)
	if err != nil {
		return Result{}, err
	}
	if err := validateSemantic(report, locked, definition, semantics, payloads); err != nil {
		return Result{}, err
	}
	if err := validateSanitizedBytes(reportBytes); err != nil {
		return Result{}, err
	}
	if err := validateSanitizedPayload(root, inventory); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if inventory.FileCount >= evidencefiles.DefaultMaxFiles || inventory.TotalBytes >= evidencefiles.DefaultMaxTotalBytes {
		return Result{}, errors.New("qualification evidence has no bounded receipt capacity")
	}
	receiptBytes, receipt, err := makeReceipt(report, reportBytes, inventory, semantics)
	if err != nil {
		return Result{}, err
	}
	if int64(len(receiptBytes))+inventory.TotalBytes > evidencefiles.DefaultMaxTotalBytes {
		return Result{}, errors.New("qualification evidence receipt exceeds total byte bound")
	}
	if err := validateEvidence(report, inventory, reportBytes, int64(len(receiptBytes))); err != nil {
		return Result{}, err
	}
	if err := validateReceiptSchema(schemaBytes, receipt); err != nil {
		return Result{}, err
	}
	stagedName, err := receiptStagingName()
	if err != nil {
		return Result{}, err
	}
	publication, err := root.Publish(stagedName, receiptBytes, evidencefiles.DefaultMaxFileBytes)
	if err != nil {
		return Result{}, fmt.Errorf("qualification receipt cannot be staged: %w", err)
	}
	finalInventory, err := root.Read([]string{ReportFileName, ReceiptFileName, stagedName}, evidencefiles.DefaultOptions())
	if err != nil {
		return Result{}, rejectStagedReceipt(publication, fmt.Errorf("verify final qualification evidence inventory: %w", err))
	}
	finalReportBytes, err := root.ReadFile(ReportFileName, maxReportBytes)
	finalReceiptBytes, receiptErr := publication.Read(evidencefiles.DefaultMaxFileBytes)
	if err != nil || receiptErr != nil || !bytes.Equal(finalReportBytes, reportBytes) || !bytes.Equal(finalReceiptBytes, receiptBytes) || finalInventory.FileCount != report.Evidence.FileCount || finalInventory.TotalBytes != report.Evidence.TotalBytes || finalInventory.Digest != inventory.Digest || !reflect.DeepEqual(finalInventory.Entries, inventory.Entries) {
		return Result{}, rejectStagedReceipt(publication, errors.New("qualification evidence changed while writing receipt"))
	}
	if err := commitQualificationReceipt(ctx, publication); err != nil {
		return Result{}, err
	}
	return Result{ReportID: report.ReportID, InvocationID: report.Invocation.InvocationID, RuntimeCommitment: report.Invocation.RuntimeCommitmentDigest, ReportDigest: evidencefiles.RawDigest(reportBytes), PayloadInventory: inventory.Digest, ReceiptFile: ReceiptFileName, RunOutcome: report.RunOutcome.Outcome, ValidationOutcome: "accepted", FileCount: finalInventory.FileCount, TotalBytes: finalInventory.TotalBytes}, nil
}

// VerifyRetained performs a read-only independent validation of a completed
// evidence root that already contains receipt.json. It recomputes every report,
// payload and receipt binding and requires the receipt's exact canonical bytes;
// it never creates, replaces or removes an entry.
func VerifyRetained(ctx context.Context, evidenceRoot, sourceRoot string) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("qualification retained verification requires context")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	definition, err := qualificationprofile.VerifyCodingShellV1(ctx, sourceRoot)
	if err != nil || definition.ProfileDigest != qualificationprofile.ExpectedProfileDigest {
		return Result{}, errors.New("qualification definition is not locked")
	}
	schemaBytes, err := readSourceFile(sourceRoot, ReportSchemaPath, 2<<20)
	if err != nil {
		return Result{}, fmt.Errorf("read qualification report schema: %w", err)
	}
	schemaDigest := evidencefiles.RawDigest(schemaBytes)
	if schemaDigest != ExpectedReportSchemaDigest {
		return Result{}, errors.New("qualification report schema identity mismatch")
	}
	semantics, err := loadValidatorSemantics(sourceRoot, schemaDigest)
	if err != nil {
		return Result{}, err
	}
	if err := validateEmbeddedTranscriptAuthority(sourceRoot, schemaBytes); err != nil {
		return Result{}, err
	}
	root, err := evidencefiles.OpenRoot(evidenceRoot)
	if err != nil {
		return Result{}, fmt.Errorf("open qualification evidence root: %w", err)
	}
	defer root.Close()
	reportBytes, err := root.ReadFile(ReportFileName, maxReportBytes)
	if err != nil {
		return Result{}, fmt.Errorf("read qualification report: %w", err)
	}
	receiptBytes, err := root.ReadFile(ReceiptFileName, evidencefiles.DefaultMaxFileBytes)
	if err != nil {
		return Result{}, fmt.Errorf("read qualification receipt: %w", err)
	}
	var reportValue any
	if err := decodeStrictJSON(reportBytes, &reportValue); err != nil || validateReportSchema(schemaBytes, reportValue) != nil {
		return Result{}, errors.New("qualification retained report is invalid")
	}
	encoded, err := json.Marshal(reportValue)
	if err != nil {
		return Result{}, errors.New("encode qualification retained report")
	}
	var report reportDocument
	if err := json.Unmarshal(encoded, &report); err != nil {
		return Result{}, errors.New("decode qualification retained report model")
	}
	profileBytes, err := readSourceFile(sourceRoot, qualificationprofile.ProfilePath, 2<<20)
	if err != nil {
		return Result{}, errors.New("read qualification profile")
	}
	locked, err := decodeLockedProfile(profileBytes)
	if err != nil {
		return Result{}, err
	}
	payloadInventory, err := root.Read([]string{ReportFileName, ReceiptFileName}, evidencefiles.DefaultOptions())
	if err != nil {
		return Result{}, fmt.Errorf("read qualification retained payload inventory: %w", err)
	}
	if payloadInventory.FileCount < 1 || payloadInventory.TotalBytes < int64(len(receiptBytes)) {
		return Result{}, errors.New("qualification retained evidence inventory is incomplete")
	}
	// evidencefiles.Inventory counts excluded files in FileCount/TotalBytes but
	// omits them from Entries/Digest. Reconstruct the validator's pre-receipt
	// view while retaining the exact payload entries and digest.
	payloadInventory.FileCount--
	payloadInventory.TotalBytes -= int64(len(receiptBytes))
	payloads, err := loadPayloads(root, payloadInventory, schemaBytes, semantics)
	if err != nil {
		return Result{}, err
	}
	if err := validateSemantic(report, locked, definition, semantics, payloads); err != nil {
		return Result{}, err
	}
	if err := validateSanitizedBytes(reportBytes); err != nil {
		return Result{}, err
	}
	if err := validateSanitizedPayload(root, payloadInventory); err != nil {
		return Result{}, err
	}
	if err := validateSanitizedBytes(receiptBytes); err != nil {
		return Result{}, err
	}
	if err := validateEvidence(report, payloadInventory, reportBytes, int64(len(receiptBytes))); err != nil {
		return Result{}, err
	}
	var receipt map[string]any
	if err := decodeStrictJSON(receiptBytes, &receipt); err != nil || validateReceiptSchema(schemaBytes, receipt) != nil {
		return Result{}, errors.New("qualification retained receipt is invalid")
	}
	validatedAt, ok := receipt["validated_at"].(string)
	if !ok {
		return Result{}, errors.New("qualification retained receipt timestamp is missing")
	}
	receiptTime, err := time.Parse("2006-01-02T15:04:05.000000000Z", validatedAt)
	if err != nil {
		return Result{}, errors.New("qualification retained receipt timestamp is invalid")
	}
	expectedReceipt, _, err := makeReceiptAt(report, reportBytes, payloadInventory, semantics, receiptTime)
	if err != nil || !bytes.Equal(expectedReceipt, receiptBytes) {
		return Result{}, errors.New("qualification retained receipt bindings differ")
	}
	finalInventory, err := root.Read(nil, evidencefiles.DefaultOptions())
	if err != nil || finalInventory.FileCount != report.Evidence.FileCount || finalInventory.TotalBytes != report.Evidence.TotalBytes {
		return Result{}, errors.New("qualification retained evidence inventory differs")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{
		ReportID: report.ReportID, InvocationID: report.Invocation.InvocationID,
		RuntimeCommitment: report.Invocation.RuntimeCommitmentDigest,
		ReportDigest:      evidencefiles.RawDigest(reportBytes), PayloadInventory: payloadInventory.Digest,
		ReceiptFile: ReceiptFileName, RunOutcome: report.RunOutcome.Outcome,
		ValidationOutcome: "accepted", FileCount: finalInventory.FileCount, TotalBytes: finalInventory.TotalBytes,
	}, nil
}

func decodeLockedProfile(profileBytes []byte) (profileDocument, error) {
	if err := qualificationprofile.VerifyCodingShellV1ProfileDocument(profileBytes); err != nil {
		return profileDocument{}, fmt.Errorf("qualification profile changed after definition verification: %w", err)
	}
	var lockedValue any
	if err := decodeStrictJSON(profileBytes, &lockedValue); err != nil {
		return profileDocument{}, errors.New("decode qualification profile")
	}
	lockedBytes, err := json.Marshal(lockedValue)
	if err != nil {
		return profileDocument{}, errors.New("encode qualification profile")
	}
	var locked profileDocument
	if err := json.Unmarshal(lockedBytes, &locked); err != nil {
		return profileDocument{}, errors.New("decode qualification profile model")
	}
	return locked, nil
}

func receiptStagingName() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("qualification receipt staging identity cannot be generated")
	}
	return ".receipt.pending-" + hex.EncodeToString(nonce[:]), nil
}

func commitQualificationReceipt(ctx context.Context, publication *evidencefiles.Publication) error {
	if err := ctx.Err(); err != nil {
		return rejectStagedReceipt(publication, err)
	}
	if err := publication.Commit(ReceiptFileName); err != nil {
		return rejectStagedReceipt(publication, fmt.Errorf("qualification receipt cannot be committed: %w", err))
	}
	return nil
}

func rejectStagedReceipt(publication *evidencefiles.Publication, cause error) error {
	if err := publication.Remove(); err != nil {
		return errors.Join(cause, fmt.Errorf("qualification receipt staging cleanup failed: %w", err))
	}
	return cause
}

func validateReportSchema(document []byte, value any) error {
	var schemaValue any
	if err := decodeStrictJSON(document, &schemaValue); err != nil {
		return fmt.Errorf("decode qualification report schema: %w", err)
	}
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(ReportSchemaID, schemaValue); err != nil {
		return fmt.Errorf("register qualification report schema: %w", err)
	}
	schema, err := compiler.Compile(ReportSchemaID)
	if err != nil {
		return fmt.Errorf("compile qualification report schema: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("qualification report schema validation failed: %w", err)
	}
	return nil
}

func validateReceiptSchema(document []byte, value any) error {
	var schemaValue any
	if err := decodeStrictJSON(document, &schemaValue); err != nil {
		return fmt.Errorf("decode qualification report schema for receipt: %w", err)
	}
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(ReportSchemaID, schemaValue); err != nil {
		return fmt.Errorf("register qualification receipt schema: %w", err)
	}
	schema, err := compiler.Compile(ReportSchemaID + "#/$defs/receipt")
	if err != nil {
		return fmt.Errorf("compile qualification receipt schema: %w", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("normalize qualification receipt: %w", err)
	}
	var normalized any
	if err := decodeStrictJSON(encoded, &normalized); err != nil {
		return fmt.Errorf("normalize qualification receipt: %w", err)
	}
	if err := schema.Validate(normalized); err != nil {
		return fmt.Errorf("qualification receipt schema validation failed: %w", err)
	}
	return nil
}

func validateSchemaReference(document []byte, reference string, value any) error {
	var schemaValue any
	if err := decodeStrictJSON(document, &schemaValue); err != nil {
		return fmt.Errorf("decode qualification report schema: %w", err)
	}
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(ReportSchemaID, schemaValue); err != nil {
		return fmt.Errorf("register qualification report schema: %w", err)
	}
	schema, err := compiler.Compile(ReportSchemaID + reference)
	if err != nil {
		return fmt.Errorf("compile qualification payload schema: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("qualification payload schema validation failed: %w", err)
	}
	return nil
}

func validateSemantic(report reportDocument, profile profileDocument, definition qualificationprofile.Report, semantics validatorSemantics, payloads payloadSet) error {
	if report.Profile.ProfileID != qualificationprofile.ProfileID || report.Profile.ProfileVersion != qualificationprofile.ProfileVersion || report.Profile.ProfileDigest != qualificationprofile.ExpectedProfileDigest || report.Profile.SchemaDigest != qualificationprofile.ExpectedSchemaDigest {
		return errors.New("qualification report profile identity does not match the locked profile")
	}
	if err := validateContract(report.Contract, profile.Contract); err != nil {
		return err
	}
	if report.Contract.LocalSuite.Exercised || report.Contract.RemoteSuite.Exercised || report.Claims.SuiteExecution.Local || report.Claims.SuiteExecution.Remote {
		return errors.New("qualification report overclaims Provider Suite execution")
	}
	if !reflect.DeepEqual(report.Capability, profile.CapabilitySelection) {
		return errors.New("qualification report capability selection differs from the profile")
	}
	if err := validateSandboxResources(report, profile.Limits); err != nil {
		return err
	}
	if err := validateTopology(report.Topology, profile.Topology); err != nil {
		return err
	}
	if err := validateArtifacts(report.Artifacts, profile.Artifacts); err != nil {
		return err
	}
	if err := validateConfigurations(report.Configurations, profile.Evidence); err != nil {
		return err
	}
	if !reflect.DeepEqual(report.Claims.NonClaims, profile.RequiredNonClaims) {
		return errors.New("qualification report non-claims differ from the locked profile")
	}
	if profile.Limits.MaxEvidenceFiles != evidencefiles.DefaultMaxFiles || int64(profile.Limits.MaxEvidenceFileBytes) != evidencefiles.DefaultMaxFileBytes || int64(profile.Limits.MaxEvidenceTotalBytes) != evidencefiles.DefaultMaxTotalBytes || !reflect.DeepEqual(profile.Evidence.ExcludedFiles, []string{ReportFileName, ReceiptFileName}) || profile.Evidence.PayloadDigestProfile != evidencefiles.DigestProfile || profile.Evidence.FileDigestProfile != evidencefiles.FileDigestProfile {
		return errors.New("qualification report validator bounds differ from the locked profile")
	}
	if err := validatePayloadBindings(report, semantics, payloads); err != nil {
		return err
	}
	identityComplete := hasCompleteIdentity(report, semantics, payloads)
	if report.RunOutcome.IdentityComplete != identityComplete {
		return errors.New("qualification report identity_complete does not match payload-backed identity evidence")
	}
	if (report.RunOutcome.Outcome == "passed" || report.RunOutcome.Outcome == "failed") && !identityComplete {
		return errors.New("qualification passed or failed outcome requires complete payload-backed identity")
	}
	if err := validateInvocation(report, profile.Reconstruction, identityComplete); err != nil {
		return err
	}
	return validateScenarios(report, profile, definition, identityComplete)
}

func validateSandboxResources(report reportDocument, limits profileLimits) error {
	expectedResources := sandboxResources{CPUMillis: limits.SandboxCPUMillis, MemoryBytes: limits.SandboxMemoryBytes, EphemeralStorageBytes: limits.SandboxEphemeralStorageBytes, PIDs: limits.SandboxPIDs}
	createSandboxObservations := 0
	for _, scenario := range report.ScenarioResults {
		for _, interaction := range scenario.Interactions {
			if interaction.InteractionID == "create-sandbox" {
				createSandboxObservations++
			}
		}
	}
	if createSandboxObservations > 1 {
		return errors.New("qualification report contains duplicate create-sandbox interactions")
	}
	if (report.SandboxResources != nil) != (createSandboxObservations == 1) {
		return errors.New("qualification report sandbox resources must be present iff create-sandbox was observed")
	}
	if report.SandboxResources != nil && *report.SandboxResources != expectedResources {
		return errors.New("qualification report sandbox resources differ from the locked profile")
	}
	return nil
}

func hasCompleteIdentity(report reportDocument, semantics validatorSemantics, payloads payloadSet) bool {
	if !payloads.complete() || report.SandboxResources == nil || len(report.Observations) != 91 || len(report.Claims.CallerAssertions) != 29 || len(report.Claims.TrustedInputs) != len(semantics.TrustedInputs) || report.Topology["target_identity"] == nil {
		return false
	}
	for _, item := range report.Artifacts {
		if item.Digest == nil || item.Source == nil {
			return false
		}
	}
	for _, item := range report.Configurations {
		if item.Digest == nil || !item.Sanitized {
			return false
		}
	}
	for _, item := range report.Observations {
		if item.EvidenceDigest == nil || item.Result == "missing" {
			return false
		}
	}
	for _, item := range report.Claims.CallerAssertions {
		if item.Result == "not_asserted" {
			return false
		}
	}
	invocation := report.Invocation
	if invocation.InitialInvocationID == nil || invocation.ReconstructionInvocationID == nil || invocation.HarnessArtifactDigest == nil || invocation.StartupIdentity == nil || invocation.StartupIdentity.CallerRelease == nil || invocation.StartupIdentity.AdapterRelease == nil || !startupIdentityBindsAdapterProtocol(invocation.StartupIdentity) || invocation.HarnessReinjected == nil || len(invocation.InitialProcesses) != 4 || len(invocation.ReconstructionProcesses) != 4 || invocation.AdapterTranscript == nil || invocation.ShellChallenge == nil {
		return false
	}
	if report.Cleanup.CleanupRequired {
		return report.Cleanup.QueryScope != nil && report.Cleanup.QueryScope.Digest != nil && report.Cleanup.Baseline != nil && report.Cleanup.Baseline.QueryScopeDigest != nil && report.Cleanup.Baseline.Digest != nil && report.Cleanup.PostTeardown != nil && report.Cleanup.PostTeardown.QueryScopeDigest != nil && report.Cleanup.PostTeardown.Digest != nil
	}
	return true
}

func validateContract(actual contractIdentity, expected profileContract) error {
	if actual.Namespace != expected.Namespace || actual.Version != expected.Version || actual.Revision != expected.Revision || actual.Tree != expected.Tree || actual.ManifestDigest != expected.ManifestDigest || actual.OpenAPIDigest != expected.OpenAPIDigest || actual.SemanticRulesDigest != expected.SemanticRulesDigest {
		return errors.New("qualification report Contract identity differs from the locked profile")
	}
	if err := validateSuite(actual.LocalSuite, expected.LocalSuite); err != nil {
		return err
	}
	return validateSuite(actual.RemoteSuite, expected.RemoteSuite)
}

func validateSuite(actual suiteIdentity, expected profileSuite) error {
	if actual.SuiteID != expected.SuiteID || actual.SuiteVersion != expected.SuiteVersion || actual.SuiteDigest != expected.SuiteDigest || actual.SuiteDigestProfile != expected.SuiteDigestProfile || actual.ProfileID != expected.ProfileID || actual.CaseCount != expected.CaseCount {
		return fmt.Errorf("qualification report Suite %q identity differs from the locked profile", expected.SuiteID)
	}
	if actual.Exercised || actual.Outcome != "not_executed" {
		return fmt.Errorf("qualification report Suite %q claims an execution that this profile does not perform", expected.SuiteID)
	}
	return nil
}

func validateTopology(actual, expected map[string]any) error {
	for _, key := range []string{"dedicated_disposable_target", "run_unique_namespace", "admitted_controllers", "same_ca_unadmitted_identity_count", "caller_process_separate_from_provider", "caller_gateway_owned_by_caller", "observer_control_domain", "observer_control_domain_disjoint_from", "process_isolation_groups"} {
		if !reflect.DeepEqual(actual[key], expected[key]) {
			return fmt.Errorf("qualification report topology field %q differs from profile", key)
		}
	}
	if !reflect.DeepEqual(actual["distinct_tenants"], expected["distinct_tenants_required"]) {
		return errors.New("qualification report distinct-tenant requirement differs from profile")
	}
	actors, ok := actual["actors"].([]any)
	if !ok || len(actors) != 4 {
		return errors.New("qualification report topology actor inventory is incomplete")
	}
	expectedActors, ok := expected["actors"].([]any)
	if !ok || !reflect.DeepEqual(actors, expectedActors) {
		return errors.New("qualification report topology actors differ from profile")
	}
	if _, ok := actual["target_identity"]; !ok {
		return errors.New("qualification report target identity is missing")
	}
	return nil
}

func validateArtifacts(actual []artifactIdentity, expected []profileArtifact) error {
	if len(actual) != len(expected) {
		return errors.New("qualification report artifact inventory is incomplete")
	}
	want := make(map[string]profileArtifact, len(expected))
	wantIndex := make(map[string]int, len(expected))
	for index, item := range expected {
		want[item.ID] = item
		wantIndex[item.ID] = index
	}
	seen := make(map[string]struct{}, len(actual))
	for _, item := range actual {
		expectedItem, ok := want[item.ArtifactID]
		if !ok {
			return fmt.Errorf("qualification report has unknown artifact %q", item.ArtifactID)
		}
		if _, duplicate := seen[item.ArtifactID]; duplicate {
			return fmt.Errorf("qualification report duplicates artifact %q", item.ArtifactID)
		}
		seen[item.ArtifactID] = struct{}{}
		if wantIndex[item.ArtifactID] != len(seen)-1 {
			return errors.New("qualification report artifact inventory order differs from profile")
		}
		if item.Owner != expectedItem.Owner || item.TrustDomain != expectedItem.TrustDomain || item.DigestSubject != expectedItem.DigestSubject || item.ObservedBy != expectedItem.ObservedBy {
			return fmt.Errorf("qualification report artifact %q identity does not match profile", item.ArtifactID)
		}
	}
	return nil
}

func validateTrustedInputs(actual []trustedInput) error {
	expected := []string{"external-caller-ownership", "source-hosting", "build-system", "operating-system", "network-path"}
	if len(actual) != len(expected) {
		return errors.New("qualification report trusted-input inventory is incomplete")
	}
	for index, item := range actual {
		if item.ID != expected[index] {
			return errors.New("qualification report trusted-input order differs from the locked report semantics")
		}
	}
	return nil
}

func validateConfigurations(actual []configuration, expected profileEvidence) error {
	want := map[string]int{}
	for index, item := range expected.RequiredInventories {
		want[item] = index
	}
	if len(actual) != len(want) {
		return errors.New("qualification report configuration inventory is incomplete")
	}
	seen := map[string]struct{}{}
	for _, item := range actual {
		expectedIndex, ok := want[item.ID]
		if !ok {
			return fmt.Errorf("qualification report has unknown configuration %q", item.ID)
		}
		if _, ok := seen[item.ID]; ok {
			return fmt.Errorf("qualification report duplicates configuration %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if expectedIndex != len(seen)-1 {
			return errors.New("qualification report configuration inventory order differs from profile")
		}
		if item.DigestProfile != expected.ConfigurationDigestProfile || item.ObservedBy != "process_supervisor" || (item.Digest != nil && !item.Sanitized) {
			return fmt.Errorf("qualification report configuration %q is not sanitized and hashed", item.ID)
		}
	}
	return nil
}

func validateInvocation(report reportDocument, expected profileReconstruction, requireComplete bool) error {
	actual := report.Invocation
	if (actual.HarnessReinjected != nil && *actual.HarnessReinjected) || !actual.InvocationIDIsValid() {
		return errors.New("qualification report invocation boundary is invalid")
	}
	if (len(actual.RestartedComponents) != 0 && !reflect.DeepEqual(actual.RestartedComponents, expected.RestartComponents)) || (len(actual.PreservedStores) != 0 && !reflect.DeepEqual(actual.PreservedStores, expected.PreserveStores)) || (actual.StartupIdentity != nil && actual.StartupIdentity.HarnessInjected) {
		return errors.New("qualification report reconstruction ownership differs from profile")
	}
	if actual.AdapterTranscript != nil {
		transcript := actual.AdapterTranscript
		wantInvocationIDs := pointerValues(actual.InitialInvocationID, actual.ReconstructionInvocationID)
		if len(wantInvocationIDs) != 2 || !reflect.DeepEqual(transcript.InvocationIDs, wantInvocationIDs) || !reflect.DeepEqual(transcript.ForbiddenFields, expected.ReinjectionForbidden) || !reflect.DeepEqual(transcript.AllowedFields, expected.AdapterInvocation.AllowedFields) || !transcript.Sanitized || transcript.ObservedBy != "process_supervisor" || !expected.AdapterInvocation.ForbiddenMatch {
			return errors.New("qualification report adapter transcript is not a valid non-reinjection proof")
		}
	}
	if actual.ShellChallenge != nil {
		challenge := actual.ShellChallenge
		if challenge.EstablishedInCase != expected.ShellChallenge.Established || challenge.VerifiedInCase != expected.ShellChallenge.Verified || challenge.RawChallengeInEvidence {
			return errors.New("qualification report shell continuity challenge is invalid")
		}
	}
	artifactByID := make(map[string]artifactIdentity, len(report.Artifacts))
	for _, artifact := range report.Artifacts {
		artifactByID[artifact.ArtifactID] = artifact
	}
	configurationByID := make(map[string]configuration, len(report.Configurations))
	for _, configuration := range report.Configurations {
		configurationByID[configuration.ID] = configuration
	}
	if !equalStringPtr(actual.HarnessArtifactDigest, artifactByID["qualification_harness"].Digest) {
		return errors.New("qualification report startup identities do not bind the reported artifacts and locks")
	}
	if actual.StartupIdentity != nil && (!reflect.DeepEqual(actual.StartupIdentity.CallerRelease, artifactByID["external_caller"].Source) || !reflect.DeepEqual(actual.StartupIdentity.AdapterRelease, artifactByID["qualification_adapter"].Source) || actual.StartupIdentity.ContractRevision != report.Contract.Revision || actual.StartupIdentity.ContractTree != report.Contract.Tree || actual.StartupIdentity.ProfileID != report.Profile.ProfileID || actual.StartupIdentity.ProfileDigest != report.Profile.ProfileDigest || !startupIdentityBindsAdapterProtocol(actual.StartupIdentity)) {
		return errors.New("qualification report startup identities do not bind the reported artifacts and locks")
	}
	configurationForComponent := map[string]string{
		"provider":              "provider_configuration",
		"external_caller":       "caller_configuration",
		"qualification_adapter": "adapter_configuration",
		"caller_gateway":        "gateway_configuration",
	}
	seenProcessIDs := map[string]struct{}{}
	for _, processes := range [][]processIdentity{actual.InitialProcesses, actual.ReconstructionProcesses} {
		if len(processes) > len(expected.RestartComponents) {
			return errors.New("qualification report process component inventory exceeds the reconstruction profile")
		}
		seenComponents := map[string]struct{}{}
		for index, process := range processes {
			if process.Component != expected.RestartComponents[index] {
				return fmt.Errorf("qualification report process component %q is out of locked reconstruction order", process.Component)
			}
			artifact, artifactExists := artifactByID[process.Component]
			configuration, configurationExists := configurationByID[configurationForComponent[process.Component]]
			if process.ObservedBy != "process_supervisor" || process.ProcessID == "" || !artifactExists || artifact.Digest == nil || process.ExecutableDigest != *artifact.Digest || !configurationExists || configuration.Digest == nil || process.ConfigurationDigest != *configuration.Digest {
				return fmt.Errorf("qualification report process identity for %q is incomplete or unbound", process.Component)
			}
			if _, duplicate := seenComponents[process.Component]; duplicate {
				return fmt.Errorf("qualification report duplicates process component %q in one phase", process.Component)
			}
			seenComponents[process.Component] = struct{}{}
			if _, duplicate := seenProcessIDs[process.ProcessID]; duplicate {
				return errors.New("qualification report reuses a process identity across reconstruction")
			}
			seenProcessIDs[process.ProcessID] = struct{}{}
		}
		if requireComplete && len(seenComponents) != len(configurationForComponent) {
			return errors.New("qualification report process component inventory is incomplete")
		}
	}
	if requireComplete && (len(actual.InitialProcesses) != 4 || len(actual.ReconstructionProcesses) != 4 || actual.InitialInvocationID == nil || actual.ReconstructionInvocationID == nil || actual.HarnessArtifactDigest == nil || actual.StartupIdentity == nil || actual.StartupIdentity.CallerRelease == nil || actual.StartupIdentity.AdapterRelease == nil || actual.HarnessReinjected == nil || !reflect.DeepEqual(actual.RestartedComponents, expected.RestartComponents) || !reflect.DeepEqual(actual.PreservedStores, expected.PreserveStores) || actual.AdapterTranscript == nil || actual.ShellChallenge == nil) {
		return errors.New("qualification report complete identity is missing invocation evidence")
	}
	return nil
}

func startupIdentityBindsAdapterProtocol(identity *startupIdentity) bool {
	return identity != nil &&
		identity.AdapterProtocolID == AdapterProtocolID &&
		identity.AdapterProtocolVersion == AdapterProtocolVersion &&
		identity.AdapterProtocolSchemaDigest == ExpectedAdapterProtocolSchemaDigest &&
		identity.AdapterProtocolSemanticsDigest == ExpectedAdapterProtocolSemanticsDigest
}

func (i invocation) InvocationIDIsValid() bool {
	return i.InvocationID != ""
}

func pointerValues(values ...*string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != nil {
			result = append(result, *value)
		}
	}
	return result
}

func validateScenarios(report reportDocument, profile profileDocument, definition qualificationprofile.Report, requireComplete bool) error {
	if len(profile.Phases) != 2 || len(profile.Phases[0].Cases) != 15 || len(profile.Phases[1].Cases) != 5 || len(report.Phases) != 2 || len(report.ScenarioResults) != 20 || len(report.Observations) > 91 || (requireComplete && len(report.Observations) != 91) {
		return errors.New("qualification report scenario inventory has incorrect cardinality")
	}
	if report.Phases[0].PhaseID != "initial" || report.Phases[1].PhaseID != "reconstruction" {
		return errors.New("qualification report phase order is invalid")
	}
	allCases := append(append([]profileCase{}, profile.Phases[0].Cases...), profile.Phases[1].Cases...)
	caseByID := make(map[string]profileCase, len(allCases))
	expectedCaseIDs := make([]string, 0, len(allCases))
	for _, item := range allCases {
		caseByID[item.CaseID] = item
		expectedCaseIDs = append(expectedCaseIDs, item.CaseID)
	}
	if !reflect.DeepEqual(report.Phases[0].ScenarioIDs, expectedCaseIDs[:15]) || !reflect.DeepEqual(report.Phases[1].ScenarioIDs, expectedCaseIDs[15:]) {
		return errors.New("qualification report phase scenario order differs from profile")
	}
	seenScenarios := map[string]struct{}{}
	seenInteractions := map[string]struct{}{}
	expectedObservations := make([]profileObservation, 0, definition.Interactions)
	for _, item := range allCases {
		for _, interaction := range item.Interactions {
			for _, observation := range interaction.Observations {
				expectedObservations = append(expectedObservations, observation)
			}
		}
	}
	if len(expectedObservations) != 91 {
		return errors.New("qualification profile observation inventory is not 91")
	}
	seenObs := map[string]observation{}
	nextExpectedObservation := 0
	for _, item := range report.Observations {
		matchedIndex := -1
		for index := nextExpectedObservation; index < len(expectedObservations); index++ {
			expected := expectedObservations[index]
			if item.ID == expected.ID && item.Source == expected.Source && item.Actor == expected.Actor && item.Subject == expected.Subject && item.Correlation == expected.Correlation {
				matchedIndex = index
				break
			}
		}
		if matchedIndex < 0 {
			return fmt.Errorf("qualification report observation %q binding or order differs from profile", item.ID)
		}
		expected := expectedObservations[matchedIndex]
		nextExpectedObservation = matchedIndex + 1
		key := observationKey(expected)
		if _, duplicate := seenObs[key]; duplicate {
			return fmt.Errorf("qualification report duplicates observation binding %q", item.ID)
		}
		if item.Source == "caller_assertion" {
			return errors.New("caller assertion was used as an independent observation")
		}
		seenObs[key] = item
	}
	if requireComplete && len(seenObs) != len(expectedObservations) {
		return errors.New("qualification report does not contain all required observations")
	}
	statusByCase := make(map[string]string, len(report.ScenarioResults))
	for index, actual := range report.ScenarioResults {
		if actual.CaseID != expectedCaseIDs[index] || actual.PhaseID != caseByID[actual.CaseID].PhaseID() {
			return fmt.Errorf("qualification report scenario %q is out of order", actual.CaseID)
		}
		if _, duplicate := seenScenarios[actual.CaseID]; duplicate {
			return fmt.Errorf("qualification report duplicates scenario %q", actual.CaseID)
		}
		seenScenarios[actual.CaseID] = struct{}{}
		for _, dependency := range caseByID[actual.CaseID].DependsOn {
			if statusByCase[dependency] != "passed" && actual.Status != "not_executed" {
				return fmt.Errorf("scenario %q executed after dependency %q did not pass", actual.CaseID, dependency)
			}
		}
		if err := validateScenario(actual, caseByID[actual.CaseID], seenObs, seenInteractions, requireComplete); err != nil {
			return err
		}
		statusByCase[actual.CaseID] = actual.Status
	}
	if len(seenInteractions) > definition.Interactions {
		return fmt.Errorf("qualification report contains %d interactions, exceeds %d", len(seenInteractions), definition.Interactions)
	}
	if err := validatePhaseResults(report); err != nil {
		return err
	}
	if err := validateCallerAssertions(report, allCases, requireComplete); err != nil {
		return err
	}
	return validateOutcomeAndCleanup(report, profile, allCases)
}

func (c profileCase) PhaseID() string {
	if strings.HasPrefix(c.CaseID, "initial.") {
		return "initial"
	}
	return "reconstruction"
}

func validateScenario(actual scenarioResult, expected profileCase, observations map[string]observation, seenInteractions map[string]struct{}, requireComplete bool) error {
	if len(actual.Assertions) > len(expected.Assertions) || (requireComplete && len(actual.Assertions) != len(expected.Assertions)) {
		return fmt.Errorf("scenario %q assertion inventory differs from profile", actual.CaseID)
	}
	for index, item := range actual.Assertions {
		if item.ID != expected.Assertions[index] {
			return fmt.Errorf("scenario %q assertion order differs from profile", actual.CaseID)
		}
	}
	if actual.Status == "not_executed" {
		if len(actual.Interactions) != 0 || len(actual.ObservationIDs) != 0 {
			return fmt.Errorf("not-executed scenario %q contains executed evidence", actual.CaseID)
		}
		for _, item := range actual.Assertions {
			if item.Result != "not_asserted" {
				return fmt.Errorf("not-executed scenario %q contains an asserted result", actual.CaseID)
			}
		}
		for _, interaction := range expected.Interactions {
			for _, expectedObservation := range interaction.Observations {
				if reported, ok := observations[observationKey(expectedObservation)]; ok && reported.Result != "missing" {
					return fmt.Errorf("not-executed scenario %q contains a non-missing observation", actual.CaseID)
				}
			}
		}
		return nil
	}
	if actual.Status != "passed" && actual.Status != "failed" && actual.Status != "incomplete" {
		return fmt.Errorf("scenario %q has a status outside the locked profile", actual.CaseID)
	}
	if len(actual.Interactions) > len(expected.Interactions) {
		return fmt.Errorf("scenario %q contains extra interactions", actual.CaseID)
	}
	expectationsPassed := len(actual.Interactions) == len(expected.Interactions)
	observedMismatch := false
	wantObservationIDs := make([]string, 0)
	for index, interaction := range actual.Interactions {
		expectedInteraction := expected.Interactions[index]
		matched, err := validateInteraction(interaction, expectedInteraction)
		if err != nil {
			return err
		}
		expectationsPassed = expectationsPassed && matched
		observedMismatch = observedMismatch || !matched
		wantObservationIDs = append(wantObservationIDs, interaction.ObservationIDs...)
		for _, expectedObservation := range expectedInteraction.Observations {
			reported, ok := observations[observationKey(expectedObservation)]
			if !ok || reported.Result != "observed" || reported.EvidenceDigest == nil {
				expectationsPassed = false
				if ok && reported.Result == "contradicted" {
					observedMismatch = true
				}
			}
		}
		if _, duplicate := seenInteractions[interaction.InteractionID]; duplicate {
			return fmt.Errorf("qualification report duplicates interaction %q", interaction.InteractionID)
		}
		seenInteractions[interaction.InteractionID] = struct{}{}
	}
	for _, interaction := range expected.Interactions[len(actual.Interactions):] {
		for _, expectedObservation := range interaction.Observations {
			if reported, ok := observations[observationKey(expectedObservation)]; ok && reported.Result != "missing" {
				return fmt.Errorf("scenario %q contains evidence for an interaction that did not execute", actual.CaseID)
			}
		}
	}
	if !reflect.DeepEqual(actual.ObservationIDs, wantObservationIDs) {
		return fmt.Errorf("scenario %q observation inventory differs from its interactions", actual.CaseID)
	}
	for _, assertion := range actual.Assertions {
		if assertion.Result == "contradicted" {
			expectationsPassed = false
			observedMismatch = true
		}
	}
	if actual.Status == "passed" && !expectationsPassed {
		return fmt.Errorf("passed scenario %q has an unmet expectation", actual.CaseID)
	}
	if actual.Status == "failed" && !observedMismatch {
		return fmt.Errorf("failed scenario %q has no observed mismatch", actual.CaseID)
	}
	if actual.Status == "incomplete" && (expectationsPassed || observedMismatch) {
		return fmt.Errorf("incomplete scenario %q must contain missing evidence without an observed mismatch", actual.CaseID)
	}
	return nil
}

func observationKey(item profileObservation) string {
	return strings.Join([]string{item.ID, item.Source, item.Actor, item.Subject, item.Correlation}, "\x00")
}

func validatePhaseResults(report reportDocument) error {
	for _, current := range report.Phases {
		counts := map[string]int{}
		for _, scenario := range report.ScenarioResults {
			if scenario.PhaseID == current.PhaseID {
				counts[scenario.Status]++
			}
		}
		want := "incomplete"
		switch {
		case counts["passed"] == len(current.ScenarioIDs):
			want = "passed"
		case counts["not_executed"] == len(current.ScenarioIDs):
			want = "not_executed"
		case counts["incomplete"] > 0 || counts["not_executed"] > 0:
			want = "incomplete"
		case counts["failed"] > 0:
			want = "failed"
		}
		if current.Status != want {
			return fmt.Errorf("qualification report phase %q status is %q, want %q", current.PhaseID, current.Status, want)
		}
	}
	return nil
}

func validateCallerAssertions(report reportDocument, cases []profileCase, requireComplete bool) error {
	expected := make(map[string]string)
	for index, scenario := range report.ScenarioResults {
		if len(scenario.Assertions) > len(cases[index].Assertions) || (requireComplete && len(scenario.Assertions) != len(cases[index].Assertions)) {
			return fmt.Errorf("scenario %q assertion inventory differs from profile", scenario.CaseID)
		}
		for _, assertion := range scenario.Assertions {
			if _, duplicate := expected[assertion.ID]; duplicate {
				return fmt.Errorf("qualification report duplicates assertion %q", assertion.ID)
			}
			expected[assertion.ID] = assertion.Result
		}
	}
	if requireComplete && len(expected) != 29 {
		return errors.New("qualification report complete caller-assertion inventory must contain 29 assertions")
	}
	if len(report.Claims.CallerAssertions) != len(expected) {
		return errors.New("qualification report caller-assertion inventory is incomplete")
	}
	seen := make(map[string]struct{}, len(expected))
	for _, assertion := range report.Claims.CallerAssertions {
		result, ok := expected[assertion.ID]
		if !ok || assertion.Owner != "external_caller_owner" || assertion.Result != result {
			return fmt.Errorf("qualification report caller assertion %q is unbound", assertion.ID)
		}
		if _, duplicate := seen[assertion.ID]; duplicate {
			return fmt.Errorf("qualification report duplicates caller assertion %q", assertion.ID)
		}
		seen[assertion.ID] = struct{}{}
	}
	return nil
}

func validateInteraction(actual interactionResult, expected profileInteraction) (bool, error) {
	if actual.InteractionID != expected.ID || actual.Surface != expected.Surface || actual.Actor != expected.Actor || actual.Method != expected.Method || actual.RouteTemplate != expected.Route || actual.LogicalRequestID != expected.Logical || !reflect.DeepEqual(actual.ReplayOf, expected.Replay) {
		return false, fmt.Errorf("interaction %q identity differs from profile", actual.InteractionID)
	}
	if actual.WireAttempts < 1 || actual.WireAttempts > expected.MaxWireAttempts || actual.WireAttempts != len(actual.TransientOutcomes)+1 {
		return false, fmt.Errorf("interaction %q has an invalid wire-attempt count", actual.InteractionID)
	}
	wantMutationWrite := containsString(expected.Counts, "provider_mutation_write_attempts") || containsString(expected.Counts, "gateway_mutation_write_attempts")
	if actual.MutationWriteObserved != wantMutationWrite {
		return false, fmt.Errorf("interaction %q mutation-write flag differs from its locked counters", actual.InteractionID)
	}
	matched := outcomeAllowed(actual.FinalOutcome, expected.Outcomes)
	for _, outcome := range actual.TransientOutcomes {
		if !outcomeAllowed(outcome, expected.Transient) || !outcome.Retryable {
			matched = false
		}
	}
	wantObservationIDs := make([]string, len(expected.Observations))
	for index, item := range expected.Observations {
		wantObservationIDs[index] = item.ID
	}
	if !reflect.DeepEqual(actual.ObservationIDs, wantObservationIDs) {
		return false, fmt.Errorf("interaction %q observation order differs from profile", actual.InteractionID)
	}
	return matched, nil
}

func outcomeAllowed(actual reportOutcome, allowed []profileOutcome) bool {
	for _, expected := range allowed {
		if actual.Transport != expected.Transport || !equalIntPtr(actual.StatusCode, expected.StatusCode) || (expected.Retryable != nil && actual.Retryable != *expected.Retryable) || (expected.RetryAfter != nil && actual.RetryAfterPresent != *expected.RetryAfter) {
			continue
		}
		if expected.ErrorPolicy == "exact" || expected.ErrorPolicy == "one-of-exact" {
			if actual.ErrorCode == nil {
				continue
			}
			found := false
			for _, code := range expected.ErrorCodes {
				if *actual.ErrorCode == code {
					found = true
				}
			}
			if !found {
				continue
			}
		} else if expected.ErrorPolicy == "none" && actual.ErrorCode != nil {
			continue
		}
		return true
	}
	return false
}

func validateOutcomeAndCleanup(report reportDocument, profile profileDocument, cases []profileCase) error {
	scenarioCounts := map[string]int{"passed": 0, "failed": 0, "incomplete": 0, "not_executed": 0}
	for _, scenario := range report.ScenarioResults {
		scenarioCounts[scenario.Status]++
	}
	counts, anyMutation := calculateCounters(report.ScenarioResults, report.Observations, cases)
	if report.Counters != counts {
		return errors.New("qualification report counters do not match observed interaction attempts")
	}
	if counts.ProviderHTTPRequests > profile.Limits.MaxProviderHTTPRequests || counts.ProviderMutationWriteAttempts > profile.Limits.MaxProviderMutationWriteAttempts || counts.GatewayConnectionAttempts > profile.Limits.MaxGatewayConnectionAttempts || counts.GatewayMutationWriteAttempts > profile.Limits.MaxGatewayMutationWriteAttempts {
		return errors.New("qualification report exceeds a locked attempt limit")
	}
	if counts.Sandboxes > profile.Limits.MaxSandboxes || counts.ExecRequests > profile.Limits.MaxExecRequests || counts.AdmittedExecOperations > profile.Limits.MaxAdmittedExecOperations || counts.TerminalSessions > profile.Limits.MaxTerminalSessions || counts.ArtifactRequests > profile.Limits.MaxArtifactRequests || counts.AdmittedArtifactOperations > profile.Limits.MaxAdmittedArtifactOperations || counts.DistinctProviderMutations > profile.Limits.MaxDistinctProviderMutations {
		return errors.New("qualification report exceeds a locked resource limit")
	}
	cleanupSatisfied, err := validateCleanup(report.Cleanup, profile.Cleanup, anyMutation)
	if err != nil {
		return err
	}
	if err := validateCleanupScopeBindings(report); err != nil {
		return err
	}
	if err := validateRunOutcome(report, scenarioCounts, cleanupSatisfied); err != nil {
		return err
	}
	if len(cases) != 20 {
		return errors.New("qualification profile case inventory is incomplete")
	}
	if err := validateTimestamps(report.Timestamps, profile.Limits); err != nil {
		return err
	}
	if err := validateCleanupTiming(report, cases); err != nil {
		return err
	}
	return validateScenarioTimestamps(report, cases)
}

func calculateCounters(scenarios []scenarioResult, observations []observation, cases []profileCase) (counters, bool) {
	counts := counters{}
	expectedByID := make(map[string]profileInteraction)
	for _, candidate := range cases {
		for _, interaction := range candidate.Interactions {
			expectedByID[interaction.ID] = interaction
		}
	}
	distinctMutations := make(map[string]struct{})
	admittedSandboxes := make(map[string]struct{})
	admittedExecs := make(map[string]struct{})
	admittedTerminals := make(map[string]struct{})
	admittedArtifacts := make(map[string]struct{})
	observationByBinding := make(map[string]observation, len(observations))
	for _, item := range observations {
		key := observationKey(profileObservation{ID: item.ID, Source: item.Source, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation})
		observationByBinding[key] = item
	}
	for _, scenario := range scenarios {
		for _, interaction := range scenario.Interactions {
			expected := expectedByID[interaction.InteractionID]
			for _, counter := range expected.Counts {
				switch counter {
				case "provider_http_requests":
					counts.ProviderHTTPRequests += interaction.WireAttempts
				case "provider_mutation_write_attempts":
					counts.ProviderMutationWriteAttempts += interaction.WireAttempts
				case "gateway_connection_attempts":
					counts.GatewayConnectionAttempts += interaction.WireAttempts
				case "gateway_mutation_write_attempts":
					counts.GatewayMutationWriteAttempts += interaction.WireAttempts
				case "distinct_provider_mutations":
					distinctMutations[interaction.LogicalRequestID] = struct{}{}
				case "exec_requests":
					counts.ExecRequests++
				case "artifact_requests":
					counts.ArtifactRequests++
				}
			}
			resourceKeys := []string{interaction.LogicalRequestID}
			expectedResource := false
			for _, counter := range expected.Counts {
				if counter == "sandboxes" || counter == "admitted_exec_operations" || counter == "terminal_sessions" || counter == "admitted_artifact_operations" {
					expectedResource = true
				}
			}
			evidenceMatches := interactionMatchesExpectedEvidence(interaction, expected, observationByBinding)
			admissionObserved := evidenceMatches && interaction.FinalOutcome.StatusCode != nil && *interaction.FinalOutcome.StatusCode == 202
			if admissionObserved {
				if !expectedResource {
					continue
				}
			} else {
				mutationMayHaveBeenWritten := containsString(expected.Counts, "provider_mutation_write_attempts")
				if evidenceMatches || !mutationMayHaveBeenWritten {
					continue
				}
				resourceKeys = make([]string, interaction.WireAttempts)
				for attempt := 0; attempt < interaction.WireAttempts; attempt++ {
					resourceKeys[attempt] = fmt.Sprintf("potential-unexpected-admission:%s:%d", interaction.InteractionID, attempt+1)
				}
			}
			for _, resourceKey := range resourceKeys {
				switch interaction.RouteTemplate {
				case "/v1/sandboxes":
					admittedSandboxes[resourceKey] = struct{}{}
				case "/v1/sandboxes/{sandbox_id}/exec":
					admittedExecs[resourceKey] = struct{}{}
				case "/v1/sandboxes/{sandbox_id}/runtime-sessions":
					admittedTerminals[resourceKey] = struct{}{}
				case "/v1/sandboxes/{sandbox_id}/artifacts:stage":
					admittedArtifacts[resourceKey] = struct{}{}
				}
			}
		}
	}
	counts.DistinctProviderMutations = len(distinctMutations)
	counts.Sandboxes = len(admittedSandboxes)
	counts.AdmittedExecOperations = len(admittedExecs)
	counts.TerminalSessions = len(admittedTerminals)
	counts.AdmittedArtifactOperations = len(admittedArtifacts)
	return counts, counts.ProviderMutationWriteAttempts > 0 || counts.GatewayMutationWriteAttempts > 0
}

func interactionMatchesExpectedEvidence(actual interactionResult, expected profileInteraction, observations map[string]observation) bool {
	if !outcomeAllowed(actual.FinalOutcome, expected.Outcomes) {
		return false
	}
	for _, outcome := range actual.TransientOutcomes {
		if !outcomeAllowed(outcome, expected.Transient) || !outcome.Retryable {
			return false
		}
	}
	for _, expectedObservation := range expected.Observations {
		reported, ok := observations[observationKey(expectedObservation)]
		if !ok || reported.Result != "observed" || reported.EvidenceDigest == nil {
			return false
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validateCleanup(actual cleanup, expected profileCleanup, anyMutation bool) (bool, error) {
	if actual.MutationWriteObserved != anyMutation || (anyMutation && !actual.CleanupRequired) {
		return false, errors.New("qualification report cleanup obligation does not match mutation evidence")
	}
	if actual.Authority != expected.Authority {
		return false, errors.New("qualification report cleanup scope or baseline differs from the locked profile")
	}
	if actual.QueryScope != nil && (actual.QueryScope.DigestProfile != expected.QueryDigestProfile || actual.QueryScope.ExcludesHarnessControlPlane != expected.ExcludesControlPlane || !reflect.DeepEqual(actual.QueryScope.ResourceKinds, expected.InspectorScope)) {
		return false, errors.New("qualification report cleanup query scope differs from the locked profile")
	}
	if actual.Baseline != nil && (actual.Baseline.DigestProfile != expected.InventoryDigestProfile || actual.Baseline.RunOwnedCount != expected.BaselineCount || !actual.Baseline.Stable) {
		return false, errors.New("qualification report cleanup baseline differs from the locked profile")
	}
	if actual.PostTeardown != nil && actual.PostTeardown.DigestProfile != expected.InventoryDigestProfile {
		return false, errors.New("qualification report post-teardown inventory uses the wrong digest profile")
	}
	for name, inventory := range map[string]*resourceInventory{"baseline": actual.Baseline, "post-teardown": actual.PostTeardown} {
		if inventory != nil && inventory.QueryScopeDigest != nil && (actual.QueryScope == nil || actual.QueryScope.Digest == nil || *inventory.QueryScopeDigest != *actual.QueryScope.Digest) {
			return false, fmt.Errorf("qualification report %s inventory query scope differs from the cleanup scope", name)
		}
	}
	if actual.QueryScope != nil {
		bindingsComplete := queryScopeBindingsComplete(*actual.QueryScope)
		bindingsEmpty := queryScopeBindingsEmpty(*actual.QueryScope)
		if !bindingsComplete && !bindingsEmpty {
			return false, errors.New("qualification report cleanup query scope identity bindings must be all empty or all complete")
		}
		if (actual.QueryScope.Digest != nil) != bindingsComplete {
			return false, errors.New("qualification report cleanup query scope digest and bindings must be complete together")
		}
		if bindingsComplete {
			digest, err := queryScopeDigest(*actual.QueryScope)
			if err != nil || digest != *actual.QueryScope.Digest {
				return false, errors.New("qualification report cleanup query scope digest does not match its bindings")
			}
		}
	}
	if !actual.CleanupRequired {
		if actual.TeardownAttempts != 0 || actual.TeardownCompleted || actual.Outcome != "not_required" || (actual.StabilitySamples != 0 && actual.StabilitySamples != expected.StabilitySamples) || (actual.StabilityIntervalMS != 0 && actual.StabilityIntervalMS != expected.StabilityIntervalMS) {
			return false, errors.New("qualification report no-obligation cleanup state is inconsistent")
		}
		return true, nil
	}
	if actual.TeardownAttempts == 0 {
		if actual.TeardownCompleted || (actual.Outcome != "unknown" && actual.Outcome != "incomplete") {
			return false, errors.New("qualification report mutation cleanup attempt state is inconsistent")
		}
		return false, nil
	}
	if actual.Outcome == "not_required" {
		return false, errors.New("qualification report mutation cleanup attempt state is inconsistent")
	}
	if actual.QueryScope == nil || actual.Baseline == nil {
		if actual.Outcome == "succeeded" {
			return false, errors.New("qualification report claims successful cleanup without inspector scope and baseline")
		}
		return false, nil
	}
	satisfied := actual.QueryScope.Digest != nil && actual.Baseline.QueryScopeDigest != nil && actual.Baseline.Digest != nil && actual.PostTeardown != nil && actual.PostTeardown.QueryScopeDigest != nil && actual.PostTeardown.Digest != nil && *actual.Baseline.QueryScopeDigest == *actual.QueryScope.Digest && *actual.PostTeardown.QueryScopeDigest == *actual.QueryScope.Digest && actual.TeardownCompleted && actual.Outcome == "succeeded" && actual.PostTeardown.RunOwnedCount == expected.PostTeardownCount && *actual.PostTeardown.Digest == *actual.Baseline.Digest && actual.PostTeardown.Stable && actual.StabilitySamples == expected.StabilitySamples && actual.StabilityIntervalMS == expected.StabilityIntervalMS
	if actual.Outcome == "succeeded" && !satisfied {
		return false, errors.New("qualification report claims successful cleanup without stable baseline restoration")
	}
	if actual.Outcome != "succeeded" && satisfied {
		return false, errors.New("qualification report denies cleanup despite stable baseline restoration")
	}
	return satisfied, nil
}

func completeQueryScope(scope queryScope) bool {
	return scope.Digest != nil && queryScopeBindingsComplete(scope)
}

func queryScopeBindingsComplete(scope queryScope) bool {
	return scope.TargetDigest != nil && scope.RunNamespaceDigest != nil && scope.OwnershipSelectorDigest != nil && scope.InspectorArtifactDigest != nil && scope.InspectorConfigurationDigest != nil
}

func queryScopeBindingsEmpty(scope queryScope) bool {
	return scope.TargetDigest == nil && scope.RunNamespaceDigest == nil && scope.OwnershipSelectorDigest == nil && scope.InspectorArtifactDigest == nil && scope.InspectorConfigurationDigest == nil && scope.Digest == nil
}

func queryScopeDigest(scope queryScope) (string, error) {
	return canonicalDigest(map[string]any{
		"target_digest":                  scope.TargetDigest,
		"run_namespace_digest":           scope.RunNamespaceDigest,
		"ownership_selector_digest":      scope.OwnershipSelectorDigest,
		"resource_kinds":                 scope.ResourceKinds,
		"inspector_artifact_digest":      scope.InspectorArtifactDigest,
		"inspector_configuration_digest": scope.InspectorConfigurationDigest,
		"excludes_harness_control_plane": scope.ExcludesHarnessControlPlane,
	})
}

func validateCleanupScopeBindings(report reportDocument) error {
	scope := report.Cleanup.QueryScope
	if scope == nil {
		return nil
	}
	if !completeQueryScope(*scope) {
		if queryScopeBindingsEmpty(*scope) {
			return nil
		}
		return errors.New("qualification report cleanup query scope identity bindings are partial")
	}
	target, ok := report.Topology["target_identity"].(map[string]any)
	if !ok || target["target_digest"] != *scope.TargetDigest || target["run_namespace_digest"] != *scope.RunNamespaceDigest {
		return errors.New("qualification report cleanup query scope does not bind the target and run namespace")
	}
	artifact := artifactMap(report.Artifacts)["resource_inspector"]
	configuration := configurationMap(report.Configurations)["inspector_configuration"]
	if artifact.Digest == nil || configuration.Digest == nil || *artifact.Digest != *scope.InspectorArtifactDigest || *configuration.Digest != *scope.InspectorConfigurationDigest {
		return errors.New("qualification report cleanup query scope does not bind the inspector artifact and configuration")
	}
	return nil
}

func validateRunOutcome(report reportDocument, counts map[string]int, cleanupSatisfied bool) error {
	if report.RunOutcome.ScenarioCounts.Passed != counts["passed"] || report.RunOutcome.ScenarioCounts.Failed != counts["failed"] || report.RunOutcome.ScenarioCounts.Incomplete != counts["incomplete"] || report.RunOutcome.ScenarioCounts.NotExecuted != counts["not_executed"] {
		return errors.New("qualification report scenario counts are inconsistent")
	}
	if report.RunOutcome.CleanupSatisfied != cleanupSatisfied || !report.RunOutcome.SanitizationPassed {
		return errors.New("qualification report run gates are inconsistent")
	}
	want := "incomplete"
	if counts["not_executed"] == 20 {
		want = "not_executed"
	} else if !cleanupSatisfied || !report.RunOutcome.IdentityComplete || !report.RunOutcome.SanitizationPassed || counts["incomplete"] > 0 || counts["not_executed"] > 0 {
		want = "incomplete"
	} else if counts["failed"] > 0 {
		want = "failed"
	} else if counts["passed"] == 20 {
		want = "passed"
	}
	if report.RunOutcome.Outcome != want {
		return fmt.Errorf("qualification report outcome %q does not follow precedence; want %q", report.RunOutcome.Outcome, want)
	}
	reasons := make(map[string]struct{}, len(report.RunOutcome.ReasonCodes))
	for _, reason := range report.RunOutcome.ReasonCodes {
		reasons[reason] = struct{}{}
	}
	if len(reasons) != len(report.RunOutcome.ReasonCodes) {
		return errors.New("qualification report duplicates a run reason")
	}
	if _, invalid := reasons["validation_failed"]; invalid {
		return errors.New("accepted qualification report claims validator failure")
	}
	if _, invalid := reasons["sanitization_failed"]; invalid {
		return errors.New("accepted qualification report claims sanitization failure")
	}
	if _, present := reasons["executed_mismatch"]; present != (counts["failed"] > 0) {
		return errors.New("qualification report executed_mismatch reason conflicts with scenario results")
	}
	if _, present := reasons["cleanup_unknown_or_failed"]; present != !cleanupSatisfied {
		return errors.New("qualification report cleanup reason conflicts with cleanup evidence")
	}
	if _, present := reasons["missing_identity_or_evidence"]; present != !report.RunOutcome.IdentityComplete {
		return errors.New("qualification report identity reason conflicts with identity evidence")
	}
	if _, present := reasons["scenario_not_executed"]; present != (counts["not_executed"] > 0) {
		return errors.New("qualification report not-executed reason conflicts with scenario results")
	}
	if _, present := reasons["prerequisite_unavailable"]; present && counts["not_executed"] == 0 {
		return errors.New("qualification report prerequisite reason conflicts with scenario results")
	}
	if want == "passed" && len(reasons) != 0 {
		return errors.New("passed qualification report contains failure reasons")
	}
	if want == "incomplete" {
		if !cleanupSatisfied {
			if _, ok := reasons["cleanup_unknown_or_failed"]; !ok {
				return errors.New("incomplete qualification report lacks cleanup reason")
			}
		}
		if !report.RunOutcome.IdentityComplete {
			if _, ok := reasons["missing_identity_or_evidence"]; !ok {
				return errors.New("incomplete qualification report lacks identity reason")
			}
		}
		if counts["not_executed"] > 0 {
			if _, ok := reasons["scenario_not_executed"]; !ok {
				return errors.New("incomplete qualification report lacks scenario_not_executed reason")
			}
		}
	}
	if want == "not_executed" {
		_, unavailable := reasons["prerequisite_unavailable"]
		_, skipped := reasons["scenario_not_executed"]
		if !unavailable && !skipped {
			return errors.New("not-executed qualification report lacks a reason")
		}
	}
	return nil
}

func validateTimestamps(ts timestamps, limits profileLimits) error {
	values := []*string{ts.RunStartedAt, ts.ExecutionStartedAt, ts.ExecutionFinishedAt, ts.CleanupStartedAt, ts.CleanupFinishedAt, ts.RunFinishedAt}
	if timestampsEmpty(ts) {
		return nil
	}
	parsed := make([]time.Time, len(values))
	for index, value := range values {
		if value == nil {
			return errors.New("qualification report timestamps must be all null or all present")
		}
		moment, err := time.Parse(time.RFC3339Nano, *value)
		if err != nil || moment.Location() != time.UTC || !strings.HasSuffix(*value, "Z") {
			return errors.New("qualification report timestamps must be UTC RFC3339Nano")
		}
		parsed[index] = moment
	}
	for index := 1; index < len(parsed); index++ {
		if parsed[index].Before(parsed[index-1]) {
			return errors.New("qualification report timestamps are not ordered")
		}
	}
	if parsed[4].Sub(parsed[3]) > time.Duration(limits.MaxCleanupSeconds)*time.Second {
		return errors.New("qualification report cleanup exceeds its deadline")
	}
	if parsed[5].Sub(parsed[0]) > time.Duration(limits.MaxTotalWallClockSeconds)*time.Second || parsed[2].Sub(parsed[1]) > time.Duration(limits.MaxExecutionSeconds)*time.Second {
		return errors.New("qualification report clock exceeds its locked bound")
	}
	return nil
}

func validateCleanupTiming(report reportDocument, cases []profileCase) error {
	actual := report.Cleanup
	ts := report.Timestamps
	if actual.Baseline != nil {
		if len(actual.Baseline.SampledAt) != 1 {
			return errors.New("qualification report cleanup does not contain the required baseline sample time")
		}
		baselineAt, err := parseUTCTimestampValue(actual.Baseline.SampledAt[0])
		if err != nil {
			return errors.New("qualification report cleanup baseline sample time is invalid")
		}
		executionStarted, err := parseUTCTimestamp(ts.ExecutionStartedAt)
		if err != nil || baselineAt.Before(executionStarted) {
			return errors.New("qualification report cleanup baseline predates execution start")
		}
		firstMutation, found := firstMutationScenarioStart(report.ScenarioResults, cases)
		if actual.MutationWriteObserved && !found {
			return errors.New("qualification report cleanup baseline has no observed mutation boundary")
		}
		if found && !baselineAt.Before(firstMutation) {
			return errors.New("qualification report cleanup baseline was not captured before the first mutation")
		}
	}
	if actual.PostTeardown != nil && len(actual.PostTeardown.SampledAt) != actual.StabilitySamples {
		return errors.New("qualification report cleanup does not contain the claimed post-teardown sample count")
	}
	if actual.StabilitySamples <= 1 {
		return nil
	}
	started, err := parseUTCTimestamp(ts.CleanupStartedAt)
	if err != nil {
		return err
	}
	finished, err := parseUTCTimestamp(ts.CleanupFinishedAt)
	if err != nil {
		return err
	}
	minimum := time.Duration(actual.StabilitySamples-1) * time.Duration(actual.StabilityIntervalMS) * time.Millisecond
	if actual.StabilityIntervalMS <= 0 || finished.Sub(started) < minimum {
		return errors.New("qualification report cleanup window cannot contain the claimed stability samples")
	}
	if actual.Baseline == nil || actual.PostTeardown == nil {
		return errors.New("qualification report cleanup does not contain the required baseline and stability sample times")
	}
	previous := time.Time{}
	for _, value := range actual.PostTeardown.SampledAt {
		sampledAt, err := parseUTCTimestampValue(value)
		if err != nil || sampledAt.Before(started) || sampledAt.After(finished) || (!previous.IsZero() && sampledAt.Sub(previous) < time.Duration(actual.StabilityIntervalMS)*time.Millisecond) {
			return errors.New("qualification report post-teardown sample times do not match the cleanup window and interval")
		}
		previous = sampledAt
	}
	return nil
}

func firstMutationScenarioStart(scenarios []scenarioResult, cases []profileCase) (time.Time, bool) {
	expectedByID := make(map[string]profileInteraction)
	for _, candidate := range cases {
		for _, interaction := range candidate.Interactions {
			expectedByID[interaction.ID] = interaction
		}
	}
	for _, scenario := range scenarios {
		for _, interaction := range scenario.Interactions {
			expected := expectedByID[interaction.InteractionID]
			if containsString(expected.Counts, "provider_mutation_write_attempts") || containsString(expected.Counts, "gateway_mutation_write_attempts") {
				started, err := parseUTCTimestamp(scenario.StartedAt)
				return started, err == nil
			}
		}
	}
	return time.Time{}, false
}

func validateScenarioTimestamps(report reportDocument, cases []profileCase) error {
	if report.Timestamps.ExecutionStartedAt == nil {
		for _, phase := range report.Phases {
			if phase.StartedAt != nil || phase.FinishedAt != nil {
				return errors.New("qualification report has phase timestamps without a run execution clock")
			}
		}
		for _, scenario := range report.ScenarioResults {
			if scenario.StartedAt != nil || scenario.FinishedAt != nil {
				return errors.New("qualification report has scenario timestamps without a run execution clock")
			}
		}
		return nil
	}
	executionStart, err := parseUTCTimestamp(report.Timestamps.ExecutionStartedAt)
	if err != nil {
		return err
	}
	executionFinish, err := parseUTCTimestamp(report.Timestamps.ExecutionFinishedAt)
	if err != nil {
		return err
	}
	phaseWindows := make(map[string][2]time.Time, len(report.Phases))
	previousScenarioFinish := make(map[string]time.Time, len(report.Phases))
	for index, phase := range report.Phases {
		started, err := parseUTCTimestamp(phase.StartedAt)
		if err != nil {
			return fmt.Errorf("qualification report phase %q start: %w", phase.PhaseID, err)
		}
		finished, err := parseUTCTimestamp(phase.FinishedAt)
		if err != nil || finished.Before(started) || started.Before(executionStart) || finished.After(executionFinish) {
			return fmt.Errorf("qualification report phase %q timestamps are outside the execution window", phase.PhaseID)
		}
		if index > 0 && started.Before(phaseWindows[report.Phases[index-1].PhaseID][1]) {
			return errors.New("qualification report phase timestamps overlap or are out of order")
		}
		phaseWindows[phase.PhaseID] = [2]time.Time{started, finished}
	}
	for index, scenario := range report.ScenarioResults {
		started, err := parseUTCTimestamp(scenario.StartedAt)
		if err != nil {
			return fmt.Errorf("qualification report scenario %q start: %w", scenario.CaseID, err)
		}
		finished, err := parseUTCTimestamp(scenario.FinishedAt)
		window := phaseWindows[scenario.PhaseID]
		if err != nil || finished.Before(started) || started.Before(window[0]) || finished.After(window[1]) || finished.Sub(started) > time.Duration(cases[index].TimeoutSeconds)*time.Second {
			return fmt.Errorf("qualification report scenario %q timestamps exceed its phase or case deadline", scenario.CaseID)
		}
		if previous, ok := previousScenarioFinish[scenario.PhaseID]; ok && started.Before(previous) {
			return fmt.Errorf("qualification report scenario %q overlaps or precedes the prior scenario", scenario.CaseID)
		}
		previousScenarioFinish[scenario.PhaseID] = finished
	}
	return nil
}

func parseUTCTimestamp(value *string) (time.Time, error) {
	if value == nil {
		return time.Time{}, errors.New("timestamp must be present")
	}
	return parseUTCTimestampValue(*value)
}

func parseUTCTimestampValue(value string) (time.Time, error) {
	moment, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("timestamp must be UTC RFC3339Nano")
	}
	return moment, nil
}

func validateEvidence(report reportDocument, inventory evidencefiles.Inventory, reportBytes []byte, receiptBytes int64) error {
	if report.Evidence.RootRelative != "." || report.Evidence.FileCount != inventory.FileCount+1 || report.Evidence.TotalBytes != inventory.TotalBytes+receiptBytes || report.Evidence.PayloadInventoryDigest != inventory.Digest || report.Evidence.PayloadInventoryDigestProfile != evidencefiles.DigestProfile || !reflect.DeepEqual(report.Evidence.PayloadInventory, inventory.Entries) {
		return errors.New("qualification report evidence inventory does not match the evidence root")
	}
	if report.Evidence.Sanitization.Status != "passed" || !report.Evidence.Sanitization.Required || report.Evidence.Sanitization.ForbiddenMaterialDetected || report.Evidence.Sanitization.ScannerIdentity != ExpectedValidatorSemanticsDigest {
		return errors.New("qualification report sanitization did not pass")
	}
	if len(reportBytes) == 0 {
		return errors.New("qualification report is empty")
	}
	return nil
}

func validateSanitizedBytes(document []byte) error {
	marker, err := findForbiddenMaterial(document)
	if err != nil {
		return err
	}
	if marker != "" {
		return fmt.Errorf("qualification evidence contains forbidden material marker %q", marker)
	}
	return nil
}

func validateSanitizedPayload(root *evidencefiles.Root, inventory evidencefiles.Inventory) error {
	for _, entry := range inventory.Entries {
		contents, err := root.ReadFile(entry.Path, evidencefiles.DefaultMaxFileBytes)
		if err != nil || int64(len(contents)) != entry.Bytes || evidencefiles.RawDigest(contents) != entry.SHA256 {
			return fmt.Errorf("qualification evidence payload %q changed during sanitization", entry.Path)
		}
		marker, err := findForbiddenMaterial(contents)
		if err != nil {
			return fmt.Errorf("decode qualification evidence payload %q for sanitization: %w", entry.Path, err)
		}
		if marker != "" {
			return fmt.Errorf("qualification evidence payload %q contains forbidden material marker %q", entry.Path, marker)
		}
	}
	return nil
}

func findForbiddenMaterial(document []byte) (string, error) {
	candidates := [][]byte{bytes.ToLower(document)}
	var value any
	if err := decodeStrictJSON(document, &value); err != nil {
		return "", fmt.Errorf("decode JSON for sanitization: %w", err)
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("normalize JSON for sanitization")
	}
	candidates = append(candidates, bytes.ToLower(normalized))
	appendDecodedJSONStrings(value, &candidates)
	for _, marker := range forbiddenMaterialMarkers() {
		for _, candidate := range candidates {
			if bytes.Contains(candidate, []byte(marker)) {
				return marker, nil
			}
		}
	}
	return "", nil
}

func appendDecodedJSONStrings(value any, candidates *[][]byte) {
	switch typed := value.(type) {
	case string:
		*candidates = append(*candidates, bytes.ToLower([]byte(typed)))
	case []any:
		for _, item := range typed {
			appendDecodedJSONStrings(item, candidates)
		}
	case map[string]any:
		for key, item := range typed {
			*candidates = append(*candidates, bytes.ToLower([]byte(key)))
			appendDecodedJSONStrings(item, candidates)
		}
	}
}

func forbiddenMaterialMarkers() []string {
	return []string{"-----begin", "bearer ", "authorization:", `"authorization":`, `"private_key":`, `"client_secret":`, "/users/", "/home/", "\\users\\", "/var/run/docker.sock", "unix://", "http://", "https://", "ws://", "wss://", "ref:"}
}

func makeReceipt(report reportDocument, reportBytes []byte, inventory evidencefiles.Inventory, semantics validatorSemantics) ([]byte, map[string]any, error) {
	return makeReceiptAt(report, reportBytes, inventory, semantics, time.Now().UTC())
}

func makeReceiptAt(report reportDocument, reportBytes []byte, inventory evidencefiles.Inventory, semantics validatorSemantics, now time.Time) ([]byte, map[string]any, error) {
	artifactDigests := make([]map[string]any, len(report.Artifacts))
	for index, artifact := range report.Artifacts {
		artifactDigests[index] = map[string]any{"artifact_id": artifact.ArtifactID, "digest": artifact.Digest}
	}
	processDigest, err := canonicalDigest(map[string]any{"initial": report.Invocation.InitialProcesses, "reconstruction": report.Invocation.ReconstructionProcesses})
	if err != nil {
		return nil, nil, fmt.Errorf("digest qualification process identities: %w", err)
	}
	phaseDigest, err := canonicalDigest(report.ScenarioResults)
	if err != nil {
		return nil, nil, fmt.Errorf("digest qualification scenario results: %w", err)
	}
	now = now.UTC()
	receipt := map[string]any{"format_version": 1, "receipt_type": "sandbox-runtime-external-caller-qualification-validator-receipt", "receipt_version": "1.0.0", "receipt_id": fmt.Sprintf("receipt-%016x", uint64(now.UnixNano())), "report_schema": semantics.ReportSchema, "validator_semantics": authorityIdentity{Path: ValidatorSemanticsPath, Digest: ExpectedValidatorSemanticsDigest}, "adapter_protocol": semantics.AdapterProtocol, "report_sha256": evidencefiles.RawDigest(reportBytes), "report_digest_profile": evidencefiles.FileDigestProfile, "payload_inventory_sha256": inventory.Digest, "payload_inventory_digest_profile": evidencefiles.DigestProfile, "profile": report.Profile, "invocation_id": report.Invocation.InvocationID, "runtime_commitment_digest": report.Invocation.RuntimeCommitmentDigest, "artifact_digests": artifactDigests, "process_identity_digest": processDigest, "phase_ordered_result_digest": phaseDigest, "completion_state": report.RunOutcome.Outcome, "validation_outcome": "accepted", "validated_at": now.Format("2006-01-02T15:04:05.000000000Z")}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, nil, fmt.Errorf("encode qualification receipt: %w", err)
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize qualification receipt: %w", err)
	}
	return append(canonical, '\n'), receipt, nil
}

func readSourceFile(root, relative string, maximum int64) ([]byte, error) {
	if !fs.ValidPath(relative) || relative == "." || filepath.IsAbs(relative) {
		return nil, errors.New("source path must be a normalized relative path")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve source root symlinks: %w", err)
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve source file: %w", err)
	}
	if resolved != path {
		return nil, errors.New("source file path must not contain symlinks")
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("source file escapes the source root")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maximum {
		return nil, errors.New("source file is not a non-empty bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > maximum {
		return nil, errors.New("source file was replaced")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) == 0 || int64(len(contents)) > maximum {
		return nil, errors.New("source file exceeds bound")
	}
	return contents, nil
}

func canonicalDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
func equalIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
func uniqueStrings(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
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
	if err := consumeUnique(decoder); err != nil {
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
func consumeUnique(decoder *json.Decoder) error {
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
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid JSON member")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate JSON member %q", name)
			}
			seen[name] = struct{}{}
			if err := consumeUnique(decoder); err != nil {
				return err
			}
		}
		return consumeExpected(decoder, '}')
	case '[':
		for decoder.More() {
			if err := consumeUnique(decoder); err != nil {
				return err
			}
		}
		return consumeExpected(decoder, ']')
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
func consumeExpected(decoder *json.Decoder, expected json.Delim) error {
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

// Keep imports and model declarations honest when schema evolution removes a
// helper field from a future report revision.
var _ = sort.Strings
