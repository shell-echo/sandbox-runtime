// Package v1 defines the Sandbox Provider API v1 wire projection. These DTOs
// are transport values and must not be reused as instance, repository, or
// runtime-driver models.
package v1

import (
	"encoding/json"
	"fmt"
	"regexp"
)

type APIVersion string

const APIVersionV1 APIVersion = "v1"

type CapabilityID string

const (
	CapabilityExec                CapabilityID = "sandbox.exec"
	CapabilityTerminal            CapabilityID = "sandbox.terminal"
	CapabilityBrowser             CapabilityID = "sandbox.browser"
	CapabilityDesktop             CapabilityID = "sandbox.desktop"
	CapabilityPortForward         CapabilityID = "sandbox.port-forward"
	CapabilityPersistentWorkspace CapabilityID = "sandbox.workspace.persistent"
	CapabilityWorkspaceSnapshot   CapabilityID = "sandbox.snapshot.workspace"
	CapabilityFilesystemSnapshot  CapabilityID = "sandbox.snapshot.filesystem"
	CapabilityProcessSnapshot     CapabilityID = "sandbox.snapshot.process"
	CapabilityRestore             CapabilityID = "sandbox.restore"
	CapabilityNetworkPolicy       CapabilityID = "sandbox.network-policy"
	CapabilityGPU                 CapabilityID = "sandbox.gpu"
	CapabilityNestedContainer     CapabilityID = "sandbox.nested-container"
	CapabilityUserNamespace       CapabilityID = "sandbox.user-namespace"
)

type IsolationClass string

const (
	IsolationContainer         IsolationClass = "container"
	IsolationHardenedContainer IsolationClass = "hardened-container"
	IsolationMicroVM           IsolationClass = "microvm"
	IsolationVirtualMachine    IsolationClass = "virtual-machine"
	IsolationLocalProcess      IsolationClass = "local-process"
)

type Architecture string

const (
	ArchitectureAMD64 Architecture = "amd64"
	ArchitectureARM64 Architecture = "arm64"
)

type SnapshotLevel string

const (
	SnapshotWorkspace  SnapshotLevel = "workspace"
	SnapshotFilesystem SnapshotLevel = "filesystem"
	SnapshotProcess    SnapshotLevel = "process"
)

type RequestedDesiredState string

const (
	RequestedStateReady     RequestedDesiredState = "ready"
	RequestedStateSuspended RequestedDesiredState = "suspended"
)

type DesiredState string

const (
	DesiredStateReady      DesiredState = "ready"
	DesiredStateSuspended  DesiredState = "suspended"
	DesiredStateTerminated DesiredState = "terminated"
)

type ObservedState string

const (
	ObservedRequested    ObservedState = "requested"
	ObservedProvisioning ObservedState = "provisioning"
	ObservedReady        ObservedState = "ready"
	ObservedSuspending   ObservedState = "suspending"
	ObservedSuspended    ObservedState = "suspended"
	ObservedResuming     ObservedState = "resuming"
	ObservedTerminating  ObservedState = "terminating"
	ObservedTerminated   ObservedState = "terminated"
	ObservedExpired      ObservedState = "expired"
	ObservedFailed       ObservedState = "failed"
)

type OperationType string

const (
	OperationCreate             OperationType = "create"
	OperationExtendLease        OperationType = "extend_lease"
	OperationExec               OperationType = "exec"
	OperationCancelExec         OperationType = "cancel_exec"
	OperationSnapshot           OperationType = "snapshot"
	OperationRestore            OperationType = "restore"
	OperationSuspend            OperationType = "suspend"
	OperationResume             OperationType = "resume"
	OperationTerminate          OperationType = "terminate"
	OperationOpenRuntimeSession OperationType = "open_runtime_session"
	OperationOpenBrowserSession OperationType = "open_browser_session"
	OperationArtifactStage      OperationType = "artifact_stage"
)

type OperationState string

const (
	OperationAccepted       OperationState = "accepted"
	OperationRunning        OperationState = "running"
	OperationSucceeded      OperationState = "succeeded"
	OperationFailed         OperationState = "failed"
	OperationCancelled      OperationState = "cancelled"
	OperationOutcomeUnknown OperationState = "outcome_unknown"
)

type RuntimeType string

const (
	RuntimeTerminal    RuntimeType = "terminal"
	RuntimeBrowser     RuntimeType = "browser"
	RuntimeDesktop     RuntimeType = "desktop"
	RuntimePortForward RuntimeType = "port_forward"
)

// TerminalRuntimeType is deliberately narrower than the architecture's
// reserved runtime vocabulary. The locked P2.3 session Contract admits only
// terminal sessions.
type TerminalRuntimeType string

const TerminalRuntimeTerminal TerminalRuntimeType = "terminal"

type SessionProtocol string

const (
	ProtocolWebSocket SessionProtocol = "websocket"
	ProtocolWebRTC    SessionProtocol = "webrtc"
	ProtocolTCPProxy  SessionProtocol = "tcp-proxy"
	ProtocolHTTPProxy SessionProtocol = "http-proxy"
)

type ErrorOutcome string

const (
	OutcomeKnownFailed    ErrorOutcome = "known_failed"
	OutcomeUnknownFailure ErrorOutcome = "outcome_unknown"
)

type SHA256Digest string

type SandboxSlotKey string

var (
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	slotKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{0,127}$`)
)

func (v *APIVersion) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "API version", v, APIVersionV1)
}

func (v *CapabilityID) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "capability ID", v,
		CapabilityExec, CapabilityTerminal, CapabilityBrowser, CapabilityDesktop,
		CapabilityPortForward, CapabilityPersistentWorkspace,
		CapabilityWorkspaceSnapshot, CapabilityFilesystemSnapshot,
		CapabilityProcessSnapshot, CapabilityRestore, CapabilityNetworkPolicy,
		CapabilityGPU, CapabilityNestedContainer, CapabilityUserNamespace)
}

func (v *IsolationClass) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "isolation class", v, IsolationContainer,
		IsolationHardenedContainer, IsolationMicroVM, IsolationVirtualMachine,
		IsolationLocalProcess)
}

func (v *Architecture) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "architecture", v, ArchitectureAMD64, ArchitectureARM64)
}

func (v *SnapshotLevel) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "snapshot level", v, SnapshotWorkspace,
		SnapshotFilesystem, SnapshotProcess)
}

func (v *RequestedDesiredState) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "requested desired state", v, RequestedStateReady,
		RequestedStateSuspended)
}

func (v *DesiredState) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "desired state", v, DesiredStateReady,
		DesiredStateSuspended, DesiredStateTerminated)
}

func (v *ObservedState) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "observed state", v, ObservedRequested,
		ObservedProvisioning, ObservedReady, ObservedSuspending, ObservedSuspended,
		ObservedResuming, ObservedTerminating, ObservedTerminated, ObservedExpired,
		ObservedFailed)
}

func (v *OperationType) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "operation type", v, OperationCreate,
		OperationExtendLease, OperationExec, OperationCancelExec, OperationSnapshot,
		OperationRestore, OperationSuspend, OperationResume, OperationTerminate,
		OperationOpenRuntimeSession, OperationOpenBrowserSession, OperationArtifactStage)
}

func (v *OperationState) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "operation state", v, OperationAccepted,
		OperationRunning, OperationSucceeded, OperationFailed, OperationCancelled,
		OperationOutcomeUnknown)
}

func (v *RuntimeType) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "runtime type", v, RuntimeTerminal, RuntimeBrowser,
		RuntimeDesktop, RuntimePortForward)
}

func (v *TerminalRuntimeType) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "terminal runtime type", v, TerminalRuntimeTerminal)
}

func (v *SessionProtocol) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "session protocol", v, ProtocolWebSocket,
		ProtocolWebRTC, ProtocolTCPProxy, ProtocolHTTPProxy)
}

func (v *ErrorOutcome) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "error outcome", v, OutcomeKnownFailed,
		OutcomeUnknownFailure)
}

func (v *SHA256Digest) UnmarshalJSON(data []byte) error {
	return unmarshalPattern(data, "SHA-256 digest", v, digestPattern)
}

func (v *SandboxSlotKey) UnmarshalJSON(data []byte) error {
	return unmarshalPattern(data, "sandbox slot key", v, slotKeyPattern)
}

func unmarshalEnum[T ~string](data []byte, name string, destination *T, allowed ...T) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	for _, candidate := range allowed {
		if value == string(candidate) {
			*destination = T(value)
			return nil
		}
	}
	return fmt.Errorf("invalid %s %q", name, value)
}

func unmarshalPattern[T ~string](data []byte, name string, destination *T, pattern *regexp.Regexp) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	if !pattern.MatchString(value) {
		return fmt.Errorf("invalid %s", name)
	}
	*destination = T(value)
	return nil
}

type MutationEnvelope struct {
	OperationID    string       `json:"operation_id"`
	AttemptID      string       `json:"attempt_id"`
	FencingToken   int64        `json:"fencing_token"`
	IdempotencyKey string       `json:"idempotency_key"`
	RequestDigest  SHA256Digest `json:"request_digest"`
	DeadlineAt     string       `json:"deadline_at"`
}

type Capabilities struct {
	ProviderRevisionID     string                   `json:"provider_revision_id"`
	APIVersion             APIVersion               `json:"api_version"`
	Capabilities           []Capability             `json:"capabilities"`
	RuntimeProfiles        []RuntimeProfile         `json:"runtime_profiles"`
	SnapshotRestoreProfile []SnapshotRestoreProfile `json:"snapshot_restore_profiles"`
	Limits                 ProviderLimits           `json:"limits"`
}

type Capability struct {
	ID       CapabilityID `json:"id"`
	Versions []string     `json:"versions"`
	Profiles []string     `json:"profiles,omitempty"`
}

type RuntimeProfile struct {
	ID                   string         `json:"id"`
	IsolationClass       IsolationClass `json:"isolation_class"`
	RuntimeClassName     string         `json:"runtime_class_name,omitempty"`
	Architecture         []Architecture `json:"architecture,omitempty"`
	CapabilityProfileIDs []string       `json:"capability_profile_ids,omitempty"`
}

type SnapshotRestoreProfile struct {
	ProfileID    string         `json:"profile_id"`
	Level        SnapshotLevel  `json:"level"`
	SuiteID      SandboxSuiteID `json:"suite_id"`
	SuiteVersion string         `json:"suite_version"`
	SuiteDigest  SHA256Digest   `json:"suite_digest"`
}

type SandboxSuiteID string

const SandboxSuiteProvider SandboxSuiteID = "sandbox-provider"

func (v *SandboxSuiteID) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "Sandbox Suite ID", v, SandboxSuiteProvider)
}

type ProviderLimits struct {
	MaxCPUMillis             int64  `json:"max_cpu_millis"`
	MaxMemoryBytes           int64  `json:"max_memory_bytes"`
	MaxEphemeralStorageBytes int64  `json:"max_ephemeral_storage_bytes"`
	MaxWorkspaceBytes        *int64 `json:"max_workspace_bytes,omitempty"`
	MaxGPUCount              *int64 `json:"max_gpu_count,omitempty"`
	MaxLeaseSeconds          int64  `json:"max_lease_seconds"`
	MaxExecSeconds           int64  `json:"max_exec_seconds"`
}

type CreateRequest struct {
	MutationEnvelope
	ProtocolVersion APIVersion      `json:"protocol_version"`
	Spec            SandboxSpec     `json:"spec"`
	TraceContext    json.RawMessage `json:"trace_context"`
}

type CancelExecRequest struct {
	MutationEnvelope
	ExpectedGeneration int64  `json:"expected_generation"`
	TargetOperationID  string `json:"target_operation_id"`
	TargetAttemptID    string `json:"target_attempt_id"`
	Reason             string `json:"reason"`
}

type DesiredStateRequest struct {
	MutationEnvelope
	ExpectedGeneration int64                 `json:"expected_generation"`
	DesiredState       RequestedDesiredState `json:"desired_state"`
	Reason             string                `json:"reason,omitempty"`
}

type LeaseRequest struct {
	MutationEnvelope
	ExpectedGeneration int64 `json:"expected_generation"`
	ExtendSeconds      int64 `json:"extend_seconds"`
}

type ExecRequest struct {
	MutationEnvelope
	ExpectedGeneration     int64             `json:"expected_generation"`
	Command                []string          `json:"command"`
	WorkingDirectory       string            `json:"working_directory"`
	ResultRetentionSeconds int64             `json:"result_retention_seconds"`
	Environment            map[string]string `json:"environment,omitempty"`
	SecretReferenceIDs     []string          `json:"secret_reference_ids,omitempty"`
	SecretGrantID          string            `json:"secret_grant_id,omitempty"`
	SecretGrantDigest      SHA256Digest      `json:"secret_grant_digest,omitempty"`
	StdinReference         string            `json:"stdin_reference,omitempty"`
	Capture                *ExecCapture      `json:"capture,omitempty"`
}

type ExecCapture struct {
	Stdout   *bool  `json:"stdout,omitempty"`
	Stderr   *bool  `json:"stderr,omitempty"`
	MaxBytes *int64 `json:"max_bytes,omitempty"`
}

type RestoreRequest struct {
	MutationEnvelope
	ProtocolVersion          APIVersion            `json:"protocol_version"`
	Spec                     SandboxSpec           `json:"spec"`
	Snapshot                 SnapshotManifest      `json:"snapshot"`
	TargetProviderRevisionID string                `json:"target_provider_revision_id"`
	TargetRuntimeRevision    string                `json:"target_runtime_revision"`
	CompatibilityDecision    CompatibilityDecision `json:"compatibility_decision"`
}

type RuntimeSessionOpenRequest struct {
	MutationEnvelope
	ExpectedGeneration  int64               `json:"expected_generation"`
	RuntimeSessionID    string              `json:"runtime_session_id"`
	RuntimeType         TerminalRuntimeType `json:"runtime_type"`
	CapabilityProfileID string              `json:"capability_profile_id"`
	ExpiresAt           string              `json:"expires_at"`
}

type BrowserSessionOpenRequest struct {
	MutationEnvelope
	ExpectedGeneration  int64  `json:"expected_generation"`
	BrowserSessionID    string `json:"browser_session_id"`
	CapabilityProfileID string `json:"capability_profile_id"`
	ExpiresAt           string `json:"expires_at"`
}

type SnapshotConsistency string

const (
	SnapshotCrashConsistent     SnapshotConsistency = "crash_consistent"
	SnapshotApplicationQuiesced SnapshotConsistency = "application_quiesced"
)

func (v *SnapshotConsistency) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "snapshot consistency", v, SnapshotCrashConsistent,
		SnapshotApplicationQuiesced)
}

type SnapshotRequest struct {
	MutationEnvelope
	ExpectedGeneration   int64               `json:"expected_generation"`
	Level                SnapshotLevel       `json:"level"`
	Consistency          SnapshotConsistency `json:"consistency"`
	CompatibilityProfile string              `json:"compatibility_profile,omitempty"`
	IncludePaths         []string            `json:"include_paths,omitempty"`
}

type TerminateRequest struct {
	MutationEnvelope
	ExpectedGeneration        int64  `json:"expected_generation"`
	Reason                    string `json:"reason"`
	PreserveWorkspaceSnapshot bool   `json:"preserve_workspace_snapshot"`
}

type SandboxSpec struct {
	SandboxID            string                  `json:"sandbox_id"`
	TenantID             string                  `json:"tenant_id"`
	WorkOrderID          string                  `json:"work_order_id"`
	WorkspaceID          string                  `json:"workspace_id"`
	BranchID             string                  `json:"branch_id"`
	ProviderResolutionID string                  `json:"provider_resolution_id"`
	ProviderRevisionID   string                  `json:"provider_revision_id"`
	Image                SandboxImage            `json:"image"`
	RuntimeProfile       string                  `json:"runtime_profile"`
	Resources            SandboxResources        `json:"resources"`
	RequiredCapabilities []CapabilityRequirement `json:"required_capabilities"`
	OptionalCapabilities []CapabilityRequirement `json:"optional_capabilities,omitempty"`
	Network              NetworkPolicy           `json:"network"`
	Workspace            WorkspacePolicy         `json:"workspace"`
	Lease                LeasePolicy             `json:"lease"`
	PlacementConstraints *PlacementConstraints   `json:"placement_constraints,omitempty"`
	Security             SecurityPolicy          `json:"security"`
	Labels               map[string]string       `json:"labels,omitempty"`
	SandboxSlotKey       SandboxSlotKey          `json:"sandbox_slot_key"`
	AgentRunID           string                  `json:"agent_run_id,omitempty"`
}

type SandboxImage struct {
	Reference    string       `json:"reference"`
	Digest       SHA256Digest `json:"digest"`
	Architecture Architecture `json:"architecture,omitempty"`
}

type SandboxResources struct {
	CPUMillis             int64  `json:"cpu_millis"`
	MemoryBytes           int64  `json:"memory_bytes"`
	EphemeralStorageBytes int64  `json:"ephemeral_storage_bytes"`
	WorkspaceBytes        *int64 `json:"workspace_bytes,omitempty"`
	GPUCount              *int64 `json:"gpu_count,omitempty"`
	PIDsLimit             int64  `json:"pids_limit"`
}

type CapabilityRequirement struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Profile string `json:"profile,omitempty"`
}

type NetworkMode string

const (
	NetworkNone       NetworkMode = "none"
	NetworkRestricted NetworkMode = "restricted"
	NetworkFull       NetworkMode = "full"
)

func (v *NetworkMode) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "network mode", v, NetworkNone, NetworkRestricted, NetworkFull)
}

type NetworkPolicy struct {
	Mode                  NetworkMode `json:"mode"`
	PolicyReference       string      `json:"policy_reference,omitempty"`
	EgressGatewayRequired *bool       `json:"egress_gateway_required,omitempty"`
}

type WorkspaceMode string
type WorkspaceCommitMode string

const (
	WorkspaceEphemeral   WorkspaceMode       = "ephemeral"
	WorkspacePersistent  WorkspaceMode       = "persistent"
	WorkspaceReadOnly    WorkspaceCommitMode = "read_only"
	WorkspaceCASRevision WorkspaceCommitMode = "cas_new_revision"
)

func (v *WorkspaceMode) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "workspace mode", v, WorkspaceEphemeral, WorkspacePersistent)
}

func (v *WorkspaceCommitMode) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "workspace commit mode", v, WorkspaceReadOnly,
		WorkspaceCASRevision)
}

type WorkspacePolicy struct {
	Mode                     WorkspaceMode       `json:"mode"`
	BaseRevisionID           string              `json:"base_revision_id"`
	BaseRevisionDigest       SHA256Digest        `json:"base_revision_digest"`
	BaseWorkspaceHeadVersion int64               `json:"base_workspace_head_version"`
	CommitMode               WorkspaceCommitMode `json:"commit_mode"`
	SnapshotReference        string              `json:"snapshot_reference,omitempty"`
	MountPath                WorkspaceMountPath  `json:"mount_path,omitempty"`
}

type WorkspaceMountPath string

const WorkspaceMount WorkspaceMountPath = "/workspace"

func (v *WorkspaceMountPath) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "workspace mount path", v, WorkspaceMount)
}

type LeasePolicy struct {
	ExpiresAt           string `json:"expires_at"`
	MaxExtensionSeconds int64  `json:"max_extension_seconds"`
}

type ResourceClass string

const (
	ResourceStandard ResourceClass = "standard"
	ResourceBrowser  ResourceClass = "browser"
	ResourceOffice   ResourceClass = "office"
	ResourceVideo    ResourceClass = "video"
	ResourceGPU      ResourceClass = "gpu"
)

func (v *ResourceClass) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "resource class", v, ResourceStandard, ResourceBrowser,
		ResourceOffice, ResourceVideo, ResourceGPU)
}

type PlacementConstraints struct {
	RegionID      string        `json:"region_id,omitempty"`
	ResourceClass ResourceClass `json:"resource_class,omitempty"`
	Architecture  Architecture  `json:"architecture,omitempty"`
}

type RootFilesystem string
type ServiceAccountMode string
type SeccompProfile string

const (
	RootFilesystemReadOnly        RootFilesystem     = "read_only"
	RootFilesystemWritableOverlay RootFilesystem     = "writable_overlay"
	ServiceAccountNone            ServiceAccountMode = "none"
	ServiceAccountRestricted      ServiceAccountMode = "restricted"
	SeccompRuntimeDefault         SeccompProfile     = "runtime-default"
	SeccompLocalhostProfile       SeccompProfile     = "localhost-profile"
)

func (v *RootFilesystem) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "root filesystem", v, RootFilesystemReadOnly,
		RootFilesystemWritableOverlay)
}

func (v *ServiceAccountMode) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "service account mode", v, ServiceAccountNone,
		ServiceAccountRestricted)
}

func (v *SeccompProfile) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "seccomp profile", v, SeccompRuntimeDefault,
		SeccompLocalhostProfile)
}

type SecurityPolicy struct {
	PrivilegeLevel           PrivilegeLevel     `json:"privilege_level"`
	RootFilesystem           RootFilesystem     `json:"root_filesystem"`
	ServiceAccountMode       ServiceAccountMode `json:"service_account_mode"`
	AllowPrivilegeEscalation bool               `json:"allow_privilege_escalation"`
	HostNamespaceAccess      bool               `json:"host_namespace_access"`
	SeccompProfile           SeccompProfile     `json:"seccomp_profile,omitempty"`
}

type PrivilegeLevel string

const PrivilegeUnprivileged PrivilegeLevel = "unprivileged"

func (v *PrivilegeLevel) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "privilege level", v, PrivilegeUnprivileged)
}

type Operation struct {
	OperationID         string         `json:"operation_id"`
	AttemptID           string         `json:"attempt_id"`
	FencingToken        int64          `json:"fencing_token"`
	SandboxID           string         `json:"sandbox_id"`
	Type                OperationType  `json:"type"`
	Status              OperationState `json:"status"`
	ProviderOperationID string         `json:"provider_operation_id,omitempty"`
	ResultReference     string         `json:"result_reference,omitempty"`
	Error               *ProviderError `json:"error,omitempty"`
	ObservedAt          string         `json:"observed_at"`
}

type ProviderError struct {
	Code         string         `json:"code"`
	Message      string         `json:"message"`
	Retryable    bool           `json:"retryable"`
	Outcome      ErrorOutcome   `json:"outcome"`
	ProviderCode string         `json:"provider_code,omitempty"`
	Details      BoundedDetails `json:"details,omitempty"`
}

type ExecResultStatus string

const (
	ExecCompleted      ExecResultStatus = "completed"
	ExecFailed         ExecResultStatus = "failed"
	ExecCancelled      ExecResultStatus = "cancelled"
	ExecOutcomeUnknown ExecResultStatus = "outcome_unknown"
)

func (v *ExecResultStatus) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "exec result status", v, ExecCompleted, ExecFailed,
		ExecCancelled, ExecOutcomeUnknown)
}

type ExecResult struct {
	OperationID     string           `json:"operation_id"`
	AttemptID       string           `json:"attempt_id"`
	FencingToken    int64            `json:"fencing_token"`
	SandboxID       string           `json:"sandbox_id"`
	Status          ExecResultStatus `json:"status"`
	ExitCode        *int64           `json:"exit_code,omitempty"`
	Signal          string           `json:"signal,omitempty"`
	StdoutReference string           `json:"stdout_reference,omitempty"`
	StderrReference string           `json:"stderr_reference,omitempty"`
	StartedAt       string           `json:"started_at"`
	CompletedAt     string           `json:"completed_at"`
	Usage           []UsageEntry     `json:"usage,omitempty"`
	Error           *ProviderError   `json:"error,omitempty"`
	RetainedUntil   string           `json:"retained_until"`
}

type ArtifactStagingRequest struct {
	MutationEnvelope
	ExpectedGeneration int64        `json:"expected_generation"`
	ArtifactReference  string       `json:"artifact_reference"`
	SourcePath         string       `json:"source_path"`
	ExpectedDigest     SHA256Digest `json:"expected_digest"`
	ExpectedMediaType  string       `json:"expected_media_type"`
	MaxBytes           int64        `json:"max_bytes"`
	RetentionSeconds   int64        `json:"retention_seconds"`
}

type ArtifactStagingStatus string

const (
	ArtifactStaged   ArtifactStagingStatus = "staged"
	ArtifactRejected ArtifactStagingStatus = "rejected"
)

func (v *ArtifactStagingStatus) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "artifact staging status", v, ArtifactStaged, ArtifactRejected)
}

type EvidenceCheckStatus string

const (
	EvidenceCheckPassed EvidenceCheckStatus = "passed"
	EvidenceCheckFailed EvidenceCheckStatus = "failed"
	EvidenceCheckNotRun EvidenceCheckStatus = "not_run"
)

func (v *EvidenceCheckStatus) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "evidence check status", v, EvidenceCheckPassed, EvidenceCheckFailed, EvidenceCheckNotRun)
}

type EvidenceCheck struct {
	Status            EvidenceCheckStatus `json:"status"`
	CheckedAt         string              `json:"checked_at"`
	EvidenceReference string              `json:"evidence_reference,omitempty"`
}

type ArtifactStagingEvidence struct {
	OperationID        string                `json:"operation_id"`
	AttemptID          string                `json:"attempt_id"`
	FencingToken       int64                 `json:"fencing_token"`
	SandboxID          string                `json:"sandbox_id"`
	ArtifactReference  string                `json:"artifact_reference"`
	StagingReference   string                `json:"staging_reference,omitempty"`
	Status             ArtifactStagingStatus `json:"status"`
	ContentDigest      SHA256Digest          `json:"content_digest"`
	MediaType          string                `json:"media_type"`
	SizeBytes          int64                 `json:"size_bytes"`
	TenantBindingCheck EvidenceCheck         `json:"tenant_binding_check"`
	ActiveContentCheck EvidenceCheck         `json:"active_content_check"`
	MalwareCheck       EvidenceCheck         `json:"malware_check"`
	ObservedAt         string                `json:"observed_at"`
	ExpiresAt          string                `json:"expires_at"`
	EvidenceDigest     SHA256Digest          `json:"evidence_digest"`
}

type UsageReconciliationStatus string

const (
	UsageReconciliationComplete UsageReconciliationStatus = "complete"
	UsageReconciliationPartial  UsageReconciliationStatus = "partial"
	UsageReconciliationUnknown  UsageReconciliationStatus = "unknown"
)

func (v *UsageReconciliationStatus) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "usage reconciliation status", v, UsageReconciliationComplete, UsageReconciliationPartial, UsageReconciliationUnknown)
}

type UsageEvidence struct {
	EvidenceID           string                    `json:"evidence_id"`
	SandboxID            string                    `json:"sandbox_id"`
	OperationID          string                    `json:"operation_id"`
	AttemptID            string                    `json:"attempt_id"`
	FencingToken         int64                     `json:"fencing_token"`
	Entries              []UsageEntry              `json:"entries"`
	ReconciliationStatus UsageReconciliationStatus `json:"reconciliation_status"`
	ObservedAt           string                    `json:"observed_at"`
	RetainedUntil        string                    `json:"retained_until"`
	EvidenceDigest       SHA256Digest              `json:"evidence_digest"`
}

type MeterID string
type MeterSource string

const (
	MeterWallTime         MeterID     = "sandbox.wall_time_milliseconds"
	MeterCPU              MeterID     = "sandbox.cpu_nanoseconds"
	MeterMemory           MeterID     = "sandbox.memory_byte_milliseconds"
	MeterNetworkIngress   MeterID     = "sandbox.network_ingress_bytes"
	MeterNetworkEgress    MeterID     = "sandbox.network_egress_bytes"
	MeterStorageRead      MeterID     = "sandbox.storage_read_bytes"
	MeterStorageWrite     MeterID     = "sandbox.storage_write_bytes"
	MeterWorkspacePeak    MeterID     = "sandbox.workspace_peak_bytes"
	MeterExecCount        MeterID     = "sandbox.exec_count"
	MeterBrowserSession   MeterID     = "sandbox.browser_session_milliseconds"
	MeterSourcePlatform   MeterSource = "platform_metered"
	MeterSourceRuntime    MeterSource = "runtime_metered"
	MeterSourceReconciled MeterSource = "reconciled"
)

func (v *MeterID) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "meter ID", v, MeterWallTime, MeterCPU, MeterMemory,
		MeterNetworkIngress, MeterNetworkEgress, MeterStorageRead, MeterStorageWrite,
		MeterWorkspacePeak, MeterExecCount, MeterBrowserSession)
}

func (v *MeterSource) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "meter source", v, MeterSourcePlatform,
		MeterSourceRuntime, MeterSourceReconciled)
}

type UsageEntry struct {
	EntryID           string      `json:"entry_id"`
	SandboxID         string      `json:"sandbox_id"`
	WorkOrderID       string      `json:"work_order_id,omitempty"`
	InvocationID      string      `json:"invocation_id,omitempty"`
	OperationID       string      `json:"operation_id,omitempty"`
	Meter             MeterID     `json:"meter"`
	Quantity          int64       `json:"quantity"`
	Unit              string      `json:"unit"`
	MeterSource       MeterSource `json:"meter_source"`
	EvidenceReference string      `json:"evidence_reference,omitempty"`
	OccurredAt        string      `json:"occurred_at"`
}

type RuntimeSessionHandoff struct {
	OperationID               string              `json:"operation_id"`
	AttemptID                 string              `json:"attempt_id"`
	FencingToken              int64               `json:"fencing_token"`
	SandboxID                 string              `json:"sandbox_id"`
	RuntimeSessionID          string              `json:"runtime_session_id"`
	RuntimeType               TerminalRuntimeType `json:"runtime_type"`
	CapabilityProfileID       string              `json:"capability_profile_id"`
	Protocol                  TerminalProtocol    `json:"protocol"`
	InternalEndpointReference string              `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64               `json:"connection_generation"`
	ExpiresAt                 string              `json:"expires_at"`
}

type BrowserSessionHandoff struct {
	OperationID               string          `json:"operation_id"`
	AttemptID                 string          `json:"attempt_id"`
	FencingToken              int64           `json:"fencing_token"`
	SandboxID                 string          `json:"sandbox_id"`
	BrowserSessionID          string          `json:"browser_session_id"`
	CapabilityProfileID       string          `json:"capability_profile_id"`
	Protocol                  BrowserProtocol `json:"protocol"`
	InternalEndpointReference string          `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64           `json:"connection_generation"`
	ExpiresAt                 string          `json:"expires_at"`
}

type BrowserProtocol string

const BrowserProtocolWebSocket BrowserProtocol = "websocket"

func (v *BrowserProtocol) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "browser protocol", v, BrowserProtocolWebSocket)
}

type TerminalProtocol string

const TerminalProtocolWebSocket TerminalProtocol = "websocket"

func (v *TerminalProtocol) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "terminal protocol", v, TerminalProtocolWebSocket)
}

type SnapshotPortability string

const (
	PortabilitySameRevision       SnapshotPortability = "same_revision"
	PortabilityCompatibleRevision SnapshotPortability = "compatible_revision"
	PortabilityPortable           SnapshotPortability = "portable"
)

func (v *SnapshotPortability) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "snapshot portability", v, PortabilitySameRevision,
		PortabilityCompatibleRevision, PortabilityPortable)
}

type SnapshotManifest struct {
	SnapshotID               string                 `json:"snapshot_id"`
	SandboxID                string                 `json:"sandbox_id"`
	SourceProviderRevisionID string                 `json:"source_provider_revision_id"`
	SourceRuntimeRevision    string                 `json:"source_runtime_revision"`
	Level                    SnapshotLevel          `json:"level"`
	Portability              SnapshotPortability    `json:"portability"`
	CompatibilityProfile     string                 `json:"compatibility_profile"`
	CompatibilityDecision    *CompatibilityDecision `json:"compatibility_decision,omitempty"`
	Digest                   SHA256Digest           `json:"digest"`
	SizeBytes                int64                  `json:"size_bytes"`
	CreatedAt                string                 `json:"created_at"`
	ContentReference         string                 `json:"content_reference"`
}

type CompatibilityDecision struct {
	DecisionID               string                    `json:"decision_id"`
	DecisionDigest           SHA256Digest              `json:"decision_digest"`
	SubjectKind              CompatibilitySubjectKind  `json:"subject_kind"`
	SubjectID                string                    `json:"subject_id"`
	SubjectDigest            SHA256Digest              `json:"subject_digest"`
	SourceProviderRevisionID string                    `json:"source_provider_revision_id"`
	SourceRuntimeRevision    string                    `json:"source_runtime_revision"`
	TargetProviderRevisionID string                    `json:"target_provider_revision_id"`
	TargetRuntimeRevision    string                    `json:"target_runtime_revision"`
	CompatibilityProfile     string                    `json:"compatibility_profile"`
	Evidence                 []CompatibilityEvidence   `json:"evidence"`
	Result                   CompatibilityResult       `json:"result"`
	ReasonCodes              []CompatibilityReasonCode `json:"reason_codes"`
	DecidedAt                string                    `json:"decided_at"`
}

type CompatibilityEvidence struct {
	EvidenceID               string                      `json:"evidence_id"`
	EvidenceDigest           SHA256Digest                `json:"evidence_digest"`
	SubjectKind              CompatibilitySubjectKind    `json:"subject_kind"`
	SourceProviderRevisionID string                      `json:"source_provider_revision_id"`
	SourceRuntimeRevision    string                      `json:"source_runtime_revision"`
	TargetProviderRevisionID string                      `json:"target_provider_revision_id"`
	TargetRuntimeRevision    string                      `json:"target_runtime_revision"`
	SuiteID                  string                      `json:"suite_id"`
	SuiteVersion             string                      `json:"suite_version"`
	SuiteDigest              SHA256Digest                `json:"suite_digest"`
	ProfileID                string                      `json:"profile_id"`
	TestRunReference         string                      `json:"test_run_reference"`
	TestRunDigest            SHA256Digest                `json:"test_run_digest"`
	Result                   CompatibilityEvidenceResult `json:"result"`
	CompletedAt              string                      `json:"completed_at"`
}

type CompatibilitySubjectKind string
type CompatibilityResult string
type CompatibilityEvidenceResult string
type CompatibilityReasonCode string

const (
	CompatibilityRuntimeCheckpoint CompatibilitySubjectKind    = "runtime_checkpoint"
	CompatibilitySandboxSnapshot   CompatibilitySubjectKind    = "sandbox_snapshot"
	CompatibilityCompatible        CompatibilityResult         = "compatible"
	CompatibilityIncompatible      CompatibilityResult         = "incompatible"
	CompatibilityEvidencePassed    CompatibilityEvidenceResult = "passed"
	CompatibilityEvidenceFailed    CompatibilityEvidenceResult = "failed"
	CompatibilitySuitePassed       CompatibilityReasonCode     = "suite_passed"
	CompatibilitySuiteFailed       CompatibilityReasonCode     = "suite_failed"
	CompatibilityProfileMismatch   CompatibilityReasonCode     = "profile_mismatch"
	CompatibilitySourceMismatch    CompatibilityReasonCode     = "source_mismatch"
	CompatibilityTargetMismatch    CompatibilityReasonCode     = "target_mismatch"
	CompatibilityEvidenceMissing   CompatibilityReasonCode     = "evidence_missing"
	CompatibilityEvidenceExpired   CompatibilityReasonCode     = "evidence_expired"
	CompatibilityPolicyDenied      CompatibilityReasonCode     = "policy_denied"
)

func (v *CompatibilitySubjectKind) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "compatibility subject kind", v,
		CompatibilityRuntimeCheckpoint, CompatibilitySandboxSnapshot)
}

func (v *CompatibilityResult) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "compatibility result", v,
		CompatibilityCompatible, CompatibilityIncompatible)
}

func (v *CompatibilityEvidenceResult) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "compatibility evidence result", v,
		CompatibilityEvidencePassed, CompatibilityEvidenceFailed)
}

func (v *CompatibilityReasonCode) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "compatibility reason code", v,
		CompatibilitySuitePassed, CompatibilitySuiteFailed,
		CompatibilityProfileMismatch, CompatibilitySourceMismatch,
		CompatibilityTargetMismatch, CompatibilityEvidenceMissing,
		CompatibilityEvidenceExpired, CompatibilityPolicyDenied)
}

type Status struct {
	SandboxID                string         `json:"sandbox_id"`
	TenantID                 string         `json:"tenant_id"`
	WorkOrderID              string         `json:"work_order_id"`
	WorkspaceID              string         `json:"workspace_id"`
	ProviderRevisionID       string         `json:"provider_revision_id"`
	DesiredState             DesiredState   `json:"desired_state"`
	ObservedState            ObservedState  `json:"observed_state"`
	Generation               int64          `json:"generation"`
	ObservedGeneration       int64          `json:"observed_generation"`
	RuntimeProfile           string         `json:"runtime_profile,omitempty"`
	RuntimeEndpointReference string         `json:"runtime_endpoint_reference,omitempty"`
	LeaseExpiresAt           string         `json:"lease_expires_at"`
	SnapshotReference        string         `json:"snapshot_reference,omitempty"`
	LastError                *ProviderError `json:"last_error,omitempty"`
	CreatedAt                string         `json:"created_at"`
	UpdatedAt                string         `json:"updated_at"`
	SandboxSlotKey           SandboxSlotKey `json:"sandbox_slot_key"`
	AgentRunID               string         `json:"agent_run_id,omitempty"`
	ProviderStateReference   string         `json:"provider_state_reference,omitempty"`
}

type BoundedDetails map[string]any

type StandardError struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	Retryable  bool           `json:"retryable"`
	TraceID    string         `json:"trace_id"`
	Details    BoundedDetails `json:"details,omitempty"`
	Violations []Violation    `json:"violations,omitempty"`
}

type Violation struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}
