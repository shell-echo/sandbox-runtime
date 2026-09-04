package caller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var bareBackendIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Capabilities struct {
	ProviderRevisionID      string                   `json:"provider_revision_id"`
	APIVersion              string                   `json:"api_version"`
	Capabilities            []Capability             `json:"capabilities"`
	RuntimeProfiles         []RuntimeProfile         `json:"runtime_profiles"`
	SnapshotRestoreProfiles []SnapshotRestoreProfile `json:"snapshot_restore_profiles"`
	Limits                  ProviderLimits           `json:"limits"`
}

type Capability struct {
	ID       string   `json:"id"`
	Versions []string `json:"versions"`
	Profiles []string `json:"profiles,omitempty"`
}

type RuntimeProfile struct {
	ID                   string   `json:"id"`
	IsolationClass       string   `json:"isolation_class"`
	RuntimeClassName     string   `json:"runtime_class_name,omitempty"`
	Architecture         []string `json:"architecture,omitempty"`
	CapabilityProfileIDs []string `json:"capability_profile_ids,omitempty"`
}

type SnapshotRestoreProfile struct {
	ProfileID    string `json:"profile_id"`
	Level        string `json:"level"`
	SuiteID      string `json:"suite_id"`
	SuiteVersion string `json:"suite_version"`
	SuiteDigest  string `json:"suite_digest"`
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

type Operation struct {
	OperationID         string         `json:"operation_id"`
	AttemptID           string         `json:"attempt_id"`
	FencingToken        int64          `json:"fencing_token"`
	SandboxID           string         `json:"sandbox_id"`
	Type                string         `json:"type"`
	Status              string         `json:"status"`
	ProviderOperationID string         `json:"provider_operation_id,omitempty"`
	ResultReference     string         `json:"result_reference,omitempty"`
	Error               *ProviderError `json:"error,omitempty"`
	ObservedAt          string         `json:"observed_at"`
}

type ProviderError struct {
	Code         string         `json:"code"`
	Message      string         `json:"message"`
	Retryable    bool           `json:"retryable"`
	Outcome      string         `json:"outcome"`
	ProviderCode string         `json:"provider_code,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

type StandardError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	TraceID   string `json:"trace_id"`
}

type SandboxStatus struct {
	SandboxID          string `json:"sandbox_id"`
	TenantID           string `json:"tenant_id"`
	WorkOrderID        string `json:"work_order_id"`
	WorkspaceID        string `json:"workspace_id"`
	ProviderRevisionID string `json:"provider_revision_id"`
	DesiredState       string `json:"desired_state"`
	ObservedState      string `json:"observed_state"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observed_generation"`
	RuntimeProfile     string `json:"runtime_profile"`
	LeaseExpiresAt     string `json:"lease_expires_at"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	SandboxSlotKey     string `json:"sandbox_slot_key"`
}

type ExecResult struct {
	OperationID     string         `json:"operation_id"`
	AttemptID       string         `json:"attempt_id"`
	FencingToken    int64          `json:"fencing_token"`
	SandboxID       string         `json:"sandbox_id"`
	Status          string         `json:"status"`
	ExitCode        *int64         `json:"exit_code,omitempty"`
	Signal          string         `json:"signal,omitempty"`
	StdoutReference string         `json:"stdout_reference,omitempty"`
	StderrReference string         `json:"stderr_reference,omitempty"`
	StartedAt       string         `json:"started_at"`
	CompletedAt     string         `json:"completed_at"`
	Usage           []UsageEntry   `json:"usage,omitempty"`
	Error           *ProviderError `json:"error,omitempty"`
	RetainedUntil   string         `json:"retained_until"`
}

type RuntimeSessionHandoff struct {
	OperationID               string `json:"operation_id"`
	AttemptID                 string `json:"attempt_id"`
	FencingToken              int64  `json:"fencing_token"`
	SandboxID                 string `json:"sandbox_id"`
	RuntimeSessionID          string `json:"runtime_session_id"`
	RuntimeType               string `json:"runtime_type"`
	CapabilityProfileID       string `json:"capability_profile_id"`
	Protocol                  string `json:"protocol"`
	InternalEndpointReference string `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64  `json:"connection_generation"`
	ExpiresAt                 string `json:"expires_at"`
}

type BrowserSessionHandoff struct {
	OperationID               string `json:"operation_id"`
	AttemptID                 string `json:"attempt_id"`
	FencingToken              int64  `json:"fencing_token"`
	SandboxID                 string `json:"sandbox_id"`
	BrowserSessionID          string `json:"browser_session_id"`
	CapabilityProfileID       string `json:"capability_profile_id"`
	Protocol                  string `json:"protocol"`
	InternalEndpointReference string `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64  `json:"connection_generation"`
	ExpiresAt                 string `json:"expires_at"`
}

type EvidenceCheck struct {
	Status            string `json:"status"`
	CheckedAt         string `json:"checked_at"`
	EvidenceReference string `json:"evidence_reference,omitempty"`
}

type ArtifactStagingEvidence struct {
	OperationID        string        `json:"operation_id"`
	AttemptID          string        `json:"attempt_id"`
	FencingToken       int64         `json:"fencing_token"`
	SandboxID          string        `json:"sandbox_id"`
	ArtifactReference  string        `json:"artifact_reference"`
	StagingReference   string        `json:"staging_reference,omitempty"`
	Status             string        `json:"status"`
	ContentDigest      string        `json:"content_digest"`
	MediaType          string        `json:"media_type"`
	SizeBytes          int64         `json:"size_bytes"`
	TenantBindingCheck EvidenceCheck `json:"tenant_binding_check"`
	ActiveContentCheck EvidenceCheck `json:"active_content_check"`
	MalwareCheck       EvidenceCheck `json:"malware_check"`
	ObservedAt         string        `json:"observed_at"`
	ExpiresAt          string        `json:"expires_at"`
	EvidenceDigest     string        `json:"evidence_digest"`
}

type UsageEvidence struct {
	EvidenceID           string       `json:"evidence_id"`
	SandboxID            string       `json:"sandbox_id"`
	OperationID          string       `json:"operation_id"`
	AttemptID            string       `json:"attempt_id"`
	FencingToken         int64        `json:"fencing_token"`
	Entries              []UsageEntry `json:"entries"`
	ReconciliationStatus string       `json:"reconciliation_status"`
	ObservedAt           string       `json:"observed_at"`
	RetainedUntil        string       `json:"retained_until"`
	EvidenceDigest       string       `json:"evidence_digest"`
}

type UsageEntry struct {
	EntryID           string `json:"entry_id"`
	SandboxID         string `json:"sandbox_id"`
	WorkOrderID       string `json:"work_order_id,omitempty"`
	InvocationID      string `json:"invocation_id,omitempty"`
	OperationID       string `json:"operation_id,omitempty"`
	Meter             string `json:"meter"`
	Quantity          int64  `json:"quantity"`
	Unit              string `json:"unit"`
	MeterSource       string `json:"meter_source"`
	EvidenceReference string `json:"evidence_reference,omitempty"`
	OccurredAt        string `json:"occurred_at"`
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("wire document has trailing input")
	}
	return nil
}

func isDigest(value string) bool { return digestPattern.MatchString(value) }

func checkNoBackendDisclosure(document []byte) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return inspectDisclosure("", value)
}

func inspectDisclosure(key string, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			lower := strings.ToLower(childKey)
			if childKey != "internal_endpoint_reference" && (strings.Contains(lower, "container_id") || strings.Contains(lower, "host_path") || strings.Contains(lower, "raw_endpoint") || strings.Contains(lower, "credential")) {
				return fmt.Errorf("forbidden wire field %q", childKey)
			}
			if err := inspectDisclosure(childKey, child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := inspectDisclosure(key, child); err != nil {
				return err
			}
		}
	case string:
		lower := strings.ToLower(typed)
		if strings.Contains(lower, "unix://") || strings.Contains(lower, "tcp://") || strings.Contains(lower, "/private/") || strings.Contains(lower, "/var/run/docker") || bareBackendIDPattern.MatchString(lower) {
			return fmt.Errorf("forbidden wire value at %q", key)
		}
	}
	return nil
}
