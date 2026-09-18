package productapiv1

import (
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
)

const APIVersion = "product.sandbox-runtime/v1alpha1"

type ActorRef struct {
	ActorType string `json:"actor_type"`
	ActorID   string `json:"actor_id"`
}

type CapabilityRequirement struct {
	CapabilityID string `json:"capability_id"`
	Version      string `json:"version"`
	ProfileID    string `json:"profile_id"`
}

type SlotSpec struct {
	SlotKey              string                  `json:"slot_key"`
	Kind                 string                  `json:"kind"`
	ProfileID            string                  `json:"profile_id"`
	RequiredCapabilities []CapabilityRequirement `json:"required_capabilities"`
	DesiredState         string                  `json:"desired_state"`
}

type CreateWorkspaceRequest struct {
	DisplayName     string   `json:"display_name"`
	LifetimeSeconds int64    `json:"lifetime_seconds"`
	PrimarySlot     SlotSpec `json:"primary_slot"`
}

type WorkspaceSlot struct {
	SlotKey              string                  `json:"slot_key"`
	Kind                 string                  `json:"kind"`
	ProfileID            string                  `json:"profile_id"`
	RequiredCapabilities []CapabilityRequirement `json:"required_capabilities"`
	DesiredState         string                  `json:"desired_state"`
	ObservedState        string                  `json:"observed_state"`
	Generation           int64                   `json:"generation"`
	ObservedGeneration   int64                   `json:"observed_generation"`
	Version              int64                   `json:"version"`
	CreatedAt            string                  `json:"created_at"`
	UpdatedAt            string                  `json:"updated_at"`
}

type Workspace struct {
	APIVersion     string          `json:"api_version"`
	WorkspaceID    string          `json:"workspace_id"`
	TenantID       string          `json:"tenant_id"`
	Owner          ActorRef        `json:"owner"`
	DisplayName    string          `json:"display_name"`
	PrimarySlotKey string          `json:"primary_slot_key"`
	DesiredState   string          `json:"desired_state"`
	ObservedState  string          `json:"observed_state"`
	Version        int64           `json:"version"`
	LeaseExpiresAt string          `json:"lease_expires_at"`
	Slots          []WorkspaceSlot `json:"slots"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
}

type WorkspacePage struct {
	Items      []Workspace `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type ProductOperation struct {
	OperationID         string   `json:"operation_id"`
	OperationType       string   `json:"operation_type"`
	WorkspaceID         string   `json:"workspace_id"`
	SlotKey             string   `json:"slot_key,omitempty"`
	SessionID           string   `json:"session_id,omitempty"`
	AgentRunID          string   `json:"agent_run_id,omitempty"`
	SubmittedBy         ActorRef `json:"submitted_by"`
	State               string   `json:"state"`
	ReconciliationState string   `json:"reconciliation_status"`
	Version             int64    `json:"version"`
	AcceptedAt          string   `json:"accepted_at"`
	UpdatedAt           string   `json:"updated_at"`
}

type CapabilityDocument struct {
	ContractNamespace string              `json:"contract_namespace"`
	ContractVersion   string              `json:"contract_version"`
	Capabilities      []ProductCapability `json:"capabilities"`
	MaxPageSize       int                 `json:"max_page_size"`
}

type ProductCapability struct {
	CapabilityID      string   `json:"capability_id"`
	Version           string   `json:"version"`
	Readiness         string   `json:"readiness"`
	ProtocolProfiles  []string `json:"protocol_profiles"`
	MaxSessionSeconds int64    `json:"max_session_seconds,omitempty"`
}

type ProductError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"request_id"`
}

type ControlScope struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
}
type AcquireControlLeaseRequest struct {
	ExpectedWorkspaceVersion int64        `json:"expected_workspace_version"`
	Scope                    ControlScope `json:"scope"`
	DurationSeconds          int64        `json:"duration_seconds"`
}
type RenewControlLeaseRequest struct {
	Fence           int64 `json:"fence"`
	DurationSeconds int64 `json:"duration_seconds"`
}
type ReleaseControlLeaseRequest struct {
	Fence  int64  `json:"fence"`
	Reason string `json:"reason"`
}
type ControlLease struct {
	LeaseID     string       `json:"lease_id"`
	WorkspaceID string       `json:"workspace_id"`
	Scope       ControlScope `json:"scope"`
	Controller  ActorRef     `json:"controller"`
	Fence       int64        `json:"fence"`
	IssuedAt    string       `json:"issued_at"`
	ExpiresAt   string       `json:"expires_at"`
}

func toControlLease(lease product.ControlLease) ControlLease {
	return ControlLease{LeaseID: lease.ID, WorkspaceID: lease.WorkspaceID, Scope: ControlScope{ScopeType: lease.Scope.Type, ScopeID: lease.Scope.ID}, Controller: toActor(lease.Controller), Fence: lease.Fence, IssuedAt: timestamp(lease.IssuedAt), ExpiresAt: timestamp(lease.ExpiresAt)}
}

type CreateSessionRequest struct {
	ExpectedWorkspaceVersion int64  `json:"expected_workspace_version"`
	SlotKey                  string `json:"slot_key"`
	Kind                     string `json:"kind"`
	ProtocolProfile          string `json:"protocol_profile"`
	ExpiresInSeconds         int64  `json:"expires_in_seconds"`
	RecordingPolicy          string `json:"recording_policy"`
}
type CloseSessionRequest struct {
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason"`
}
type ResizeSessionRequest struct {
	ExpectedVersion int64  `json:"expected_version"`
	Columns         int    `json:"columns"`
	Rows            int    `json:"rows"`
	ControlLeaseID  string `json:"control_lease_id"`
	ControlFence    int64  `json:"control_fence"`
}
type RuntimeSession struct {
	SessionID            string `json:"session_id"`
	WorkspaceID          string `json:"workspace_id"`
	SlotKey              string `json:"slot_key"`
	Kind                 string `json:"kind"`
	ProtocolProfile      string `json:"protocol_profile"`
	State                string `json:"state"`
	RequiresControlLease bool   `json:"requires_control_lease"`
	RecordingPolicy      string `json:"recording_policy"`
	Version              int64  `json:"version"`
	ExpiresAt            string `json:"expires_at"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
}
type SessionPage struct {
	Items      []RuntimeSession `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type Artifact struct {
	ArtifactID  string   `json:"artifact_id"`
	WorkspaceID string   `json:"workspace_id"`
	SlotKey     string   `json:"slot_key,omitempty"`
	Name        string   `json:"name"`
	MediaType   string   `json:"media_type"`
	SizeBytes   int64    `json:"size_bytes"`
	Digest      string   `json:"digest"`
	State       string   `json:"state"`
	CreatedBy   ActorRef `json:"created_by"`
	CreatedAt   string   `json:"created_at"`
}

type ArtifactPage struct {
	Items      []Artifact `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type Recording struct {
	RecordingID        string `json:"recording_id"`
	WorkspaceID        string `json:"workspace_id"`
	SessionID          string `json:"session_id,omitempty"`
	AgentRunID         string `json:"agent_run_id,omitempty"`
	RecordingType      string `json:"recording_type"`
	State              string `json:"state"`
	Digest             string `json:"digest,omitempty"`
	SizeBytes          *int64 `json:"size_bytes,omitempty"`
	StartedAt          string `json:"started_at"`
	CompletedAt        string `json:"completed_at,omitempty"`
	RetentionExpiresAt string `json:"retention_expires_at"`
}

type RecordingPage struct {
	Items      []Recording `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

func toArtifact(value product.Artifact) Artifact {
	return Artifact{ArtifactID: value.ID, WorkspaceID: value.WorkspaceID, SlotKey: value.SlotKey, Name: value.Name, MediaType: value.MediaType, SizeBytes: value.SizeBytes, Digest: value.Digest, State: value.State, CreatedBy: toActor(value.CreatedBy), CreatedAt: timestamp(value.CreatedAt)}
}

func toRecording(value product.Recording) Recording {
	projected := Recording{RecordingID: value.ID, WorkspaceID: value.WorkspaceID, SessionID: value.SessionID, AgentRunID: value.AgentRunID, RecordingType: value.Type, State: value.State, Digest: value.Digest, StartedAt: timestamp(value.StartedAt), RetentionExpiresAt: timestamp(value.RetentionExpiresAt)}
	if value.State == "available" || value.State == "expired" || value.State == "deleted" {
		size := value.SizeBytes
		projected.SizeBytes = &size
	}
	if !value.CompletedAt.IsZero() && value.CompletedAt.Unix() > 1 {
		projected.CompletedAt = timestamp(value.CompletedAt)
	}
	return projected
}

func toSession(session product.RuntimeSession) RuntimeSession {
	return RuntimeSession{SessionID: session.ID, WorkspaceID: session.WorkspaceID, SlotKey: session.SlotKey, Kind: session.Kind, ProtocolProfile: session.ProtocolProfile, State: session.State, RequiresControlLease: session.RequiresControlLease, RecordingPolicy: session.RecordingPolicy, Version: session.Version, ExpiresAt: timestamp(session.ExpiresAt), CreatedAt: timestamp(session.CreatedAt), UpdatedAt: timestamp(session.UpdatedAt)}
}

type CreateConnectionRequest struct {
	ExpectedSessionVersion int64  `json:"expected_session_version"`
	ProtocolProfile        string `json:"protocol_profile"`
	ControlLeaseID         string `json:"control_lease_id,omitempty"`
	ControlFence           int64  `json:"control_fence,omitempty"`
}

type ConnectionGrant struct {
	ConnectionID     string `json:"connection_id"`
	SessionID        string `json:"session_id"`
	ProtocolProfile  string `json:"protocol_profile"`
	GatewayURI       string `json:"gateway_uri"`
	ConnectionTicket string `json:"connection_ticket"`
	ExpiresAt        string `json:"expires_at"`
}

func toConnectionGrant(grant product.ConnectionGrant) ConnectionGrant {
	return ConnectionGrant{
		ConnectionID: grant.ID, SessionID: grant.SessionID,
		ProtocolProfile: grant.ProtocolProfile, GatewayURI: grant.GatewayURI,
		ConnectionTicket: grant.Ticket, ExpiresAt: timestamp(grant.ExpiresAt),
	}
}

func toOperation(operation product.Operation) ProductOperation {
	return ProductOperation{
		OperationID: operation.ID, OperationType: operation.Type, WorkspaceID: operation.WorkspaceID,
		SlotKey: operation.SlotKey, SessionID: operation.SessionID, AgentRunID: operation.AgentRunID,
		SubmittedBy: toActor(operation.SubmittedBy), State: operation.State,
		ReconciliationState: operation.ReconciliationStatus, Version: operation.Version,
		AcceptedAt: timestamp(operation.AcceptedAt), UpdatedAt: timestamp(operation.UpdatedAt),
	}
}

func toWorkspace(workspace product.Workspace) Workspace {
	projected := Workspace{
		APIVersion: APIVersion, WorkspaceID: workspace.ID, TenantID: workspace.TenantID,
		Owner: toActor(workspace.Owner), DisplayName: workspace.DisplayName,
		PrimarySlotKey: workspace.PrimarySlotKey, DesiredState: workspace.DesiredState,
		ObservedState: workspace.ObservedState, Version: workspace.Version,
		LeaseExpiresAt: timestamp(workspace.LeaseExpiresAt), CreatedAt: timestamp(workspace.CreatedAt),
		UpdatedAt: timestamp(workspace.UpdatedAt), Slots: make([]WorkspaceSlot, 0, len(workspace.Slots)),
	}
	for _, slot := range workspace.Slots {
		capabilities := make([]CapabilityRequirement, 0, len(slot.RequiredCapabilities))
		for _, capability := range slot.RequiredCapabilities {
			capabilities = append(capabilities, CapabilityRequirement{
				CapabilityID: capability.CapabilityID, Version: capability.Version, ProfileID: capability.ProfileID,
			})
		}
		projected.Slots = append(projected.Slots, WorkspaceSlot{
			SlotKey: slot.SlotKey, Kind: slot.Kind, ProfileID: slot.ProfileID,
			RequiredCapabilities: capabilities, DesiredState: slot.DesiredState,
			ObservedState: slot.ObservedState, Generation: slot.Generation,
			ObservedGeneration: slot.ObservedGeneration, Version: slot.Version,
			CreatedAt: timestamp(slot.CreatedAt), UpdatedAt: timestamp(slot.UpdatedAt),
		})
	}
	return projected
}

func toActor(actor product.ActorRef) ActorRef {
	return ActorRef{ActorType: string(actor.Type), ActorID: actor.ID}
}

func timestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
