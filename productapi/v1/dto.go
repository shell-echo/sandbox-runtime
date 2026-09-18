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
	CapabilityID    string         `json:"capability_id"`
	Version         string         `json:"version"`
	ProtocolProfile string         `json:"protocol_profile"`
	Readiness       string         `json:"readiness"`
	Limits          map[string]any `json:"limits"`
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

func toSession(session product.RuntimeSession) RuntimeSession {
	return RuntimeSession{SessionID: session.ID, WorkspaceID: session.WorkspaceID, SlotKey: session.SlotKey, Kind: session.Kind, ProtocolProfile: session.ProtocolProfile, State: session.State, RequiresControlLease: session.RequiresControlLease, RecordingPolicy: session.RecordingPolicy, Version: session.Version, ExpiresAt: timestamp(session.ExpiresAt), CreatedAt: timestamp(session.CreatedAt), UpdatedAt: timestamp(session.UpdatedAt)}
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
