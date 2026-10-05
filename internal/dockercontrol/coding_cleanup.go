package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

const (
	CodingCleanupProtocol = "sandbox-runtime.docker-control-coding-cleanup.v1"
	CodingCleanupAction   = "coding.retire"
	MaxCleanupBytes       = 4 << 10
)

// CodingCleanupAuthority is a separate short-lived, Provider-PG-owned
// retirement intent. It identifies the original create effect and birth
// generation but has a distinct current operation/generation binding. This
// envelope cannot itself prove daemon quiescence or authorize deletion of a
// mismatched physical resource. No public Provider DTO is changed.
// A legitimate terminate or lease expiry can retain the birth fence; the
// issuing Provider transaction must bind CleanupFence to its *current*
// highwater and uniquely reserve this cleanup operation, not merely compare
// two numbers in this envelope.
type CodingCleanupAuthority struct {
	Protocol                string    `json:"protocol"`
	Action                  string    `json:"action"`
	RequestID               string    `json:"request_id"`
	OriginalAuthorityDigest string    `json:"original_authority_digest"`
	EffectID                string    `json:"effect_id"`
	ProfileDigest           string    `json:"profile_digest"`
	ControlPolicyDigest     string    `json:"control_policy_digest"`
	PeerDeployment          string    `json:"peer_deployment"`
	PeerPrincipalDigest     string    `json:"peer_principal_digest"`
	ProviderRevisionID      string    `json:"provider_revision_id"`
	TenantDigest            string    `json:"tenant_digest"`
	AllocationID            string    `json:"allocation_id"`
	SandboxID               string    `json:"sandbox_id"`
	PlanDigest              string    `json:"plan_digest"`
	SlotID                  string    `json:"slot_id"`
	BirthGeneration         uint64    `json:"birth_generation"`
	BirthFence              uint64    `json:"birth_fence"`
	CleanupOperationID      string    `json:"cleanup_operation_id"`
	CleanupAttemptID        string    `json:"cleanup_attempt_id"`
	CleanupRequestDigest    string    `json:"cleanup_request_digest"`
	CurrentGeneration       uint64    `json:"current_generation"`
	CleanupFence            uint64    `json:"cleanup_fence"`
	OperationDeadline       time.Time `json:"operation_deadline"`
	IssuedAt                time.Time `json:"issued_at"`
	ExpiresAt               time.Time `json:"expires_at"`
}

// NewCodingCleanupAuthority must be called from one Provider PostgreSQL
// transaction containing the current Cleaning reservation, termination
// operation and sandbox. It intentionally does not admit Creating: that
// transition additionally needs independent external daemon-quiescence
// evidence and is not part of this conservative constructor.
func NewCodingCleanupAuthority(ctx context.Context, create CodingCreateAuthority,
	reservation codingidentity.Reservation, operation lifecycle.Operation, sandbox lifecycle.Sandbox,
	plan codingidentity.Plan, controlPolicyDigest, peerPrincipalDigest string,
	now time.Time) (CodingCleanupAuthority, error) {
	planDigest, planErr := plan.Digest()
	tenantDigest, tenantErr := codingidentity.TenantDigestForID(sandbox.TenantID)
	var selected codingidentity.Slot
	for _, slot := range plan.Slots {
		if slot.ID == create.SlotID {
			selected = slot
			break
		}
	}
	if ctx == nil || ctx.Err() != nil || create.BindControl(plan, controlPolicyDigest,
		peerPrincipalDigest, reservation.SpecDigest, create.IssuedAt) != nil ||
		reservation.Status != codingidentity.Cleaning || reservation.PlanDigest != planDigest ||
		reservation.Slot != selected || reservation.Claim.Validate() != nil ||
		reservation.Claim.AllocationID != create.AllocationID ||
		reservation.Claim.SandboxID != create.SandboxID ||
		reservation.Claim.OperationID != create.OperationID || reservation.Claim.AttemptID != create.AttemptID ||
		reservation.Claim.RequestDigest != create.RequestDigest ||
		reservation.Claim.Generation != create.CreationGeneration || reservation.Claim.Fence != create.Fence ||
		reservation.Claim.TenantDigest != create.TenantDigest ||
		operation.Validate() != nil || operation.Type != lifecycle.OperationTerminate ||
		operation.State != lifecycle.OperationRunning || operation.CancelRequested || operation.Failure != nil ||
		!controlDigest.MatchString(operation.RequestDigest) ||
		operation.SandboxID != create.SandboxID || operation.ID == create.OperationID ||
		operation.FencingToken < create.Fence || !operation.Deadline.After(now) ||
		sandbox.Validate() != nil || sandbox.ID != create.SandboxID ||
		sandbox.ProviderRevisionID != create.ProviderRevisionID ||
		sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
		sandbox.DesiredState != lifecycle.DesiredTerminated ||
		sandbox.Generation <= create.CreationGeneration ||
		tenantErr != nil || tenantDigest != create.TenantDigest ||
		planErr != nil || planDigest != create.PlanDigest {
		return CodingCleanupAuthority{}, ErrInvalidAuthority
	}
	expiry := now.UTC().Add(MaxAuthorityAge)
	if operation.Deadline.Before(expiry) {
		expiry = operation.Deadline.UTC()
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expiry) {
		expiry = deadline.UTC()
	}
	authority := CodingCleanupAuthority{Protocol: CodingCleanupProtocol, Action: CodingCleanupAction,
		OriginalAuthorityDigest: create.Digest(), EffectID: create.EffectID,
		ProfileDigest: create.ProfileDigest, ControlPolicyDigest: controlPolicyDigest,
		PeerDeployment: "provider-runtime", PeerPrincipalDigest: peerPrincipalDigest,
		ProviderRevisionID: create.ProviderRevisionID, TenantDigest: create.TenantDigest,
		AllocationID: create.AllocationID, SandboxID: create.SandboxID,
		PlanDigest: planDigest, SlotID: create.SlotID,
		BirthGeneration: create.CreationGeneration, BirthFence: create.Fence,
		CleanupOperationID: operation.ID, CleanupAttemptID: operation.AttemptID,
		CleanupRequestDigest: operation.RequestDigest,
		CurrentGeneration:    sandbox.Generation, CleanupFence: operation.FencingToken,
		OperationDeadline: operation.Deadline.UTC(), IssuedAt: now.UTC(), ExpiresAt: expiry}
	authority.RequestID = codingCleanupRequestID(authority)
	if authority.Validate(now) != nil {
		return CodingCleanupAuthority{}, ErrInvalidAuthority
	}
	return authority, nil
}

func (a CodingCleanupAuthority) Validate(now time.Time) error {
	if a.Protocol != CodingCleanupProtocol || a.Action != CodingCleanupAction ||
		!controlDigest.MatchString(a.RequestID) || !controlDigest.MatchString(a.OriginalAuthorityDigest) ||
		!controlDigest.MatchString(a.EffectID) || !controlDigest.MatchString(a.ProfileDigest) ||
		!controlDigest.MatchString(a.ControlPolicyDigest) || a.PeerDeployment != "provider-runtime" ||
		!controlDigest.MatchString(a.PeerPrincipalDigest) || !controlID.MatchString(a.ProviderRevisionID) ||
		!controlDigest.MatchString(a.TenantDigest) || !controlAllocationID.MatchString(a.AllocationID) ||
		!controlID.MatchString(a.SandboxID) || !controlDigest.MatchString(a.PlanDigest) ||
		!controlID.MatchString(a.SlotID) || !controlID.MatchString(a.CleanupOperationID) ||
		!controlID.MatchString(a.CleanupAttemptID) ||
		!controlDigest.MatchString(a.CleanupRequestDigest) ||
		a.BirthGeneration == 0 || a.CurrentGeneration <= a.BirthGeneration ||
		a.BirthFence == 0 || a.CleanupFence < a.BirthFence ||
		a.RequestID != codingCleanupRequestID(a) ||
		!a.OperationDeadline.After(a.IssuedAt) || a.ExpiresAt.After(a.OperationDeadline) ||
		a.IssuedAt.IsZero() || a.IssuedAt.After(now) || !a.ExpiresAt.After(now) ||
		!a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.After(a.IssuedAt.Add(MaxAuthorityAge)) {
		return ErrInvalidAuthority
	}
	return nil
}

// BindProvider rechecks the same-transaction PG snapshot before the private
// envelope is sent. A stale termination operation cannot be refreshed by a
// Control-side receipt or caller-provided digest.
func (a CodingCleanupAuthority) BindProvider(create CodingCreateAuthority,
	reservation codingidentity.Reservation, operation lifecycle.Operation, sandbox lifecycle.Sandbox,
	plan codingidentity.Plan, controlPolicyDigest, authenticatedPeerDigest string,
	now time.Time) error {
	want, err := NewCodingCleanupAuthority(context.Background(), create, reservation,
		operation, sandbox, plan, controlPolicyDigest, authenticatedPeerDigest, a.IssuedAt)
	if err != nil || a.Validate(now) != nil || a.ExpiresAt.After(want.ExpiresAt) {
		return ErrInvalidAuthority
	}
	// The issuing Provider may have had an earlier parent-context deadline.
	// Bind every business field to the current PG snapshot while permitting
	// only a shorter, still-live expiry than the unconstrained reconstruction.
	want.ExpiresAt = a.ExpiresAt
	if a != want {
		return ErrInvalidAuthority
	}
	return nil
}

// BindControl checks only the frozen private control configuration and exact
// original effect. It cannot reconstruct or replace Provider PG truth.
func (a CodingCleanupAuthority) BindControl(create CodingCreateAuthority,
	plan codingidentity.Plan, controlPolicyDigest, authenticatedPeerDigest, expectedSpecDigest string,
	now time.Time) error {
	planDigest, err := plan.Digest()
	if err != nil || a.Validate(now) != nil ||
		create.BindControl(plan, controlPolicyDigest, authenticatedPeerDigest,
			expectedSpecDigest, create.IssuedAt) != nil ||
		a.OriginalAuthorityDigest != create.Digest() || a.EffectID != create.EffectID ||
		a.ProfileDigest != create.ProfileDigest || a.ControlPolicyDigest != create.ControlPolicyDigest ||
		a.PeerPrincipalDigest != authenticatedPeerDigest ||
		a.ProviderRevisionID != create.ProviderRevisionID || a.TenantDigest != create.TenantDigest ||
		a.AllocationID != create.AllocationID || a.SandboxID != create.SandboxID ||
		a.PlanDigest != planDigest || a.SlotID != create.SlotID ||
		a.BirthGeneration != create.CreationGeneration || a.BirthFence != create.Fence {
		return ErrInvalidAuthority
	}
	return nil
}

func (a CodingCleanupAuthority) Digest() string {
	document, err := EncodeCodingCleanupAuthority(a)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-cleanup-authority/v1\x00"), document...))
}

func EncodeCodingCleanupAuthority(a CodingCleanupAuthority) ([]byte, error) {
	document, err := json.Marshal(a)
	if err != nil || len(document) > MaxCleanupBytes {
		return nil, ErrInvalidAuthority
	}
	return document, nil
}

func DecodeCodingCleanupAuthority(document []byte, now time.Time) (CodingCleanupAuthority, error) {
	var authority CodingCleanupAuthority
	if len(document) == 0 || len(document) > MaxCleanupBytes ||
		json.Unmarshal(document, &authority) != nil || authority.Validate(now) != nil {
		return CodingCleanupAuthority{}, ErrInvalidAuthority
	}
	canonical, err := EncodeCodingCleanupAuthority(authority)
	if err != nil || !bytes.Equal(document, canonical) {
		return CodingCleanupAuthority{}, ErrInvalidAuthority
	}
	return authority, nil
}

func codingCleanupRequestID(a CodingCleanupAuthority) string {
	return digest([]byte("sandbox-runtime/docker-control-coding-cleanup-request/v1\x00" +
		a.OriginalAuthorityDigest + "\x00" + a.EffectID + "\x00" + a.ProfileDigest + "\x00" +
		a.ControlPolicyDigest + "\x00" + a.PeerPrincipalDigest + "\x00" +
		a.CleanupOperationID + "\x00" + a.CleanupAttemptID + "\x00" +
		a.CleanupRequestDigest + "\x00" +
		strconv.FormatUint(a.CurrentGeneration, 10) + "\x00" +
		strconv.FormatUint(a.CleanupFence, 10)))
}
