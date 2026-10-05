// Package dockercontrol defines the private, bounded Docker-control boundary.
// This first subprotocol covers Coding's one-time physical allocation intent;
// it is not a public Provider DTO or permission to activate a daemon service.
package dockercontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

const (
	CodingCreateProtocol = "sandbox-runtime.docker-control-coding-create.v1"
	CodingCreateAction   = "coding.allocate"
	MaxAuthorityBytes    = 4 << 10
	MaxAuthorityAge      = 30 * time.Second
)

var (
	ErrInvalidAuthority = errors.New("invalid private Docker-control authority")
	controlDigest       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	controlID           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	controlAllocationID = regexp.MustCompile(`^codingalloc-[0-9a-f]{64}$`)
)

// CodingCreateAuthority carries no image, host path, daemon/container ID,
// socket, arbitrary mount, network, privilege or credential. The control
// principal must independently bind the mTLS peer and exact Profile template
// before interpreting this as a candidate physical operation.
type CodingCreateAuthority struct {
	Protocol             string    `json:"protocol"`
	Action               string    `json:"action"`
	RequestID            string    `json:"request_id"`
	EffectID             string    `json:"effect_id"`
	ProfileDigest        string    `json:"profile_digest"`
	ControlPolicyDigest  string    `json:"control_policy_digest"`
	PeerDeployment       string    `json:"peer_deployment"`
	PeerPrincipalDigest  string    `json:"peer_principal_digest"`
	ProviderRevisionID   string    `json:"provider_revision_id"`
	TenantDigest         string    `json:"tenant_digest"`
	AllocationID         string    `json:"allocation_id"`
	SandboxID            string    `json:"sandbox_id"`
	OperationID          string    `json:"operation_id"`
	AttemptID            string    `json:"attempt_id"`
	RequestDigest        string    `json:"request_digest"`
	PlanDigest           string    `json:"plan_digest"`
	SpecDigest           string    `json:"spec_digest"`
	MappingDigest        string    `json:"mapping_digest"`
	SlotID               string    `json:"slot_id"`
	CreationGeneration   uint64    `json:"creation_generation"`
	AuthorizedGeneration uint64    `json:"authorized_generation"`
	Fence                uint64    `json:"fence"`
	OperationDeadline    time.Time `json:"operation_deadline"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// NewCodingCreateAuthority projects the ticket and Running Operation returned
// by the same Provider PG first-permit transaction. The operation, not the
// wire or an independent caller-supplied time, supplies the original deadline.
// This does not create a second signing key: exact mTLS peer verification
// remains mandatory at transport.
func NewCodingCreateAuthority(ctx context.Context, ticket codingidentity.Reservation,
	operation lifecycle.Operation, sandbox lifecycle.Sandbox, plan codingidentity.Plan,
	controlPolicyDigest, peerPrincipalDigest string, now time.Time) (CodingCreateAuthority, error) {
	planDigest, planErr := plan.Digest()
	mappingDigest, mappingErr := codingMappingDigest(plan, ticket)
	derivedAllocation, allocationErr := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID,
		sandbox.TenantID, sandbox.ID, operation.ID)
	if ctx == nil || ctx.Err() != nil || ticket.Status != codingidentity.Creating ||
		ticket.Claim.Validate() != nil || ticket.Slot.Validate() != nil ||
		operation.Validate() != nil || operation.Type != lifecycle.OperationCreate ||
		operation.State != lifecycle.OperationRunning || operation.CancelRequested || operation.Failure != nil ||
		operation.ID != ticket.Claim.OperationID || operation.AttemptID != ticket.Claim.AttemptID ||
		operation.SandboxID != ticket.Claim.SandboxID || operation.FencingToken != ticket.Claim.Fence ||
		(operation.RequestDigest != "" && operation.RequestDigest != ticket.Claim.RequestDigest) ||
		sandbox.Validate() != nil || sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
		sandbox.ID != ticket.Claim.SandboxID || sandbox.Generation != ticket.Claim.Generation ||
		allocationErr != nil || ticket.Claim.AllocationID != derivedAllocation ||
		planErr != nil || mappingErr != nil || planDigest != ticket.PlanDigest ||
		plan.OwnerPrincipalDigest != peerPrincipalDigest ||
		!operation.Deadline.After(now) ||
		!controlDigest.MatchString(controlPolicyDigest) || !controlDigest.MatchString(peerPrincipalDigest) {
		return CodingCreateAuthority{}, ErrInvalidAuthority
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil || tenantDigest != ticket.Claim.TenantDigest {
		return CodingCreateAuthority{}, ErrInvalidAuthority
	}
	expiry := now.UTC().Add(MaxAuthorityAge)
	if operation.Deadline.Before(expiry) {
		expiry = operation.Deadline.UTC()
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expiry) {
		expiry = deadline.UTC()
	}
	authority := CodingCreateAuthority{Protocol: CodingCreateProtocol, Action: CodingCreateAction,
		EffectID:      codingEffectID(ticket.Claim.AllocationID, ticket.Claim.Generation),
		ProfileDigest: plan.ProfileDigest, ControlPolicyDigest: controlPolicyDigest,
		PeerDeployment: "provider-runtime", PeerPrincipalDigest: peerPrincipalDigest,
		ProviderRevisionID: sandbox.ProviderRevisionID, TenantDigest: tenantDigest,
		AllocationID: ticket.Claim.AllocationID, SandboxID: sandbox.ID,
		OperationID: ticket.Claim.OperationID, AttemptID: ticket.Claim.AttemptID,
		RequestDigest: ticket.Claim.RequestDigest, PlanDigest: ticket.PlanDigest,
		SpecDigest: ticket.SpecDigest, MappingDigest: mappingDigest, SlotID: ticket.Slot.ID,
		CreationGeneration: ticket.Claim.Generation, AuthorizedGeneration: sandbox.Generation,
		Fence: ticket.Claim.Fence, OperationDeadline: operation.Deadline.UTC(),
		IssuedAt: now.UTC(), ExpiresAt: expiry}
	authority.RequestID = codingRequestID(authority)
	if authority.Validate(now) != nil {
		return CodingCreateAuthority{}, ErrInvalidAuthority
	}
	return authority, nil
}

func (a CodingCreateAuthority) Validate(now time.Time) error {
	if a.Protocol != CodingCreateProtocol || a.Action != CodingCreateAction ||
		!controlDigest.MatchString(a.RequestID) || !controlDigest.MatchString(a.EffectID) ||
		!controlDigest.MatchString(a.ProfileDigest) ||
		!controlDigest.MatchString(a.ControlPolicyDigest) || a.PeerDeployment != "provider-runtime" ||
		!controlDigest.MatchString(a.PeerPrincipalDigest) || !controlID.MatchString(a.ProviderRevisionID) ||
		!controlDigest.MatchString(a.TenantDigest) || !controlAllocationID.MatchString(a.AllocationID) ||
		!controlID.MatchString(a.SandboxID) || !controlID.MatchString(a.OperationID) ||
		!controlID.MatchString(a.AttemptID) || !controlDigest.MatchString(a.RequestDigest) ||
		!controlDigest.MatchString(a.PlanDigest) || !controlDigest.MatchString(a.SpecDigest) ||
		!controlDigest.MatchString(a.MappingDigest) || !controlID.MatchString(a.SlotID) ||
		a.CreationGeneration == 0 || a.AuthorizedGeneration != a.CreationGeneration || a.Fence == 0 ||
		a.EffectID != codingEffectID(a.AllocationID, a.CreationGeneration) ||
		a.RequestID != codingRequestID(a) ||
		!a.OperationDeadline.After(a.IssuedAt) || a.ExpiresAt.After(a.OperationDeadline) ||
		a.IssuedAt.IsZero() || a.IssuedAt.After(now) || !a.ExpiresAt.After(now) ||
		!a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.After(a.IssuedAt.Add(MaxAuthorityAge)) {
		return ErrInvalidAuthority
	}
	return nil
}

// BindProvider independently checks the same-transaction Provider Operation,
// ticket, Profile and authenticated peer before serialization. The Control
// process cannot read Provider PG and instead performs BindControl below.
func (a CodingCreateAuthority) BindProvider(ticket codingidentity.Reservation, operation lifecycle.Operation,
	sandbox lifecycle.Sandbox, plan codingidentity.Plan, controlPolicyDigest, authenticatedPeerDigest string,
	now time.Time) error {
	want, err := NewCodingCreateAuthority(context.Background(), ticket, operation, sandbox, plan,
		controlPolicyDigest, authenticatedPeerDigest, a.IssuedAt)
	if err != nil || a.Validate(now) != nil || a.RequestID != want.RequestID ||
		a.EffectID != want.EffectID ||
		!a.OperationDeadline.Equal(operation.Deadline) ||
		a.ProfileDigest != want.ProfileDigest || a.ControlPolicyDigest != want.ControlPolicyDigest ||
		a.PeerPrincipalDigest != want.PeerPrincipalDigest || a.ProviderRevisionID != want.ProviderRevisionID ||
		a.TenantDigest != want.TenantDigest || a.AllocationID != want.AllocationID ||
		a.SandboxID != want.SandboxID || a.OperationID != want.OperationID ||
		a.AttemptID != want.AttemptID || a.RequestDigest != want.RequestDigest ||
		a.PlanDigest != want.PlanDigest || a.SpecDigest != want.SpecDigest ||
		a.MappingDigest != want.MappingDigest || a.SlotID != want.SlotID ||
		a.CreationGeneration != want.CreationGeneration ||
		a.AuthorizedGeneration != want.AuthorizedGeneration || a.Fence != want.Fence {
		return ErrInvalidAuthority
	}
	return nil
}

// BindControl checks only the independently configured exact plan/policy and
// authenticated peer. It does not pretend to reconstruct Provider PG truth.
func (a CodingCreateAuthority) BindControl(plan codingidentity.Plan,
	controlPolicyDigest, authenticatedPeerDigest, expectedSpecDigest string, now time.Time) error {
	planDigest, err := plan.Digest()
	if err != nil || a.Validate(now) != nil || planDigest != a.PlanDigest ||
		plan.ProfileDigest != a.ProfileDigest || plan.OwnerPrincipalDigest != authenticatedPeerDigest ||
		a.PeerPrincipalDigest != authenticatedPeerDigest || a.ControlPolicyDigest != controlPolicyDigest ||
		!controlDigest.MatchString(expectedSpecDigest) || a.SpecDigest != expectedSpecDigest {
		return ErrInvalidAuthority
	}
	var selected codingidentity.Slot
	for _, slot := range plan.Slots {
		if slot.ID == a.SlotID {
			selected = slot
			break
		}
	}
	claim := codingidentity.Claim{TenantDigest: a.TenantDigest, SandboxID: a.SandboxID,
		AllocationID: a.AllocationID, OperationID: a.OperationID, AttemptID: a.AttemptID,
		RequestDigest: a.RequestDigest, Generation: a.CreationGeneration, Fence: a.Fence}
	ticket := codingidentity.Reservation{PlanDigest: a.PlanDigest, Slot: selected, Claim: claim,
		SpecDigest: a.SpecDigest, Status: codingidentity.Creating}
	mappingDigest, err := codingMappingDigest(plan, ticket)
	if err != nil || mappingDigest != a.MappingDigest {
		return ErrInvalidAuthority
	}
	return nil
}

func (a CodingCreateAuthority) Digest() string {
	document, err := EncodeCodingCreateAuthority(a)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-create-authority/v1\x00"), document...))
}

func EncodeCodingCreateAuthority(a CodingCreateAuthority) ([]byte, error) {
	document, err := json.Marshal(a)
	if err != nil || len(document) > MaxAuthorityBytes {
		return nil, ErrInvalidAuthority
	}
	return document, nil
}

func DecodeCodingCreateAuthority(document []byte, now time.Time) (CodingCreateAuthority, error) {
	var authority CodingCreateAuthority
	if len(document) == 0 || len(document) > MaxAuthorityBytes ||
		json.Unmarshal(document, &authority) != nil || authority.Validate(now) != nil {
		return CodingCreateAuthority{}, ErrInvalidAuthority
	}
	canonical, err := EncodeCodingCreateAuthority(authority)
	if err != nil || !bytes.Equal(document, canonical) {
		return CodingCreateAuthority{}, ErrInvalidAuthority
	}
	return authority, nil
}

func codingEffectID(allocationID string, creationGeneration uint64) string {
	return digest([]byte("sandbox-runtime/docker-control-coding-create-effect/v1\x00" +
		allocationID + "\x00" + strconv.FormatUint(creationGeneration, 10)))
}

// The request replay key can change with a new attempt, fence or policy. The
// physical effect key above cannot: it is tied only to the allocation and
// original creation generation, and remains a tombstone after release.
func codingRequestID(a CodingCreateAuthority) string {
	return digest([]byte("sandbox-runtime/docker-control-coding-request/v1\x00" +
		a.PeerPrincipalDigest + "\x00" + a.AllocationID + "\x00" +
		strconv.FormatUint(a.CreationGeneration, 10) + "\x00" + a.OperationID + "\x00" +
		a.AttemptID + "\x00" + a.RequestDigest + "\x00" +
		strconv.FormatUint(a.Fence, 10) + "\x00" + a.ProfileDigest + "\x00" +
		a.ControlPolicyDigest + "\x00" + a.PlanDigest + "\x00" +
		a.SpecDigest + "\x00" + a.MappingDigest + "\x00" + a.SlotID))
}

func codingMappingDigest(plan codingidentity.Plan, ticket codingidentity.Reservation) (string, error) {
	if plan.Validate() != nil || ticket.Claim.Validate() != nil || ticket.Slot.Validate() != nil {
		return "", ErrInvalidAuthority
	}
	found := false
	for _, slot := range plan.Slots {
		if slot.ID == ticket.Slot.ID {
			found = slot == ticket.Slot
			break
		}
	}
	if !found {
		return "", ErrInvalidAuthority
	}
	mounts, err := plan.EffectiveMounts(ticket.Slot.ID, ticket.Claim)
	if err != nil || len(mounts) != 3 {
		return "", ErrInvalidAuthority
	}
	projection := struct {
		PlanDigest string                       `json:"plan_digest"`
		Slot       codingidentity.Slot          `json:"slot"`
		Mounts     []codingidentity.VolumeMount `json:"mounts"`
	}{ticket.PlanDigest, ticket.Slot, mounts}
	document, err := json.Marshal(projection)
	if err != nil {
		return "", ErrInvalidAuthority
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-mapping/v1\x00"), document...)), nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
