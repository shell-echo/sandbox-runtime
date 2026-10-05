// Package codingidentity defines an offline, finite coding-workload identity
// and whole-volume plan. It does not issue allocations, own business truth,
// provision Docker resources, or by itself authorize Provider v3 startup.
package codingidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
)

const (
	Protocol               = "sandbox-runtime.phase6-coding-identity-plan.v1"
	Version                = 1
	LocalCandidateCapacity = 2
	MaxCapacity            = 32
)

var (
	ErrInvalidPlan  = errors.New("invalid coding identity plan")
	ErrInvalidState = errors.New("invalid coding identity reservation state")
	ErrConflict     = errors.New("coding identity reservation conflict")
	ErrExhausted    = errors.New("coding identity slots exhausted")
	ErrInProgress   = errors.New("coding identity physical outcome unresolved")
	identifier      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	privateID       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	allocationID    = regexp.MustCompile(`^codingalloc-[0-9a-f]{64}$`)
	digest          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Slot reserves one high UID/GID and three *whole* generation-namespaced
// volumes. Inputs is mounted read-only; Workspace and Outputs are writable.
// These IDs are named-volume prefixes, never host paths or subdirectories.
type Slot struct {
	ID              string `json:"id"`
	WorkloadUID     uint32 `json:"workload_uid"`
	WorkloadGID     uint32 `json:"workload_gid"`
	InputsVolume    string `json:"inputs_volume"`
	WorkspaceVolume string `json:"workspace_volume"`
	OutputsVolume   string `json:"outputs_volume"`
}

func (s Slot) Validate() error {
	if !identifier.MatchString(s.ID) || s.WorkloadUID < 10000 || s.WorkloadUID > 60000 ||
		s.WorkloadGID < 10000 || s.WorkloadGID > 60000 ||
		s.InputsVolume != s.ID+"-inputs" || s.WorkspaceVolume != s.ID+"-workspace" ||
		s.OutputsVolume != s.ID+"-outputs" {
		return ErrInvalidPlan
	}
	return nil
}

type Limits struct {
	MemoryBytes int64 `json:"memory_bytes"`
	CPUMillis   int64 `json:"cpu_millis"`
	PIDs        int64 `json:"pids"`
}

func (l Limits) Validate() error {
	if l.MemoryBytes < 16<<20 || l.MemoryBytes > 64<<30 ||
		l.CPUMillis < 10 || l.CPUMillis > 64000 || l.PIDs < 4 || l.PIDs > 4096 {
		return ErrInvalidPlan
	}
	return nil
}

// Plan is a prospective v2 Profile projection, not a Browser/Desktop Plan.
// No gateway, SessionID, egress, agent or additional coding network exists.
type Plan struct {
	Protocol             string `json:"protocol"`
	Version              int    `json:"version"`
	ProfileDigest        string `json:"profile_digest"`
	OwnerDeployment      string `json:"owner_deployment"`
	OwnerPrincipalDigest string `json:"owner_principal_digest"`
	Namespace            string `json:"namespace"`
	ControllerID         string `json:"controller_id"`
	Template             string `json:"template"`
	TemplateDigest       string `json:"template_digest"`
	ImageDigest          string `json:"image_digest"`
	ImageConfigDigest    string `json:"image_config_digest"`
	NetworkMode          string `json:"network_mode"`
	Limits               Limits `json:"limits"`
	Capacity             int    `json:"capacity"`
	Slots                []Slot `json:"slots"`
}

func (p Plan) Validate() error {
	if p.Protocol != Protocol || p.Version != Version || !digest.MatchString(p.ProfileDigest) ||
		p.OwnerDeployment != "provider-runtime" || !digest.MatchString(p.OwnerPrincipalDigest) ||
		!identifier.MatchString(p.Namespace) || !identifier.MatchString(p.ControllerID) ||
		p.Template != "coding-sandbox-runtime" || !digest.MatchString(p.TemplateDigest) ||
		!digest.MatchString(p.ImageDigest) || !digest.MatchString(p.ImageConfigDigest) ||
		p.NetworkMode != "none" || p.Limits.Validate() != nil ||
		p.Capacity < 1 || p.Capacity > MaxCapacity || len(p.Slots) != p.Capacity {
		return ErrInvalidPlan
	}
	previous := ""
	uids, gids, volumes := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	for _, slot := range p.Slots {
		if slot.Validate() != nil || slot.ID <= previous || uids[slot.WorkloadUID] || gids[slot.WorkloadGID] {
			return ErrInvalidPlan
		}
		for _, volume := range []string{slot.InputsVolume, slot.WorkspaceVolume, slot.OutputsVolume} {
			if volumes[volume] {
				return ErrInvalidPlan
			}
			volumes[volume] = true
		}
		uids[slot.WorkloadUID], gids[slot.WorkloadGID] = true, true
		previous = slot.ID
	}
	return nil
}

// ValidateAgainst checks collisions with every static and Browser/Desktop
// identity. The caller must supply that complete v2 inventory; omitting it
// makes this only a local-plan check, not a full Profile admission.
func (p Plan) ValidateAgainst(usedUIDs, usedGIDs []uint32) error {
	if p.Validate() != nil || len(usedUIDs) == 0 || len(usedGIDs) == 0 {
		return ErrInvalidPlan
	}
	uids, gids := map[uint32]bool{}, map[uint32]bool{}
	for _, uid := range usedUIDs {
		if uids[uid] {
			return ErrInvalidPlan
		}
		uids[uid] = true
	}
	for _, gid := range usedGIDs {
		if gids[gid] {
			return ErrInvalidPlan
		}
		gids[gid] = true
	}
	for _, slot := range p.Slots {
		if uids[slot.WorkloadUID] || gids[slot.WorkloadGID] {
			return ErrInvalidPlan
		}
	}
	return nil
}

func (p Plan) ValidateLocalCandidate(usedUIDs, usedGIDs []uint32) error {
	if p.Capacity != LocalCandidateCapacity || p.ValidateAgainst(usedUIDs, usedGIDs) != nil {
		return ErrInvalidPlan
	}
	return nil
}

func (p Plan) Digest() (string, error) {
	if p.Validate() != nil {
		return "", ErrInvalidPlan
	}
	document, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalidPlan
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-coding-identity-plan/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// EffectiveVolumes derives plan-, allocation- and generation-scoped physical
// names. The slot must belong to this exact frozen plan. A later occupant or
// a different Profile revision cannot address prior volume names.
func (p Plan) EffectiveVolumes(slotID string, claim Claim) (inputs, workspace, outputs string, err error) {
	if p.Validate() != nil || claim.Validate() != nil {
		return "", "", "", ErrInvalidPlan
	}
	for _, slot := range p.Slots {
		if slot.ID != slotID {
			continue
		}
		scope := sha256.Sum256([]byte("sandbox-runtime/phase6-coding-volume-scope/v1\x00" + p.ProfileDigest + "\x00" +
			claim.AllocationID + "\x00" + strconv.FormatUint(claim.Generation, 10)))
		suffix := "-" + hex.EncodeToString(scope[:])
		return slot.InputsVolume + suffix, slot.WorkspaceVolume + suffix, slot.OutputsVolume + suffix, nil
	}
	return "", "", "", ErrInvalidPlan
}

// VolumeMount is a closed named-volume projection for the future restricted
// control protocol. There is no source/host path and no writable inputs mode.
type VolumeMount struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

func (p Plan) EffectiveMounts(slotID string, claim Claim) ([]VolumeMount, error) {
	inputs, workspace, outputs, err := p.EffectiveVolumes(slotID, claim)
	if err != nil {
		return nil, err
	}
	return []VolumeMount{
		{Name: inputs, Target: "/inputs", ReadOnly: true},
		{Name: workspace, Target: "/workspace"},
		{Name: outputs, Target: "/outputs"},
	}, nil
}

// DeriveAllocationID is a deterministic Provider-private name for the
// already-accepted create operation. All four fields must come from the same
// verified Provider PostgreSQL lifecycle state, never from caller input.
// Attempt, mutable fence/generation and rotating Profile are intentionally
// excluded: they are separate authorization and receipt bindings.
func DeriveAllocationID(providerRevisionID, tenantID, sandboxID, createOperationID string) (string, error) {
	for _, value := range []string{providerRevisionID, tenantID, sandboxID, createOperationID} {
		if !privateID.MatchString(value) {
			return "", ErrInvalidPlan
		}
	}
	identity := struct {
		ProviderRevisionID string `json:"provider_revision_id"`
		TenantID           string `json:"tenant_id"`
		SandboxID          string `json:"sandbox_id"`
		CreateOperationID  string `json:"create_operation_id"`
	}{providerRevisionID, tenantID, sandboxID, createOperationID}
	canonical, err := json.Marshal(identity)
	if err != nil {
		return "", ErrInvalidPlan
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/coding-allocation-id/v1\x00"), canonical...))
	return "codingalloc-" + hex.EncodeToString(sum[:]), nil
}

// TenantDigestForID reuses the scanner-private tenant digest domain. It is
// not a new Provider wire field or a replacement for existing tenant truth.
func TenantDigestForID(tenantID string) (string, error) {
	if !privateID.MatchString(tenantID) {
		return "", ErrInvalidPlan
	}
	sum := sha256.Sum256([]byte("tenant\x00" + tenantID))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Claim references an already accepted Provider lifecycle operation. It
// deliberately has no terminal SessionID and cannot select a slot or UID.
type Claim struct {
	TenantDigest  string `json:"tenant_digest"`
	SandboxID     string `json:"sandbox_id"`
	AllocationID  string `json:"allocation_id"`
	OperationID   string `json:"operation_id"`
	AttemptID     string `json:"attempt_id"`
	RequestDigest string `json:"request_digest"`
	Generation    uint64 `json:"generation"`
	Fence         uint64 `json:"fence"`
}

func (c Claim) Validate() error {
	if !digest.MatchString(c.TenantDigest) || !privateID.MatchString(c.SandboxID) ||
		!allocationID.MatchString(c.AllocationID) || !privateID.MatchString(c.OperationID) ||
		!privateID.MatchString(c.AttemptID) || !digest.MatchString(c.RequestDigest) ||
		c.Generation == 0 || c.Fence == 0 {
		return ErrInvalidPlan
	}
	return nil
}
