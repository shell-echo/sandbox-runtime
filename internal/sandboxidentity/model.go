// Package sandboxidentity defines Provider-private, per-owner finite identity
// reservations. A trusted deployment profile is projected to Plan before a
// runtime driver sees it; neither callers nor allocation requests choose UIDs.
package sandboxidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	MaxSlots = 1000
	Version  = 1
)

var (
	ErrInvalidPlan   = errors.New("invalid sandbox identity plan")
	ErrInvalidState  = errors.New("invalid sandbox identity state")
	ErrConflict      = errors.New("sandbox identity reservation conflict")
	ErrExhausted     = errors.New("sandbox identity slots exhausted")
	ErrUninitialized = errors.New("sandbox identity authority is not initialized")
	ErrInProgress    = errors.New("sandbox identity operation outcome is unresolved")
	privateID        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	databaseID       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	digest           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Slot is the effective workload/gateway identity pair for one allocation.
// Complete-deployment collision checks, including static principals and the
// other Provider's pool, are performed before projecting this owner-local plan.
type Slot struct {
	ID          string `json:"id"`
	WorkloadUID uint32 `json:"workload_uid"`
	WorkloadGID uint32 `json:"workload_gid"`
	GatewayUID  uint32 `json:"gateway_uid"`
	GatewayGID  uint32 `json:"gateway_gid"`
}

// Validate checks the shape of one slot. Membership and cross-slot
// distinctness remain properties of the complete trusted Plan.
func (s Slot) Validate() error {
	if !privateID.MatchString(s.ID) || !validID(s.WorkloadUID) || !validID(s.WorkloadGID) ||
		!validID(s.GatewayUID) || !validID(s.GatewayGID) ||
		s.WorkloadUID == s.GatewayUID || s.WorkloadGID == s.GatewayGID {
		return ErrInvalidPlan
	}
	return nil
}

type Plan struct {
	ProfileDigest         string `json:"profile_digest"`
	OwnerDeployment       string `json:"owner_deployment"`
	OwnerPrincipalDigest  string `json:"owner_principal_digest"`
	Namespace             string `json:"namespace"`
	ServiceName           string `json:"service_name"`
	ServiceIdentityDigest string `json:"service_identity_digest"`
	TrustEdgeID           string `json:"trust_edge_id"`
	EgressPolicyID        string `json:"egress_policy_id"`
	BrokerDeployment      string `json:"broker_deployment"`
	BrokerRoleEdgeID      string `json:"broker_role_edge_id"`
	BrokerExternalEdgeID  string `json:"broker_external_edge_id"`
	MaterialBindingID     string `json:"material_binding_id"`
	DatabaseName          string `json:"database_name"`
	RuntimeRole           string `json:"runtime_role"`
	ControllerID          string `json:"controller_id"`
	Template              string `json:"template"`
	TemplateDigest        string `json:"template_digest"`
	Capacity              int    `json:"capacity"`
	Slots                 []Slot `json:"slots"`
}

// RuntimeAuthority is the minimal trusted projection handed to a slot-aware
// Docker driver. Database names, roles, material references and deployment
// topology stay with the Provider application coordinator.
type RuntimeAuthority struct {
	PlanDigest      string `json:"plan_digest"`
	OwnerDeployment string `json:"owner_deployment"`
	Namespace       string `json:"namespace"`
	ControllerID    string `json:"controller_id"`
	Template        string `json:"template"`
	Capacity        int    `json:"capacity"`
	Slots           []Slot `json:"slots"`
}

func (p Plan) ProjectRuntimeAuthority() (RuntimeAuthority, error) {
	planDigest, err := p.Digest()
	if err != nil {
		return RuntimeAuthority{}, err
	}
	return RuntimeAuthority{PlanDigest: planDigest, OwnerDeployment: p.OwnerDeployment,
		Namespace: p.Namespace, ControllerID: p.ControllerID, Template: p.Template,
		Capacity: p.Capacity, Slots: slices.Clone(p.Slots)}, nil
}

func (a RuntimeAuthority) Validate() error {
	owner := ""
	switch a.Template {
	case "browser-sandbox-runtime":
		owner = "provider-browser-runtime"
	case "desktop-sandbox-runtime":
		owner = "provider-desktop-runtime"
	}
	if owner == "" || a.OwnerDeployment != owner || !digest.MatchString(a.PlanDigest) ||
		!privateID.MatchString(a.Namespace) || !privateID.MatchString(a.ControllerID) ||
		a.Capacity < 1 || len(a.Slots) < a.Capacity || len(a.Slots) > MaxSlots {
		return ErrInvalidPlan
	}
	previous := ""
	uids := make(map[uint32]struct{}, len(a.Slots)*2)
	gids := make(map[uint32]struct{}, len(a.Slots)*2)
	for _, slot := range a.Slots {
		if slot.Validate() != nil || slot.ID <= previous {
			return ErrInvalidPlan
		}
		for _, uid := range []uint32{slot.WorkloadUID, slot.GatewayUID} {
			if _, exists := uids[uid]; exists {
				return ErrInvalidPlan
			}
			uids[uid] = struct{}{}
		}
		for _, gid := range []uint32{slot.WorkloadGID, slot.GatewayGID} {
			if _, exists := gids[gid]; exists {
				return ErrInvalidPlan
			}
			gids[gid] = struct{}{}
		}
		previous = slot.ID
	}
	return nil
}

func (p Plan) Validate() error {
	owner := ""
	switch p.Template {
	case "browser-sandbox-runtime":
		owner = "provider-browser-runtime"
	case "desktop-sandbox-runtime":
		owner = "provider-desktop-runtime"
	}
	if owner == "" || p.OwnerDeployment != owner || !digest.MatchString(p.ProfileDigest) ||
		!digest.MatchString(p.OwnerPrincipalDigest) || !digest.MatchString(p.TemplateDigest) ||
		!digest.MatchString(p.ServiceIdentityDigest) || !privateID.MatchString(p.Namespace) ||
		!privateID.MatchString(p.ServiceName) || !privateID.MatchString(p.TrustEdgeID) ||
		!privateID.MatchString(p.EgressPolicyID) || !privateID.MatchString(p.BrokerDeployment) ||
		!privateID.MatchString(p.BrokerRoleEdgeID) || !privateID.MatchString(p.BrokerExternalEdgeID) ||
		!privateID.MatchString(p.MaterialBindingID) ||
		!databaseID.MatchString(p.DatabaseName) || !databaseID.MatchString(p.RuntimeRole) ||
		!privateID.MatchString(p.ControllerID) || len(p.Slots) < 1 || len(p.Slots) > MaxSlots {
		return ErrInvalidPlan
	}
	if p.Capacity < 1 || p.Capacity > len(p.Slots) {
		return ErrInvalidPlan
	}
	previous := ""
	uids := make(map[uint32]struct{}, len(p.Slots)*2)
	gids := make(map[uint32]struct{}, len(p.Slots)*2)
	for _, slot := range p.Slots {
		if slot.Validate() != nil || slot.ID <= previous {
			return ErrInvalidPlan
		}
		for _, uid := range []uint32{slot.WorkloadUID, slot.GatewayUID} {
			if _, exists := uids[uid]; exists {
				return ErrInvalidPlan
			}
			uids[uid] = struct{}{}
		}
		for _, gid := range []uint32{slot.WorkloadGID, slot.GatewayGID} {
			if _, exists := gids[gid]; exists {
				return ErrInvalidPlan
			}
			gids[gid] = struct{}{}
		}
		previous = slot.ID
	}
	return nil
}

func validID(id uint32) bool { return id >= 10000 && id <= 60000 }

func (p Plan) Digest() (string, error) {
	if p.Validate() != nil {
		return "", ErrInvalidPlan
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalidPlan
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-sandbox-identity-plan/v1\x00"), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Claim binds an allocation to the trusted owner/controller in Plan. Neither
// field is accepted from this claim, so a request cannot self-select a pool.
type Claim struct {
	SandboxID     string `json:"sandbox_id"`
	SessionID     string `json:"session_id"`
	OperationID   string `json:"operation_id"`
	AttemptID     string `json:"attempt_id"`
	RequestDigest string `json:"request_digest"`
	Generation    int64  `json:"generation"`
	Fence         int64  `json:"fence"`
}

func (c Claim) Validate() error {
	if !privateID.MatchString(c.SandboxID) || !privateID.MatchString(c.SessionID) ||
		!privateID.MatchString(c.OperationID) || !privateID.MatchString(c.AttemptID) ||
		!digest.MatchString(c.RequestDigest) || c.Generation < 1 || c.Fence < 1 {
		return ErrInvalidPlan
	}
	return nil
}

type Status string

const (
	Reserved Status = "reserved"
	Creating Status = "creating"
	Active   Status = "active"
	Cleaning Status = "cleaning"
)

type Reservation struct {
	PlanDigest string `json:"plan_digest"`
	Slot       Slot   `json:"slot"`
	Claim      Claim  `json:"claim"`
	SpecDigest string `json:"spec_digest"`
	Status     Status `json:"status"`
}

func (r Reservation) SameIdentity(other Reservation) bool {
	return r.PlanDigest == other.PlanDigest && r.Slot == other.Slot &&
		r.Claim == other.Claim && r.SpecDigest == other.SpecDigest
}
