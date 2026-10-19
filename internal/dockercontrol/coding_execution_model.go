package dockercontrol

import (
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

// v3 binds the reviewed unsigned Coding candidate and a recheckable physical
// projection. Neither held v1 nor old-image v2 states have a migration path.
const executionReceiptProtocol = "sandbox-runtime.coding-isolated-receipts.v3"

// All types in this file are held Control-internal types, not Provider DTOs or
// a transport authenticator. No current command or public Profile admits them.
// A new source-bound physical observer and PG/mTLS producer remain required.
type executionBinding struct {
	Storage                 controlstorage.Binding                          `json:"storage"`
	Template                phase6security.CodingCandidateExecutionTemplate `json:"template"`
	DaemonDigest            string                                          `json:"daemon_digest"`
	DaemonEnvironmentDigest string                                          `json:"daemon_environment_digest"`
	EndpointScopeDigest     string                                          `json:"endpoint_scope_digest"`
	ControlPolicyDigest     string                                          `json:"control_policy_digest"`
}

func (b executionBinding) validate() error {
	d, err := b.Template.Digest()
	if err != nil || b.Storage.Validate() != nil || b.Storage.TemplateDigest != d || b.Storage.Layout != b.Template.ControlStorage {
		return ErrInvalidReceiptState
	}
	for _, v := range []string{b.DaemonDigest, b.DaemonEnvironmentDigest, b.EndpointScopeDigest, b.ControlPolicyDigest} {
		if !controlDigest.MatchString(v) {
			return ErrInvalidReceiptState
		}
	}
	return nil
}
func executionDigest(domain string, v any) string {
	d, _ := json.Marshal(v)
	return digest(append([]byte(executionReceiptProtocol+"/"+domain+"\x00"), d...))
}
func (b executionBinding) digest() string { return executionDigest("binding", b) }
func (b executionBinding) clone() executionBinding {
	d, _ := json.Marshal(b)
	var out executionBinding
	_ = json.Unmarshal(d, &out)
	return out
}

type executionCreate struct {
	Protocol           string    `json:"protocol"`
	BindingDigest      string    `json:"binding_digest"`
	AllocationID       string    `json:"allocation_id"`
	SlotID             string    `json:"slot_id"`
	SandboxID          string    `json:"sandbox_id"`
	ProviderRevisionID string    `json:"provider_revision_id"`
	TenantDigest       string    `json:"tenant_digest"`
	OperationID        string    `json:"operation_id"`
	AttemptID          string    `json:"attempt_id"`
	RequestDigest      string    `json:"request_digest"`
	Generation         uint64    `json:"generation"`
	Fence              uint64    `json:"fence"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	OperationDeadline  time.Time `json:"operation_deadline"`
}

func (a executionCreate) digest() string { return executionDigest("create", a) }
func (a executionCreate) validate(b executionBinding, now time.Time) error {
	if b.validate() != nil || a.Protocol != executionReceiptProtocol || a.BindingDigest != b.digest() ||
		!controlAllocationID.MatchString(a.AllocationID) || !controlDigest.MatchString(a.TenantDigest) ||
		!controlDigest.MatchString(a.RequestDigest) || a.Generation == 0 || a.Generation > 1<<63-1 || a.Fence == 0 || a.Fence > 1<<63-1 ||
		!executionWindow(a.IssuedAt, a.ExpiresAt, now) || !a.OperationDeadline.After(a.IssuedAt) || a.ExpiresAt.After(a.OperationDeadline) {
		return ErrInvalidAuthority
	}
	for _, v := range []string{a.SandboxID, a.ProviderRevisionID, a.OperationID, a.AttemptID} {
		if !controlID.MatchString(v) {
			return ErrInvalidAuthority
		}
	}
	for _, slot := range b.Template.Slots {
		if slot.Data.ID == a.SlotID {
			return nil
		}
	}
	return ErrInvalidAuthority
}
func executionWindow(issued, expires, now time.Time) bool {
	return !now.IsZero() && !issued.IsZero() && !issued.After(now) && expires.After(now) && !expires.After(issued.Add(MaxAuthorityAge)) && issued.Location() == time.UTC && expires.Location() == time.UTC
}

// No caller supplies physical resource names. All four names and both static
// containers bind the fresh namespace, complete template and allocation tuple.
type executionResources struct {
	Preparation       string    `json:"preparation"`
	Resident          string    `json:"resident"`
	Volumes           [4]string `json:"volumes"`
	UID               uint32    `json:"uid"`
	GID               uint32    `json:"gid"`
	ImageConfigDigest string    `json:"image_config_digest"`
}

func (a executionCreate) resources(b executionBinding) executionResources {
	var slot codingidentity.Slot
	for _, s := range b.Template.Slots {
		if s.Data.ID == a.SlotID {
			slot = s.Data
		}
	}
	name := "cex-" + executionDigest("resources", struct {
		Binding, Allocation, Slot string
		Generation                uint64
	}{b.digest(), a.AllocationID, a.SlotID, a.Generation})[7:47]
	return executionResources{Preparation: name + "-prepare", Resident: name + "-resident",
		Volumes: [4]string{name + "-inputs", name + "-workspace", name + "-outputs", name + "-scratch"},
		UID:     slot.WorkloadUID, GID: slot.WorkloadGID, ImageConfigDigest: b.Template.Image.ConfigDigest}
}

type executionClaim struct {
	Protocol           string               `json:"protocol"`
	BindingDigest      string               `json:"binding_digest"`
	CreateDigest       string               `json:"create_digest"`
	CompletionDigest   string               `json:"completion_digest"`
	TenantDigest       string               `json:"tenant_digest"`
	ProviderRevisionID string               `json:"provider_revision_id"`
	Request            providerexec.Request `json:"request"`
	AcceptedAt         time.Time            `json:"accepted_at"`
	ExpiresAt          time.Time            `json:"expires_at"`
}

func (c executionClaim) digest() string        { return executionDigest("claim", c) }
func (c executionClaim) clone() executionClaim { c.Request = c.Request.Clone(); return c }
func (c executionClaim) validate(b executionBinding, a executionCreate, now time.Time) error {
	r := c.Request
	if c.Protocol != executionReceiptProtocol || c.BindingDigest != b.digest() || c.CreateDigest != a.digest() ||
		!controlDigest.MatchString(c.CompletionDigest) || c.TenantDigest != a.TenantDigest || c.ProviderRevisionID != a.ProviderRevisionID ||
		a.validate(b, a.IssuedAt) != nil || r.Validate(c.AcceptedAt) != nil ||
		!executionWindow(c.AcceptedAt, c.ExpiresAt, now) || c.AcceptedAt.Before(a.IssuedAt) || c.ExpiresAt.After(r.Deadline) ||
		r.SandboxID != a.SandboxID || uint64(r.ExpectedGeneration) != a.Generation || uint64(r.FencingToken) < a.Fence ||
		len(r.Environment) != 0 || len(r.SecretReferenceIDs) != 0 || r.SecretGrantID != "" || r.SecretGrantDigest != "" || r.StdinReference != "" {
		return ErrInvalidAuthority
	}
	_, err := c.charge(b)
	return err
}
func (c executionClaim) charge(b executionBinding) (codingidentity.ExecutionStorageCharge, error) {
	d, err := json.Marshal(c.Request)
	if err != nil {
		return codingidentity.ExecutionStorageCharge{}, ErrInvalidAuthority
	}
	return b.Template.Storage.Charge(codingidentity.CaptureBudget{Stdout: c.Request.CaptureStdout, Stderr: c.Request.CaptureStderr, MaxBytes: c.Request.CaptureMaxBytes, RequestBytes: int64(len(d))})
}

// This is an internal observation envelope. No exported constructor, decoded
// caller success flag or old three-volume observation may manufacture one.
// Only the bounded source observer produces physical evidence. Test fixtures
// remain synthetic; complete Profile and physical namespace admission are held.
type executionCompletionObservation struct {
	Protocol                string                 `json:"protocol"`
	BindingDigest           string                 `json:"binding_digest"`
	CreateDigest            string                 `json:"create_digest"`
	Resources               executionResources     `json:"resources"`
	ResidentID              string                 `json:"resident_id"`
	ObservedAt              time.Time              `json:"observed_at"`
	SourceRevision          uint64                 `json:"source_revision"`
	SourceStateDigest       string                 `json:"source_state_digest"`
	ImageEvidenceDigest     string                 `json:"image_evidence_digest"`
	InventoryEvidenceDigest string                 `json:"inventory_evidence_digest"`
	RootEvidenceDigests     [4]string              `json:"root_evidence_digests"`
	Physical                executionPhysicalProof `json:"physical"`
}

func (o executionCompletionObservation) digest() string { return executionDigest("completion", o) }
func (o executionCompletionObservation) validate(b executionBinding, a executionCreate, now time.Time) error {
	if o.Protocol != executionReceiptProtocol || o.BindingDigest != b.digest() || o.CreateDigest != a.digest() ||
		o.Resources != a.resources(b) || !codingArchiveRuntimeID.MatchString(o.ResidentID) || o.ObservedAt.Before(a.IssuedAt) ||
		o.ObservedAt.After(now) || !o.ObservedAt.Before(a.ExpiresAt) || o.SourceRevision == 0 {
		return ErrInvalidReceiptState
	}
	for _, d := range append([]string{o.SourceStateDigest, o.ImageEvidenceDigest, o.InventoryEvidenceDigest}, o.RootEvidenceDigests[:]...) {
		if !controlDigest.MatchString(d) {
			return ErrInvalidReceiptState
		}
	}
	return o.Physical.recheck(b, a, o)
}
