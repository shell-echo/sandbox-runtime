package phase6security

import (
	"reflect"
	"regexp"

	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

const CodingExecutionProfileProtocol = "sandbox-runtime.phase6-coding-execution-profile.v3"
const CodingReceiptNamespaceProtocol = "sandbox-runtime.phase6-coding-receipt-namespace.v1"

var codingNamespaceID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// CodingExecutionProfileV3 is an explicit alternative within the held complete
// Profile v2. It cannot coexist with the historical three-volume template or
// resource budget. It grants no launch or physical storage authority.
type CodingExecutionProfileV3 struct {
	Protocol string                           `json:"protocol"`
	Template CodingCandidateExecutionTemplate `json:"template"`
	Receipt  CodingReceiptNamespaceV3         `json:"receipt"`
	Budget   CodingExecutionProfileBudget     `json:"budget"`
}

// The namespace is part of the Profile preimage. The derived Binding carries
// the final Profile digest; putting it here instead would create a digest cycle.
// The physical mode is a REQUIRED gate, not a caller assertion of observed facts.
type CodingReceiptNamespaceV3 struct {
	Protocol     string `json:"protocol"`
	Namespace    string `json:"namespace"`
	StorageID    string `json:"storage_id"`
	Target       string `json:"target"`
	PhysicalMode string `json:"physical_mode"`
	MaxBytes     int64  `json:"max_bytes"`
	OtherScopes  string `json:"other_scopes"`
}

func NewCodingReceiptNamespaceV3(namespace string) (CodingReceiptNamespaceV3, error) {
	if !codingNamespaceID.MatchString(namespace) {
		return CodingReceiptNamespaceV3{}, ErrInvalidProfile
	}
	return CodingReceiptNamespaceV3{Protocol: CodingReceiptNamespaceProtocol, Namespace: namespace,
		StorageID: "control-execution-" + namespace, Target: v2ReceiptTarget,
		PhysicalMode: "dedicated-persistent-filesystem-and-exclusive-control-required",
		MaxBytes:     v2ReceiptMaxBytes, OtherScopes: "unallocated-no-writer"}, nil
}

func (r CodingReceiptNamespaceV3) validate() error {
	want, err := NewCodingReceiptNamespaceV3(r.Namespace)
	if err != nil || r != want {
		return ErrInvalidProfile
	}
	return nil
}

func (p ProfileV2) verifyCodingMode() error {
	if p.CodingExecution == nil {
		return VerifySlice6V2CodingSlots(p.CodingTemplate, p.Principals, p.SandboxIdentitySlots)
	}
	x := p.CodingExecution
	if x.Protocol != CodingExecutionProfileProtocol || !reflect.DeepEqual(p.CodingTemplate, CodingRuntimeTemplateV2{}) ||
		p.ResourceBudget != (Slice6V2ResourceBudget{}) || x.Receipt.validate() != nil ||
		VerifyCodingExecutionProfileSlots(x.Template, p.Principals, p.SandboxIdentitySlots) != nil ||
		p.DockerControl.ReceiptStorageID != x.Receipt.StorageID || p.DockerControl.ReceiptTarget != x.Receipt.Target ||
		p.DockerControl.ReceiptMaxBytes != x.Receipt.MaxBytes {
		return ErrInvalidProfile
	}
	// Exactly one whole mount belongs to Control. Aliases, descendants and other
	// principals cannot borrow this volume, even read-only.
	count := 0
	for _, principal := range p.Principals {
		if principal.Name == "provider-docker-control" && principal.ImagePlatform != x.Template.Image.Platform {
			return ErrInvalidProfile
		}
		for _, mount := range principal.Mounts {
			if mount.StorageID != x.Receipt.StorageID {
				continue
			}
			if principal.Name != "provider-docker-control" || mount.Target != x.Receipt.Target ||
				mount.Kind != "persistent_ledger" || mount.ReadOnly || mount.MaxBytes != x.Receipt.MaxBytes || mount.PrivateFiles != "" {
				return ErrInvalidProfile
			}
			count++
		}
	}
	if count != 1 {
		return ErrInvalidProfile
	}
	return nil
}

func (p ProfileV2) verifyCodingResourceBudget() error {
	if p.CodingExecution == nil {
		budget, err := CalculateSlice6V2ResourceBudget(p.Principals, p.SandboxIdentitySlots, p.CodingTemplate, p.SandboxGatewayLimits, p.ExternalResourceLimits)
		if err != nil || budget != p.ResourceBudget {
			return ErrInvalidProfile
		}
		return nil
	}
	budget, err := CalculateCodingExecutionProfileBudget(p.Principals, p.SandboxIdentitySlots, p.CodingExecution.Template, p.SandboxGatewayLimits, p.ExternalResourceLimits)
	if err != nil || budget != p.CodingExecution.Budget {
		return ErrInvalidProfile
	}
	return nil
}

// CodingExecutionStorageBinding requires PUBLIC admission, which remains closed.
// In particular, a digest that merely looks valid never reaches a Store opener.
func (p ProfileV2) CodingExecutionStorageBinding() (controlstorage.Binding, error) {
	if p.Validate() != nil {
		return controlstorage.Binding{}, ErrInvalidProfile
	}
	return p.codingExecutionStorageBindingFields()
}

// The full field chain is deliberately checked, rather than trusting that a
// caller previously checked a template, digest or partial inventory. This pure
// path is exercised by complete synthetic Profile tests, not a launch bypass.
func (p ProfileV2) codingExecutionStorageBindingFields() (controlstorage.Binding, error) {
	if p.CodingExecution == nil || p.validateFields() != nil {
		return controlstorage.Binding{}, ErrInvalidProfile
	}
	x := p.CodingExecution
	d, err := x.Template.Digest()
	if err != nil {
		return controlstorage.Binding{}, ErrInvalidProfile
	}
	var control Principal
	for _, principal := range p.Principals {
		if principal.Name == "provider-docker-control" {
			control = principal
		}
	}
	b := controlstorage.Binding{Layout: x.Template.ControlStorage, Namespace: x.Receipt.Namespace, StorageID: x.Receipt.StorageID,
		ProfileDigest: p.ProfileDigest, TemplateDigest: d, ControlPrincipalDigest: control.PrincipalDigest, UID: control.UID, GID: control.GID}
	if b.Validate() != nil {
		return controlstorage.Binding{}, ErrInvalidProfile
	}
	return b, nil
}

// VerifyCodingExecutionProfileSlots checks all DECLARED static and dynamic
// identities, plus all four per-slot volume prefixes. It is not live inventory.
func VerifyCodingExecutionProfileSlots(t CodingCandidateExecutionTemplate, principals []Principal, slots []SandboxIdentitySlot) error {
	if t.Validate() != nil || len(principals) != len(slice6ApprovedDeploymentKinds)+len(slice6V2IdentityDelta) {
		return ErrInvalidProfile
	}
	byName := map[string]Principal{}
	uids, gids, storage := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	for _, p := range principals {
		if _, ok := byName[p.Name]; ok || uids[p.UID] || gids[p.GID] {
			return ErrInvalidProfile
		}
		if _, added := slice6V2IdentityDelta[p.Name]; !added {
			if kind, ok := slice6ApprovedDeploymentKinds[p.Name]; !ok || p.Kind != kind {
				return ErrInvalidProfile
			}
		}
		byName[p.Name] = p
		uids[p.UID] = true
		gids[p.GID] = true
		for _, m := range p.Mounts {
			if m.StorageID != "" {
				storage[m.StorageID] = true
			}
		}
	}
	for name := range slice6V2IdentityDelta {
		if _, ok := byName[name]; !ok {
			return ErrInvalidProfile
		}
	}
	owner := byName[t.OwnerDeployment]
	if t.OwnerDeployment != "provider-runtime" || owner.Kind != "runtime" || owner.PrincipalDigest != t.OwnerPrincipalDigest || validateSandboxIdentitySlots(slots, byName) != nil {
		return ErrInvalidProfile
	}
	if owner.ImagePlatform != t.Image.Platform {
		return ErrInvalidProfile
	}
	for _, s := range slots {
		uids[s.WorkloadUID] = true
		uids[s.GatewayUID] = true
		gids[s.WorkloadGID] = true
		gids[s.GatewayGID] = true
	}
	for _, s := range t.Slots {
		if uids[s.Data.WorkloadUID] || gids[s.Data.WorkloadGID] {
			return ErrInvalidProfile
		}
		uids[s.Data.WorkloadUID] = true
		gids[s.Data.WorkloadGID] = true
		for _, v := range []string{s.Data.InputsVolume, s.Data.WorkspaceVolume, s.Data.OutputsVolume, s.ScratchVolume} {
			if storage[v] {
				return ErrInvalidProfile
			}
			storage[v] = true
		}
	}
	return nil
}
