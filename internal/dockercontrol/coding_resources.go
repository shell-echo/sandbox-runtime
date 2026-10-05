package dockercontrol

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	codingManagedLabel   = "io.github.shell-echo.sandbox-runtime.managed"
	codingEffectLabel    = "io.github.shell-echo.sandbox-runtime.coding-effect"
	codingAuthorityLabel = "io.github.shell-echo.sandbox-runtime.coding-authority"
	codingProfileLabel   = "io.github.shell-echo.sandbox-runtime.coding-profile"
	codingPlanLabel      = "io.github.shell-echo.sandbox-runtime.coding-plan"
	codingTemplateLabel  = "io.github.shell-echo.sandbox-runtime.coding-template"
	codingSlotLabel      = "io.github.shell-echo.sandbox-runtime.coding-slot"
	codingRoleLabel      = "io.github.shell-echo.sandbox-runtime.coding-role"
)

type CodingResourceRole string

const (
	CodingPreparationRole CodingResourceRole = "preparation"
	CodingRuntimeRole     CodingResourceRole = "runtime"
	CodingInputsRole      CodingResourceRole = "inputs"
	CodingWorkspaceRole   CodingResourceRole = "workspace"
	CodingOutputsRole     CodingResourceRole = "outputs"
)

// CodingResourceSet names exactly the two possible containers and three
// whole volumes belonging to one create effect. Names and labels are derived
// from the frozen plan and authority, never from a caller-supplied Docker ID,
// path or endpoint. This is an inventory projection, not a dispatch permit or
// evidence that any resource exists.
type CodingResourceSet struct {
	effectID             string
	authorityDigest      string
	profileDigest        string
	planDigest           string
	templateDigest       string
	slotID               string
	preparationContainer string
	runtimeContainer     string
	mounts               []codingidentity.VolumeMount
}

func NewCodingResourceSet(binding CodingReceiptBinding, authority CodingCreateAuthority) (CodingResourceSet, error) {
	if binding.Validate() != nil || authority.BindControl(binding.Plan, binding.ControlPolicyDigest,
		binding.PeerPrincipalDigest, binding.SpecBySlot[authority.SlotID], authority.IssuedAt) != nil ||
		authority.ProfileDigest != binding.ProfileDigest || authority.PlanDigest != binding.PlanDigest {
		return CodingResourceSet{}, ErrInvalidAuthority
	}
	claim := codingidentity.Claim{TenantDigest: authority.TenantDigest, SandboxID: authority.SandboxID,
		AllocationID: authority.AllocationID, OperationID: authority.OperationID,
		AttemptID: authority.AttemptID, RequestDigest: authority.RequestDigest,
		Generation: authority.CreationGeneration, Fence: authority.Fence}
	mounts, err := binding.Plan.EffectiveMounts(authority.SlotID, claim)
	if err != nil || len(mounts) != 3 || mounts[0].Target != "/inputs" || !mounts[0].ReadOnly ||
		mounts[1].Target != "/workspace" || mounts[1].ReadOnly ||
		mounts[2].Target != "/outputs" || mounts[2].ReadOnly {
		return CodingResourceSet{}, ErrInvalidAuthority
	}
	// EffectID is a canonical sha256 digest. Using its complete hex value
	// avoids truncation collisions and keeps the names bounded and replay-stable.
	suffix := strings.TrimPrefix(authority.EffectID, "sha256:")
	return CodingResourceSet{effectID: authority.EffectID, authorityDigest: authority.Digest(),
		profileDigest: binding.ProfileDigest, planDigest: binding.PlanDigest,
		templateDigest:       binding.Plan.TemplateDigest,
		slotID:               authority.SlotID,
		preparationContainer: "sandbox-runtime-coding-prep-" + suffix,
		runtimeContainer:     "sandbox-runtime-coding-runtime-" + suffix,
		mounts:               slices.Clone(mounts)}, nil
}

func (s CodingResourceSet) ContainerName(role CodingResourceRole) (string, error) {
	if !controlDigest.MatchString(s.effectID) || !controlDigest.MatchString(s.authorityDigest) ||
		!controlDigest.MatchString(s.profileDigest) || !controlDigest.MatchString(s.planDigest) ||
		!controlDigest.MatchString(s.templateDigest) || s.slotID == "" || len(s.mounts) != 3 {
		return "", ErrInvalidAuthority
	}
	switch role {
	case CodingPreparationRole:
		return s.preparationContainer, nil
	case CodingRuntimeRole:
		return s.runtimeContainer, nil
	default:
		return "", ErrInvalidAuthority
	}
}

func (s CodingResourceSet) Mounts() []codingidentity.VolumeMount { return slices.Clone(s.mounts) }

func (s CodingResourceSet) VolumeName(role CodingResourceRole) (string, error) {
	if _, err := s.Labels(role); err != nil {
		return "", err
	}
	switch role {
	case CodingInputsRole:
		return s.mounts[0].Name, nil
	case CodingWorkspaceRole:
		return s.mounts[1].Name, nil
	case CodingOutputsRole:
		return s.mounts[2].Name, nil
	default:
		return "", ErrInvalidAuthority
	}
}

func (s CodingResourceSet) Labels(role CodingResourceRole) (map[string]string, error) {
	if !controlDigest.MatchString(s.effectID) || !controlDigest.MatchString(s.authorityDigest) ||
		!controlDigest.MatchString(s.profileDigest) || !controlDigest.MatchString(s.planDigest) ||
		!controlDigest.MatchString(s.templateDigest) ||
		s.slotID == "" || len(s.mounts) != 3 ||
		role != CodingPreparationRole && role != CodingRuntimeRole &&
			role != CodingInputsRole && role != CodingWorkspaceRole && role != CodingOutputsRole {
		return nil, ErrInvalidAuthority
	}
	return map[string]string{codingManagedLabel: "true", codingEffectLabel: s.effectID,
		codingAuthorityLabel: s.authorityDigest, codingProfileLabel: s.profileDigest,
		codingPlanLabel: s.planDigest, codingTemplateLabel: s.templateDigest,
		codingSlotLabel: s.slotID, codingRoleLabel: string(role)}, nil
}

// MatchLabels checks a named volume, whose labels are only the frozen
// Control-generated binding labels. Containers additionally inherit the
// pinned OCI image's labels and must use MatchContainerLabels below.
func (s CodingResourceSet) MatchLabels(role CodingResourceRole, observed map[string]string) error {
	if role != CodingInputsRole && role != CodingWorkspaceRole && role != CodingOutputsRole {
		return ErrInvalidAuthority
	}
	want, err := s.Labels(role)
	if err != nil || !maps.Equal(want, observed) {
		return ErrInvalidAuthority
	}
	return nil
}

// ContainerLabels derives the complete effective label set from the exact
// descriptor-verified OCI config, then adds the Control binding labels. A
// collision is rejected even if the values happen to agree. This prevents a
// caller from dropping inherited provenance labels or accepting extras by
// filtering on a prefix.
func (s CodingResourceSet) ContainerLabels(role CodingResourceRole,
	template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments) (map[string]string, error) {
	if role != CodingPreparationRole && role != CodingRuntimeRole {
		return nil, ErrInvalidAuthority
	}
	templateDigest, err := template.Digest()
	if err != nil || templateDigest != s.templateDigest {
		return nil, ErrInvalidAuthority
	}
	if _, err := phase6security.VerifyImageDescriptorDocuments(template.Image.Location,
		template.Image.IdentityKind, template.Image.Reference, template.Image.Descriptor.Digest,
		template.Image.Platform, template.Image.SelectedManifestDigest,
		template.Image.ConfigDigest, documents); err != nil {
		return nil, ErrInvalidAuthority
	}
	var config struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if json.Unmarshal(documents.Config, &config) != nil || len(config.Config.Labels) == 0 ||
		len(config.Config.Labels) > 64 {
		return nil, ErrInvalidAuthority
	}
	binding, err := s.Labels(role)
	if err != nil {
		return nil, err
	}
	return mergeCodingContainerLabels(config.Config.Labels, binding)
}

func (s CodingResourceSet) MatchContainerLabels(role CodingResourceRole,
	template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments, observed map[string]string) error {
	want, err := s.ContainerLabels(role, template, documents)
	if err != nil {
		return ErrInvalidAuthority
	}
	return matchEffectiveCodingContainerLabels(want, observed)
}

func matchEffectiveCodingContainerLabels(expected, observed map[string]string) error {
	if len(expected) == 0 || !maps.Equal(expected, observed) {
		return ErrInvalidAuthority
	}
	return nil
}

func mergeCodingContainerLabels(imageLabels, bindingLabels map[string]string) (map[string]string, error) {
	if len(imageLabels) == 0 || len(imageLabels) > 64 || len(bindingLabels) != 8 {
		return nil, ErrInvalidAuthority
	}
	result := maps.Clone(imageLabels)
	for key, value := range bindingLabels {
		if _, collision := result[key]; collision {
			return nil, ErrInvalidAuthority
		}
		result[key] = value
	}
	return result, nil
}
