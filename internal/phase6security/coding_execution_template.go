package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

const (
	CodingExecutionTemplateProtocol = "sandbox-runtime.phase6-coding-execution-template.v2"
	CodingExecutionResourceMode     = "sandbox-runtime.coding-isolated-resources.v1"
	MaxCodingExecutionTemplateBytes = 16 << 10
)

type CodingExecutionSlot struct {
	Data          codingidentity.Slot `json:"data"`
	ScratchVolume string              `json:"scratch_volume"`
}

// CodingExecutionTemplate is a NEW, held source candidate, not template-v2,
// Plan v1, a complete Profile or a migration of populated receipt namespaces.
// It fixes proposed budgets, whose workload/physical gates remain unproved.
// No current production dispatcher or Profile validator admits this type.
type CodingExecutionTemplate struct {
	Protocol               string                            `json:"protocol"`
	ResourceMode           string                            `json:"resource_mode"`
	OwnerDeployment        string                            `json:"owner_deployment"`
	OwnerPrincipalDigest   string                            `json:"owner_principal_digest"`
	Image                  CodingTemplateImageV2             `json:"image"`
	ImageManifestDigest    string                            `json:"image_manifest_digest"`
	ResidentCommand        []string                          `json:"resident_command"`
	CommandMode            string                            `json:"command_mode"`
	Environment            []string                          `json:"environment"`
	WorkingDirectory       string                            `json:"working_directory"`
	NetworkMode            string                            `json:"network_mode"`
	RootFilesystemReadOnly bool                              `json:"root_filesystem_read_only"`
	DropAllCapabilities    bool                              `json:"drop_all_capabilities"`
	NoNewPrivileges        bool                              `json:"no_new_privileges"`
	SeccompPolicyDigest    string                            `json:"seccomp_policy_digest"`
	PrivatePID             bool                              `json:"private_pid"`
	PrivateIPC             bool                              `json:"private_ipc"`
	UseInit                bool                              `json:"use_init"`
	RestartPolicy          string                            `json:"restart_policy"`
	LogDriver              string                            `json:"log_driver"`
	PrivateShmBytes        int64                             `json:"private_shm_bytes"`
	Resources              codingidentity.ExecutionResources `json:"resources"`
	Scratch                codingidentity.ExecutionScratch   `json:"scratch"`
	Storage                codingidentity.ExecutionStorage   `json:"storage"`
	ControlStorage         controlstorage.Layout             `json:"control_storage"`
	DataMounts             []CodingTemplateMountV2           `json:"data_mounts"`
	ScratchTarget          string                            `json:"scratch_target"`
	VolumePrep             string                            `json:"volume_prep"`
	VolumePrepMode         uint32                            `json:"volume_prep_mode"`
	Slots                  []CodingExecutionSlot             `json:"slots"`
}

func codingExecutionCandidateResources() codingidentity.ExecutionResources {
	return codingidentity.ExecutionResources{Protocol: codingidentity.ExecutionResourcesProtocol,
		Total:        codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64},
		Resident:     codingidentity.Limits{MemoryBytes: 128 << 20, CPUMillis: 100, PIDs: 16},
		Command:      codingidentity.Limits{MemoryBytes: 832 << 20, CPUMillis: 900, PIDs: 48},
		ScratchBytes: codingidentity.SharedScratchBytes, MaxPossibleCommands: 1}
}

// NewCodingExecutionTemplate copies source/image identity into a distinct
// canonical type. It neither changes the original nor inherits its admission.
// The input limit must match the selected new candidate ceiling exactly.
func NewCodingExecutionTemplate(source CodingRuntimeTemplateV2) (CodingExecutionTemplate, error) {
	if source.Validate() != nil || source.Limits != codingExecutionCandidateResources().Total {
		return CodingExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	t := CodingExecutionTemplate{Protocol: CodingExecutionTemplateProtocol, ResourceMode: CodingExecutionResourceMode,
		OwnerDeployment: source.OwnerDeployment, OwnerPrincipalDigest: source.OwnerPrincipalDigest,
		Image: source.Image, ImageManifestDigest: source.ImageManifestDigest, ResidentCommand: slices.Clone(source.Command),
		CommandMode: "validated_argv_as_pid1", Environment: slices.Clone(source.Environment),
		WorkingDirectory: "/workspace", NetworkMode: "none", RootFilesystemReadOnly: true,
		DropAllCapabilities: true, NoNewPrivileges: true, SeccompPolicyDigest: source.SeccompPolicyDigest,
		PrivatePID: true, PrivateIPC: true, RestartPolicy: "no", LogDriver: "none", PrivateShmBytes: 16 << 20,
		Resources: codingExecutionCandidateResources(), Scratch: codingidentity.NewExecutionScratch(),
		Storage: codingidentity.NewExecutionStorage(), ControlStorage: controlstorage.NewLayout(), DataMounts: slices.Clone(source.Mounts), ScratchTarget: "/tmp",
		VolumePrep: "stopped_carrier_two_directories_v1", VolumePrepMode: 0o770}
	for _, slot := range source.Slots {
		t.Slots = append(t.Slots, CodingExecutionSlot{Data: slot, ScratchVolume: slot.ID + "-scratch"})
	}
	if t.Validate() != nil {
		return CodingExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	return t, nil
}

func (t CodingExecutionTemplate) Validate() error {
	if t.Protocol != CodingExecutionTemplateProtocol || t.ResourceMode != CodingExecutionResourceMode ||
		t.Resources != codingExecutionCandidateResources() || t.Scratch.BindResources(t.Resources) != nil || t.Storage.Validate() != nil ||
		t.ControlStorage.Validate() != nil || t.ControlStorage.Coding != t.Storage ||
		t.CommandMode != "validated_argv_as_pid1" || !t.PrivatePID || !t.PrivateIPC || t.UseInit || t.RestartPolicy != "no" ||
		t.LogDriver != "none" || t.PrivateShmBytes != 16<<20 || t.ScratchTarget != "/tmp" || len(t.Slots) != codingidentity.LocalCandidateCapacity {
		return ErrInvalidCodingTemplate
	}
	slots := make([]codingidentity.Slot, 0, len(t.Slots))
	for _, slot := range t.Slots {
		if slot.Data.Validate() != nil || slot.ScratchVolume != slot.Data.ID+"-scratch" {
			return ErrInvalidCodingTemplate
		}
		slots = append(slots, slot.Data)
	}
	// Reuse only the locked image/static-source verification. The temporary
	// old-format value is never returned, bound to a Plan or sent to an executor.
	expected, err := NewCodingRuntimeTemplateV2(t.Image.Platform, t.Image.ConfigDigest, t.Image.Descriptor.Size,
		t.OwnerPrincipalDigest, t.SeccompPolicyDigest, slots, t.Resources.Total)
	if err != nil || t.OwnerDeployment != expected.OwnerDeployment || t.Image != expected.Image ||
		t.ImageManifestDigest != expected.ImageManifestDigest || !slices.Equal(t.ResidentCommand, expected.Command) ||
		!slices.Equal(t.Environment, expected.Environment) || t.WorkingDirectory != expected.WorkingDirectory ||
		t.NetworkMode != expected.NetworkMode || !t.RootFilesystemReadOnly || !t.DropAllCapabilities || !t.NoNewPrivileges ||
		!slices.Equal(t.DataMounts, expected.Mounts) || t.VolumePrep != expected.VolumePrep || t.VolumePrepMode != expected.VolumePrepMode {
		return ErrInvalidCodingTemplate
	}
	return nil
}

func EncodeCodingExecutionTemplate(t CodingExecutionTemplate) ([]byte, error) {
	if t.Validate() != nil {
		return nil, ErrInvalidCodingTemplate
	}
	b, err := json.Marshal(t)
	if err != nil || len(b) == 0 || len(b) > MaxCodingExecutionTemplateBytes {
		return nil, ErrInvalidCodingTemplate
	}
	return b, nil
}

func DecodeCodingExecutionTemplate(b []byte) (CodingExecutionTemplate, error) {
	var t CodingExecutionTemplate
	if len(b) == 0 || len(b) > MaxCodingExecutionTemplateBytes || json.Unmarshal(b, &t) != nil {
		return CodingExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	canonical, err := EncodeCodingExecutionTemplate(t)
	if err != nil || !bytes.Equal(b, canonical) {
		return CodingExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	return t, nil
}

func (t CodingExecutionTemplate) Digest() (string, error) {
	b, err := EncodeCodingExecutionTemplate(t)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("sandbox-runtime/phase6-coding-execution-template/v2\x00"), b...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
