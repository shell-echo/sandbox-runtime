package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	codingcandidate "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/candidate"
)

const CodingCandidateExecutionTemplateProtocol = "sandbox-runtime.phase6-coding-execution-template.v3"

// CodingCandidateExecutionTemplate freezes the unsigned candidate's identity
// and four-volume policy in a distinct type and digest domain. It grants no
// Profile, supply-chain, namespace, dispatch, or historical publication authority.
// Existing v2 templates are neither converted nor implicitly upgraded.
type CodingCandidateExecutionTemplate struct {
	Protocol               string                            `json:"protocol"`
	ResourceMode           string                            `json:"resource_mode"`
	OwnerDeployment        string                            `json:"owner_deployment"`
	OwnerPrincipalDigest   string                            `json:"owner_principal_digest"`
	Image                  CodingTemplateImageV2             `json:"image"`
	Candidate              codingcandidate.Identity          `json:"candidate"`
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

func NewCodingCandidateExecutionTemplate(platform, ownerPrincipalDigest, seccompPolicyDigest string, slots []codingidentity.Slot) (CodingCandidateExecutionTemplate, error) {
	return newCodingCandidateExecutionTemplate(platform, ownerPrincipalDigest, seccompPolicyDigest, slots)
}

func newCodingCandidateExecutionTemplate(platform, owner, seccomp string, slots []codingidentity.Slot) (CodingCandidateExecutionTemplate, error) {
	i, err := codingcandidate.LockedIdentity(platform)
	if err != nil || !digestPattern.MatchString(owner) || !digestPattern.MatchString(seccomp) || len(slots) != codingidentity.LocalCandidateCapacity {
		return CodingCandidateExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	r, err := codingcandidate.LockedRuntime(platform)
	if err != nil {
		return CodingCandidateExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	t := CodingCandidateExecutionTemplate{Protocol: CodingCandidateExecutionTemplateProtocol, ResourceMode: CodingExecutionResourceMode,
		OwnerDeployment: "provider-runtime", OwnerPrincipalDigest: owner, Candidate: i,
		Image: CodingTemplateImageV2{Location: "local", IdentityKind: ImageIdentityOCIManifest, Reference: i.ManifestDigest,
			Descriptor: ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: i.ManifestDigest, Size: i.ManifestSize},
			Platform:   platform, SelectedManifestSize: i.ManifestSize, ConfigDigest: i.ConfigDigest},
		ResidentCommand: r.Command, Environment: r.Environment, WorkingDirectory: r.WorkingDirectory,
		CommandMode: "validated_argv_as_pid1", NetworkMode: "none", RootFilesystemReadOnly: true,
		DropAllCapabilities: true, NoNewPrivileges: true, SeccompPolicyDigest: seccomp,
		PrivatePID: true, PrivateIPC: true, RestartPolicy: "no", LogDriver: "none", PrivateShmBytes: 16 << 20,
		Resources: codingExecutionCandidateResources(), Scratch: codingidentity.NewExecutionScratch(),
		Storage: codingidentity.NewExecutionStorage(), ControlStorage: controlstorage.NewLayout(),
		DataMounts:    []CodingTemplateMountV2{{Target: "/inputs", ReadOnly: true}, {Target: "/workspace"}, {Target: "/outputs"}},
		ScratchTarget: "/tmp", VolumePrep: "stopped_carrier_two_directories_v1", VolumePrepMode: 0o770}
	previous := ""
	uids, gids, volumes := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	for _, slot := range slots {
		if slot.Validate() != nil || slot.ID <= previous || uids[slot.WorkloadUID] || gids[slot.WorkloadGID] {
			return CodingCandidateExecutionTemplate{}, ErrInvalidCodingTemplate
		}
		scratch := slot.ID + "-scratch"
		for _, v := range []string{slot.InputsVolume, slot.WorkspaceVolume, slot.OutputsVolume, scratch} {
			if volumes[v] {
				return CodingCandidateExecutionTemplate{}, ErrInvalidCodingTemplate
			}
			volumes[v] = true
		}
		uids[slot.WorkloadUID], gids[slot.WorkloadGID], previous = true, true, slot.ID
		t.Slots = append(t.Slots, CodingExecutionSlot{Data: slot, ScratchVolume: scratch})
	}
	return t, nil
}

func (t CodingCandidateExecutionTemplate) Validate() error {
	if t.Candidate.ValidateLocked() != nil || len(t.Slots) != codingidentity.LocalCandidateCapacity {
		return ErrInvalidCodingTemplate
	}
	slots := make([]codingidentity.Slot, len(t.Slots))
	for j, slot := range t.Slots {
		slots[j] = slot.Data
	}
	expected, err := newCodingCandidateExecutionTemplate(t.Candidate.Platform, t.OwnerPrincipalDigest, t.SeccompPolicyDigest, slots)
	if err != nil {
		return ErrInvalidCodingTemplate
	}
	// Compare every frozen policy field, including booleans, scratch and all
	// storage budgets. This does not call or reinterpret either old v2 type.
	b, err := json.Marshal(t)
	want, wantErr := json.Marshal(expected)
	if err != nil || wantErr != nil || len(b) > MaxCodingExecutionTemplateBytes || !bytes.Equal(b, want) {
		return ErrInvalidCodingTemplate
	}
	return nil
}

func EncodeCodingCandidateExecutionTemplate(t CodingCandidateExecutionTemplate) ([]byte, error) {
	if t.Validate() != nil {
		return nil, ErrInvalidCodingTemplate
	}
	return json.Marshal(t)
}

func DecodeCodingCandidateExecutionTemplate(b []byte) (CodingCandidateExecutionTemplate, error) {
	var t CodingCandidateExecutionTemplate
	if len(b) == 0 || len(b) > MaxCodingExecutionTemplateBytes || json.Unmarshal(b, &t) != nil {
		return CodingCandidateExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	canonical, err := EncodeCodingCandidateExecutionTemplate(t)
	if err != nil || !bytes.Equal(b, canonical) {
		return CodingCandidateExecutionTemplate{}, ErrInvalidCodingTemplate
	}
	return t, nil
}

func (t CodingCandidateExecutionTemplate) Digest() (string, error) {
	b, err := EncodeCodingCandidateExecutionTemplate(t)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("sandbox-runtime/phase6-coding-execution-template/v3\x00"), b...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
