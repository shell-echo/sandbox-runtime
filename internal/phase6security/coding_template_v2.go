package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

const (
	CodingTemplateProtocolV2 = "sandbox-runtime.phase6-coding-runtime-template.v2"
	CodingTemplateVersionV2  = 2
	MaxCodingTemplateBytes   = 8 << 10
	CodingTmpfsBytes         = 32 << 20
)

var ErrInvalidCodingTemplate = errors.New("invalid Phase 6 Coding runtime template v2")

type CodingTemplateImageV2 struct {
	Location               string          `json:"location"`
	IdentityKind           string          `json:"identity_kind"`
	Reference              string          `json:"reference"`
	Descriptor             ImageDescriptor `json:"descriptor"`
	Platform               string          `json:"platform"`
	SelectedManifestDigest string          `json:"selected_manifest_digest"`
	SelectedManifestSize   int64           `json:"selected_manifest_size"`
	ConfigDigest           string          `json:"config_digest"`
}

type CodingTemplateMountV2 struct {
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// CodingRuntimeTemplateV2 is the single v2-only source for create and
// inspect. It intentionally omits the final Profile digest: that Profile
// freezes this template, while codingidentity.Plan references its digest.
// This fragment alone is not a complete runnable Security Profile v2.
type CodingRuntimeTemplateV2 struct {
	Protocol               string                  `json:"protocol"`
	Version                int                     `json:"version"`
	OwnerDeployment        string                  `json:"owner_deployment"`
	OwnerPrincipalDigest   string                  `json:"owner_principal_digest"`
	Image                  CodingTemplateImageV2   `json:"image"`
	ImageManifestDigest    string                  `json:"image_manifest_digest"`
	Command                []string                `json:"command"`
	Environment            []string                `json:"environment"`
	WorkingDirectory       string                  `json:"working_directory"`
	NetworkMode            string                  `json:"network_mode"`
	RootFilesystemReadOnly bool                    `json:"root_filesystem_read_only"`
	DropAllCapabilities    bool                    `json:"drop_all_capabilities"`
	NoNewPrivileges        bool                    `json:"no_new_privileges"`
	SeccompPolicyDigest    string                  `json:"seccomp_policy_digest"`
	Limits                 codingidentity.Limits   `json:"limits"`
	TmpfsTarget            string                  `json:"tmpfs_target"`
	TmpfsBytes             int64                   `json:"tmpfs_bytes"`
	TmpfsMode              uint32                  `json:"tmpfs_mode"`
	TmpfsNoExec            bool                    `json:"tmpfs_no_exec"`
	TmpfsNoSUID            bool                    `json:"tmpfs_no_suid"`
	TmpfsNoDevice          bool                    `json:"tmpfs_no_device"`
	Mounts                 []CodingTemplateMountV2 `json:"mounts"`
	VolumePrep             string                  `json:"volume_prep"`
	VolumePrepMode         uint32                  `json:"volume_prep_mode"`
	Slots                  []codingidentity.Slot   `json:"slots"`
}

func NewCodingRuntimeTemplateV2(platform, configDigest string, descriptorSize int64,
	ownerPrincipalDigest, seccompPolicyDigest string, slots []codingidentity.Slot,
	limits codingidentity.Limits) (CodingRuntimeTemplateV2, error) {
	manifest, err := codingimage.LockedManifest()
	if err != nil {
		return CodingRuntimeTemplateV2{}, ErrInvalidCodingTemplate
	}
	manifestDigest, err := codingImageManifestDigest(manifest)
	if err != nil {
		return CodingRuntimeTemplateV2{}, ErrInvalidCodingTemplate
	}
	publication := codingimage.LockedPublication()
	selected := ""
	for _, candidate := range publication.Platforms {
		if candidate.Platform == platform {
			selected = candidate.Digest
		}
	}
	template := CodingRuntimeTemplateV2{
		Protocol: CodingTemplateProtocolV2, Version: CodingTemplateVersionV2,
		OwnerDeployment: "provider-runtime", OwnerPrincipalDigest: ownerPrincipalDigest,
		Image: CodingTemplateImageV2{Location: "registry", IdentityKind: ImageIdentityOCIIndex,
			Reference: publication.Image(), Descriptor: ImageDescriptor{MediaType: "application/vnd.oci.image.index.v1+json",
				Digest: publication.Digest, Size: descriptorSize}, Platform: platform,
			SelectedManifestDigest: selected, SelectedManifestSize: codingimage.PublishedManifestSize,
			ConfigDigest: configDigest},
		ImageManifestDigest: manifestDigest, Command: slices.Clone(manifest.Runtime.Command),
		Environment:      codingimage.LockedRuntimeEnvironment(),
		WorkingDirectory: "/workspace", NetworkMode: "none", RootFilesystemReadOnly: true,
		DropAllCapabilities: true, NoNewPrivileges: true, SeccompPolicyDigest: seccompPolicyDigest,
		Limits: limits, TmpfsTarget: "/tmp", TmpfsBytes: CodingTmpfsBytes, TmpfsMode: 0o700,
		TmpfsNoExec: true, TmpfsNoSUID: true, TmpfsNoDevice: true,
		Mounts: []CodingTemplateMountV2{{Target: "/inputs", ReadOnly: true},
			{Target: "/workspace"}, {Target: "/outputs"}},
		VolumePrep: "stopped_carrier_two_directories_v1", VolumePrepMode: 0o770,
		Slots: slices.Clone(slots),
	}
	if template.Validate() != nil {
		return CodingRuntimeTemplateV2{}, ErrInvalidCodingTemplate
	}
	return template, nil
}

func (t CodingRuntimeTemplateV2) Validate() error {
	manifest, manifestErr := codingimage.LockedManifest()
	manifestDigest, digestErr := codingImageManifestDigest(manifest)
	publication := codingimage.LockedPublication()
	selected := ""
	for _, candidate := range publication.Platforms {
		if candidate.Platform == t.Image.Platform {
			selected = candidate.Digest
		}
	}
	if manifestErr != nil || digestErr != nil || publication.Validate() != nil ||
		t.Protocol != CodingTemplateProtocolV2 || t.Version != CodingTemplateVersionV2 ||
		t.OwnerDeployment != "provider-runtime" || !digestPattern.MatchString(t.OwnerPrincipalDigest) ||
		t.Image.Location != "registry" || t.Image.IdentityKind != ImageIdentityOCIIndex ||
		t.Image.Reference != publication.Image() || t.Image.Descriptor.Digest != publication.Digest ||
		t.Image.Descriptor.MediaType != "application/vnd.oci.image.index.v1+json" ||
		t.Image.Descriptor.Size != codingimage.PublishedDescriptorSize ||
		selected == "" || t.Image.SelectedManifestDigest != selected ||
		t.Image.SelectedManifestSize != codingimage.PublishedManifestSize ||
		t.Image.ConfigDigest != codingimage.LockedConfigDigest(t.Image.Platform) ||
		!validImageIdentity(t.Image.Location, t.Image.IdentityKind, t.Image.Reference,
			t.Image.Descriptor.Digest, t.Image.Platform, t.Image.SelectedManifestDigest, t.Image.ConfigDigest) ||
		t.ImageManifestDigest != manifestDigest || !slices.Equal(t.Command, manifest.Runtime.Command) ||
		!slices.Equal(t.Environment, codingimage.LockedRuntimeEnvironment()) ||
		t.WorkingDirectory != "/workspace" || t.NetworkMode != "none" || !t.RootFilesystemReadOnly ||
		!t.DropAllCapabilities || !t.NoNewPrivileges || !digestPattern.MatchString(t.SeccompPolicyDigest) ||
		t.Limits.Validate() != nil || t.TmpfsTarget != "/tmp" || t.TmpfsBytes != CodingTmpfsBytes ||
		t.TmpfsMode != 0o700 || !t.TmpfsNoExec || !t.TmpfsNoSUID || !t.TmpfsNoDevice ||
		!slices.Equal(t.Mounts, []CodingTemplateMountV2{{Target: "/inputs", ReadOnly: true},
			{Target: "/workspace"}, {Target: "/outputs"}}) ||
		t.VolumePrep != "stopped_carrier_two_directories_v1" || t.VolumePrepMode != 0o770 ||
		len(t.Slots) != codingidentity.LocalCandidateCapacity {
		return ErrInvalidCodingTemplate
	}
	previous := ""
	uids, gids, volumes := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	for _, slot := range t.Slots {
		if slot.Validate() != nil || slot.ID <= previous || uids[slot.WorkloadUID] || gids[slot.WorkloadGID] ||
			volumes[slot.InputsVolume] || volumes[slot.WorkspaceVolume] || volumes[slot.OutputsVolume] {
			return ErrInvalidCodingTemplate
		}
		uids[slot.WorkloadUID], gids[slot.WorkloadGID] = true, true
		volumes[slot.InputsVolume], volumes[slot.WorkspaceVolume], volumes[slot.OutputsVolume] = true, true, true
		previous = slot.ID
	}
	return nil
}

func (t CodingRuntimeTemplateV2) Digest() (string, error) {
	if t.Validate() != nil {
		return "", ErrInvalidCodingTemplate
	}
	document, err := json.Marshal(t)
	if err != nil || len(document) > MaxCodingTemplateBytes {
		return "", ErrInvalidCodingTemplate
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-coding-runtime-template/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (t CodingRuntimeTemplateV2) BindPlan(plan codingidentity.Plan) error {
	digest, err := t.Digest()
	if err != nil || plan.Validate() != nil || plan.TemplateDigest != digest ||
		plan.OwnerDeployment != t.OwnerDeployment || plan.OwnerPrincipalDigest != t.OwnerPrincipalDigest ||
		plan.ImageDigest != t.Image.Descriptor.Digest || plan.ImageConfigDigest != t.Image.ConfigDigest ||
		plan.NetworkMode != t.NetworkMode || plan.Limits != t.Limits ||
		!slices.Equal(plan.Slots, t.Slots) {
		return ErrInvalidCodingTemplate
	}
	return nil
}

func EncodeCodingRuntimeTemplateV2(t CodingRuntimeTemplateV2) ([]byte, error) {
	if t.Validate() != nil {
		return nil, ErrInvalidCodingTemplate
	}
	document, err := json.Marshal(t)
	if err != nil || len(document) == 0 || len(document) > MaxCodingTemplateBytes {
		return nil, ErrInvalidCodingTemplate
	}
	return document, nil
}

func DecodeCodingRuntimeTemplateV2(document []byte) (CodingRuntimeTemplateV2, error) {
	var template CodingRuntimeTemplateV2
	if len(document) == 0 || len(document) > MaxCodingTemplateBytes ||
		json.Unmarshal(document, &template) != nil || template.Validate() != nil {
		return CodingRuntimeTemplateV2{}, ErrInvalidCodingTemplate
	}
	canonical, err := EncodeCodingRuntimeTemplateV2(template)
	if err != nil || !bytes.Equal(canonical, document) {
		return CodingRuntimeTemplateV2{}, ErrInvalidCodingTemplate
	}
	return template, nil
}

func codingImageManifestDigest(manifest codingimage.Manifest) (string, error) {
	if manifest.Validate() != nil {
		return "", ErrInvalidCodingTemplate
	}
	document, err := json.Marshal(manifest)
	if err != nil {
		return "", ErrInvalidCodingTemplate
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/coding-shell-image-manifest/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
