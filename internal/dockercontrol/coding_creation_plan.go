package dockercontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// All write parameters are derived here from the original authority and the
// frozen template. Neither the Provider nor the wire request supplies Docker
// options, object names, archive bytes, paths, or an image override.
type codingCreationPlan struct {
	set                            CodingResourceSet
	slot                           codingidentity.Slot
	prepName, runtimeName          string
	prepBody, runtimeBody, archive []byte
	volumeBodies                   [3][]byte
}

func newCodingCreationPlan(binding CodingReceiptBinding, authority CodingCreateAuthority,
	template phase6security.CodingRuntimeTemplateV2, documents phase6security.ImageDescriptorDocuments,
	policy []byte) (codingCreationPlan, error) {
	var plan codingCreationPlan
	if verifyCodingCreationSource(binding, template, documents, policy) != nil {
		return plan, ErrInvalidCodingCreation
	}
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		return plan, ErrInvalidCodingCreation
	}
	return codingCreationPlanForSet(set, authority, template, documents, policy)
}

func verifyCodingCreationSource(binding CodingReceiptBinding, template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments, policy []byte) error {
	sum := sha256.Sum256(policy)
	if binding.Validate() != nil || template.BindPlan(binding.Plan) != nil ||
		template.Image.Platform != binding.RuntimePlatform || len(policy) == 0 || len(policy) > 64<<10 ||
		"sha256:"+hex.EncodeToString(sum[:]) != template.SeccompPolicyDigest {
		return ErrInvalidCodingCreation
	}
	if _, ok := codingOCIPlatform(template.Image.Platform); !ok {
		return ErrInvalidCodingCreation
	}
	i := template.Image
	if _, err := phase6security.VerifyImageDescriptorDocuments(i.Location, i.IdentityKind, i.Reference, i.Descriptor.Digest, i.Platform, i.SelectedManifestDigest, i.ConfigDigest, documents); err != nil {
		return ErrInvalidCodingCreation
	}
	return nil
}

func codingCreationPlanForSet(set CodingResourceSet, authority CodingCreateAuthority, template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments, policy []byte) (codingCreationPlan, error) {
	var plan codingCreationPlan
	plan.set = set
	for _, slot := range template.Slots {
		if slot.ID == authority.SlotID {
			plan.slot = slot
		}
	}
	if plan.slot.ID == "" {
		return codingCreationPlan{}, ErrInvalidCodingCreation
	}
	plan.prepName, _ = set.ContainerName(CodingPreparationRole)
	plan.runtimeName, _ = set.ContainerName(CodingRuntimeRole)
	for i, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := set.VolumeName(role)
		labels, err := set.Labels(role)
		if err != nil {
			return codingCreationPlan{}, ErrInvalidCodingCreation
		}
		plan.volumeBodies[i], err = json.Marshal(struct {
			Name   string
			Driver string
			Labels map[string]string
		}{name, "local", labels})
		if err != nil {
			return codingCreationPlan{}, ErrInvalidCodingCreation
		}
	}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		labels, err := set.ContainerLabels(role, template, documents)
		if err != nil {
			return codingCreationPlan{}, ErrInvalidCodingCreation
		}
		runtime := role == CodingRuntimeRole
		command := slices.Clone(template.Command)
		if !runtime {
			command = []string{"/bin/false"}
		}
		var mounts []mount.Mount
		for _, item := range set.Mounts() {
			mounts = append(mounts, mount.Mount{Type: mount.TypeVolume, Source: item.Name, Target: item.Target,
				ReadOnly: item.ReadOnly, VolumeOptions: &mount.VolumeOptions{NoCopy: runtime}})
		}
		pids := template.Limits.PIDs
		body, err := json.Marshal(struct {
			*container.Config
			HostConfig *container.HostConfig
		}{&container.Config{Image: template.Image.Reference, Cmd: command, Env: slices.Clone(template.Environment),
			WorkingDir: template.WorkingDirectory, User: fmt.Sprintf("%d:%d", plan.slot.WorkloadUID, plan.slot.WorkloadGID), Labels: labels},
			&container.HostConfig{NetworkMode: "none", ReadonlyRootfs: runtime, CapDrop: []string{"ALL"},
				SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + string(policy)}, Mounts: mounts,
				Tmpfs:         map[string]string{"/tmp": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=%d,gid=%d", template.TmpfsBytes, plan.slot.WorkloadUID, plan.slot.WorkloadGID)},
				RestartPolicy: container.RestartPolicy{Name: "no"}, Resources: container.Resources{
					Memory: template.Limits.MemoryBytes, MemorySwap: template.Limits.MemoryBytes,
					NanoCPUs: template.Limits.CPUMillis * 1_000_000, PidsLimit: &pids}}})
		if err != nil {
			return codingCreationPlan{}, ErrInvalidCodingCreation
		}
		if runtime {
			plan.runtimeBody = body
		} else {
			plan.prepBody = body
		}
	}
	archive, err := CodingVolumePrepArchive(template, authority.SlotID)
	if err != nil {
		return codingCreationPlan{}, ErrInvalidCodingCreation
	}
	plan.archive = archive
	return plan, nil
}
