package dockercontrol

import (
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const executionScopeLabel = "io.github.shell-echo.sandbox-runtime.execution-scope"

var executionVolumeRoles = [4]string{"inputs", "workspace", "outputs", "scratch"}
var executionTargets = [4]string{"/inputs", "/workspace", "/outputs", "/tmp"}

func executionMounts(r executionResources) []codingidentity.VolumeMount {
	var result []codingidentity.VolumeMount
	for i, name := range r.Volumes {
		result = append(result, codingidentity.VolumeMount{Name: name, Target: executionTargets[i], ReadOnly: i == 0})
	}
	return result
}
func executionLabels(b executionBinding, a executionCreate, role string) map[string]string {
	return map[string]string{codingManagedLabel: "true", executionScopeLabel: a.digest(),
		"io.github.shell-echo.sandbox-runtime.execution-binding":  b.digest(),
		"io.github.shell-echo.sandbox-runtime.execution-protocol": executionReceiptProtocol,
		codingProfileLabel: b.Storage.ProfileDigest, codingTemplateLabel: b.Storage.TemplateDigest,
		codingSlotLabel: a.SlotID, codingRoleLabel: role}
}
func executionImageProof(b executionBinding, d phase6security.ImageDescriptorDocuments) (phase6security.ImageDescriptorProof, error) {
	// Both original candidate descriptor documents fit below this limit and
	// the allocation record's reserved envelope; oversized sources fail.
	if len(d.Index)+len(d.Manifest)+len(d.Config) > 24<<10 {
		return phase6security.ImageDescriptorProof{}, ErrInvalidCodingCompletionObservation
	}
	i := b.Template.Image
	return phase6security.VerifyImageDescriptorDocuments(i.Location, i.IdentityKind, i.Reference, i.Descriptor.Digest, i.Platform, i.SelectedManifestDigest, i.ConfigDigest, d)
}
func executionContainerLabels(b executionBinding, a executionCreate, role string, d phase6security.ImageDescriptorDocuments) (map[string]string, error) {
	if role != "resident" && role != "preparation" {
		return nil, ErrInvalidAuthority
	}
	if _, err := executionImageProof(b, d); err != nil {
		return nil, err
	}
	var config struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if json.Unmarshal(d.Config, &config) != nil {
		return nil, ErrInvalidAuthority
	}
	return mergeCodingContainerLabels(config.Config.Labels, executionLabels(b, a, role))
}
func executionVolumeOptions(b executionBinding, r executionResources, i int) map[string]string {
	if i != 3 {
		return map[string]string{}
	}
	options, _ := b.Template.Scratch.VolumeOptions(r.UID, r.GID)
	return options
}
func executionRootOwner(r executionResources, i int) (int, int, int64) {
	if i == 0 {
		return 0, 0, 0o555
	}
	if i == 3 {
		return int(r.UID), int(r.GID), 0o700
	}
	return int(r.UID), int(r.GID), 0o770
}

type executionInventoryObject struct {
	Role, Name, ID, LabelsDigest, OptionsDigest string
	Present                                     bool
	Driver, Scope                               string
}
type executionInventory struct {
	Containers [2]executionInventoryObject
	Volumes    [4]executionInventoryObject
}

func (s executionInventory) recheck(b executionBinding, a executionCreate, id string, d phase6security.ImageDescriptorDocuments) error {
	r := a.resources(b)
	labels, err := executionContainerLabels(b, a, "resident", d)
	if err != nil || s.Containers[0] != (executionInventoryObject{Role: "preparation", Name: r.Preparation}) ||
		s.Containers[1] != (executionInventoryObject{Role: "resident", Name: r.Resident, ID: id, Present: true, LabelsDigest: executionDigest("labels", labels)}) {
		return ErrInvalidCodingCompletionObservation
	}
	for i, v := range s.Volumes {
		want := executionInventoryObject{Role: executionVolumeRoles[i], Name: r.Volumes[i], ID: r.Volumes[i], Present: true, Driver: "local", Scope: "local",
			LabelsDigest: executionDigest("labels", executionLabels(b, a, executionVolumeRoles[i])), OptionsDigest: executionDigest("volume-options", executionVolumeOptions(b, r, i))}
		if v != want {
			return ErrInvalidCodingCompletionObservation
		}
	}
	return nil
}

// Retained private evidence contains no raw daemon endpoint, host mountpoint,
// inspect body or seccomp text. The locked raw OCI descriptor sources are kept
// so reopen can independently recheck their chain and inherited labels. It is
// a checked projection, not a replay of the historical Docker reads.
type executionPhysicalProof struct {
	Documents                                                     phase6security.ImageDescriptorDocuments
	DaemonBefore, DaemonAfter                                     CodingDaemonObservation
	InitialInventory, FinalInventory                              executionInventory
	InitialRuntime, FinalRuntime                                  executionRuntimeProjection
	InitialRuntimeDigest, FinalRuntimeDigest, SelectedImageDigest string
	Image                                                         phase6security.DockerImageObservation
	Roots                                                         [4]codingEmptyRootObservation
}

func (p executionPhysicalProof) recheck(b executionBinding, a executionCreate, o executionCompletionObservation) error {
	t := b.Template
	i := t.Image
	r := a.resources(b)
	descriptor, err := executionImageProof(b, p.Documents)
	if err != nil || p.DaemonBefore != p.DaemonAfter || p.DaemonBefore.IdentityDigest != b.DaemonDigest ||
		p.DaemonBefore.EnvironmentDigest != b.DaemonEnvironmentDigest || p.DaemonBefore.Platform != i.Platform ||
		p.InitialInventory != p.FinalInventory || p.InitialInventory.recheck(b, a, o.ResidentID, p.Documents) != nil ||
		!reflect.DeepEqual(p.InitialRuntime, p.FinalRuntime) {
		return ErrInvalidCodingCompletionObservation
	}
	labels, err := executionContainerLabels(b, a, "resident", p.Documents)
	if err != nil || p.InitialRuntime.recheck(b, a, o.ResidentID, labels) != nil {
		return ErrInvalidCodingCompletionObservation
	}
	started, err := time.Parse(time.RFC3339Nano, p.InitialRuntime.Common.StartedAt)
	if err != nil || started.Before(a.IssuedAt) || started.After(o.ObservedAt) {
		return ErrInvalidCodingCompletionObservation
	}
	image := p.Image
	if image.ContainerID != o.ResidentID || image.DescriptorProofDigest != descriptor.ProofDigest || image.ImageReference != i.Reference ||
		image.RuntimeStoreImageID != i.Descriptor.Digest || image.RuntimeStoreDescriptor != i.Descriptor ||
		image.SelectedManifestDescriptor.Digest != i.Descriptor.Digest || image.SelectedManifestDescriptor.Size != i.SelectedManifestSize ||
		image.SelectedManifestDescriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
		image.OCIConfigDigest != i.ConfigDigest || image.RuntimePlatform != i.Platform ||
		o.ImageEvidenceDigest != executionDigest("image-evidence", struct {
			Image    phase6security.DockerImageObservation
			Selected string
		}{image, p.SelectedImageDigest}) ||
		o.InventoryEvidenceDigest != executionDigest("inventory", p.InitialInventory) {
		return ErrInvalidCodingCompletionObservation
	}
	for _, d := range []string{p.InitialRuntimeDigest, p.FinalRuntimeDigest, p.SelectedImageDigest, image.ContainerInspectDigest, image.ImageInspectDigest} {
		if !controlDigest.MatchString(d) {
			return ErrInvalidCodingCompletionObservation
		}
	}
	for n, root := range p.Roots {
		uid, gid, mode := executionRootOwner(r, n)
		name := executionTargets[n][1:]
		if root.Target != executionTargets[n] || root.StatName != name || root.StatMode != uint32(os.ModeDir|os.FileMode(mode)) ||
			root.StatSize < 0 || root.StatSize > maxCodingArchiveResponseBytes || (root.ArchiveName != name && root.ArchiveName != name+"/") ||
			root.ArchiveUID != uid || root.ArchiveGID != gid || root.ArchiveMode != mode || root.ArchiveSize != 0 ||
			root.ArchiveDigest != o.RootEvidenceDigests[n] || !controlDigest.MatchString(root.ArchiveDigest) {
			return ErrInvalidCodingCompletionObservation
		}
	}
	return nil
}

func executionOptionsMatch(want, got map[string]string) bool { return maps.Equal(want, got) }
