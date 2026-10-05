package dockercontrol

import (
	"context"
	"encoding/json"
	"errors"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidCodingInventory = errors.New("invalid private Coding Docker resource inventory")

type CodingInventoryObject struct {
	Role    CodingResourceRole
	Name    string
	ID      string // Control-private; never a stable Provider DTO
	Present bool
	// Closed, non-host-path metadata retained for independent private proof
	// rechecks. Raw volume Mountpoint and container inspect are never kept.
	Driver       string
	Scope        string
	LabelsDigest string
	OptionsCount int
}

// CodingResourceInventory is one bounded, read-only observation. It is not
// a completion, absence, quiescence, cleanup, or release proof. In particular,
// a missing object can appear later if an old daemon request is still active.
type CodingResourceInventory struct {
	Daemon     CodingDaemonObservation
	Containers [2]CodingInventoryObject
	Volumes    [3]CodingInventoryObject
}

type codingInventoryReader interface {
	codingInfoReader
	ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	VolumeInspect(context.Context, string, client.VolumeInspectOptions) (client.VolumeInspectResult, error)
	ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error)
	VolumeList(context.Context, client.VolumeListOptions) (client.VolumeListResult, error)
}

// readCodingResourceInventory checks both exact names and an effect-label
// inventory through one already-frozen client. A foreign same-name object,
// missing/extra label, unknown effect-labelled object, API error, or daemon
// identity/environment drift fails closed. It deliberately does not inspect
// the complete runtime policy or issue any Docker mutation.
func readCodingResourceInventory(ctx context.Context, api codingInventoryReader,
	binding CodingReceiptBinding, authority CodingCreateAuthority,
	template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments) (CodingResourceInventory, error) {
	if ctx == nil || ctx.Err() != nil || api == nil || template.BindPlan(binding.Plan) != nil ||
		template.Image.Platform != binding.RuntimePlatform {
		return CodingResourceInventory{}, ErrInvalidCodingInventory
	}
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		return CodingResourceInventory{}, ErrInvalidCodingInventory
	}
	expected := make(map[CodingResourceRole]map[string]string, 2)
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		labels, err := set.ContainerLabels(role, template, documents)
		if err != nil {
			return CodingResourceInventory{}, ErrInvalidCodingInventory
		}
		expected[role] = labels
	}
	var inventory CodingResourceInventory
	daemon, err := ObserveCodingDaemonAround(ctx, api, binding, func(ctx context.Context) error {
		return readCodingInventoryObjects(ctx, api, set, expected, &inventory)
	})
	if err != nil {
		return CodingResourceInventory{}, ErrInvalidCodingInventory
	}
	inventory.Daemon = daemon
	return inventory, nil
}

func readCodingInventoryObjects(ctx context.Context, api codingInventoryReader,
	set CodingResourceSet, expected map[CodingResourceRole]map[string]string,
	inventory *CodingResourceInventory) error {
	if ctx == nil || ctx.Err() != nil || api == nil || inventory == nil ||
		len(expected) != 2 || len(expected[CodingPreparationRole]) == 0 || len(expected[CodingRuntimeRole]) == 0 {
		return ErrInvalidCodingInventory
	}
	for index, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		name, _ := set.ContainerName(role)
		item := CodingInventoryObject{Role: role, Name: name}
		observed, inspectErr := api.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if cerrdefs.IsNotFound(inspectErr) {
			inventory.Containers[index] = item
			continue
		}
		if inspectErr != nil || observed.Container.ID == "" || observed.Container.Name != "/"+name ||
			observed.Container.Config == nil ||
			matchEffectiveCodingContainerLabels(expected[role], observed.Container.Config.Labels) != nil {
			return ErrInvalidCodingInventory
		}
		labelsDigest := codingInventoryLabelsDigest(observed.Container.Config.Labels)
		if labelsDigest == "" {
			return ErrInvalidCodingInventory
		}
		item.ID, item.Present = observed.Container.ID, true
		item.LabelsDigest = labelsDigest
		inventory.Containers[index] = item
	}
	for index, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := set.VolumeName(role)
		item := CodingInventoryObject{Role: role, Name: name}
		observed, inspectErr := api.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
		if cerrdefs.IsNotFound(inspectErr) {
			inventory.Volumes[index] = item
			continue
		}
		if inspectErr != nil || observed.Volume.Name != name || observed.Volume.Driver != "local" ||
			observed.Volume.Scope != "local" ||
			len(observed.Volume.Options) != 0 || set.MatchLabels(role, observed.Volume.Labels) != nil {
			return ErrInvalidCodingInventory
		}
		labelsDigest := codingInventoryLabelsDigest(observed.Volume.Labels)
		if labelsDigest == "" {
			return ErrInvalidCodingInventory
		}
		item.ID, item.Present = name, true
		item.Driver, item.Scope = observed.Volume.Driver, observed.Volume.Scope
		item.LabelsDigest = labelsDigest
		item.OptionsCount = len(observed.Volume.Options)
		inventory.Volumes[index] = item
	}
	filters := make(client.Filters).Add("label", codingEffectLabel+"="+set.effectID)
	containers, listErr := api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if listErr != nil {
		return ErrInvalidCodingInventory
	}
	seenContainers := map[CodingResourceRole]bool{}
	for _, item := range containers.Items {
		matched := false
		for _, want := range inventory.Containers {
			if want.Present && item.ID == want.ID && len(item.Names) == 1 && item.Names[0] == "/"+want.Name &&
				matchCodingContainerListLabels(expected[want.Role], item.Labels) == nil && !seenContainers[want.Role] {
				seenContainers[want.Role], matched = true, true
				break
			}
		}
		if !matched {
			return ErrInvalidCodingInventory
		}
	}
	for _, want := range inventory.Containers {
		if want.Present != seenContainers[want.Role] {
			return ErrInvalidCodingInventory
		}
	}
	volumes, listErr := api.VolumeList(ctx, client.VolumeListOptions{Filters: filters})
	if listErr != nil || len(volumes.Warnings) != 0 {
		return ErrInvalidCodingInventory
	}
	seenVolumes := map[CodingResourceRole]bool{}
	for _, item := range volumes.Items {
		matched := false
		for _, want := range inventory.Volumes {
			if want.Present && item.Name == want.Name && item.Driver == "local" && item.Scope == "local" &&
				len(item.Options) == 0 && set.MatchLabels(want.Role, item.Labels) == nil &&
				!seenVolumes[want.Role] {
				seenVolumes[want.Role], matched = true, true
				break
			}
		}
		if !matched {
			return ErrInvalidCodingInventory
		}
	}
	for _, want := range inventory.Volumes {
		if want.Present != seenVolumes[want.Role] {
			return ErrInvalidCodingInventory
		}
	}
	return nil
}

// The exact container inspect is the authority for image-inherited and
// Control labels. Docker Desktop 29.7.2 adds this one informational key in
// its container-list projection but not in Config.Labels. The list is still
// an exact whole-effect ID/name cross-check; no arbitrary extra labels are
// accepted, and this key/value is never included in ownership proof.
func matchCodingContainerListLabels(expected, listed map[string]string) error {
	if len(expected) == 0 || len(listed) < len(expected) || len(listed) > len(expected)+1 {
		return ErrInvalidCodingInventory
	}
	for key, value := range expected {
		if actual, present := listed[key]; !present || actual != value {
			return ErrInvalidCodingInventory
		}
	}
	if len(listed) == len(expected) {
		return nil
	}
	if _, expectedKey := expected["desktop.docker.io/ports.scheme"]; expectedKey {
		return ErrInvalidCodingInventory
	}
	value, present := listed["desktop.docker.io/ports.scheme"]
	if !present || len(value) > 4096 {
		return ErrInvalidCodingInventory
	}
	return nil
}

func codingInventoryLabelsDigest(labels map[string]string) string {
	document, err := json.Marshal(labels)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-labels/v1\x00"), document...))
}
