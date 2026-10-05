package dockercontrol

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// codingRuntimeConfigurationDigest excludes only mutable process state. The
// image identity, users, command/environment, labels, namespace, mounts,
// network, seccomp and resource limits remain bound to the completion proof.
// The projection contains no raw host paths or Docker endpoint.
func codingRuntimeConfigurationDigest(projection codingRuntimeSecurityProjection) string {
	realized, ok := canonicalCodingRealizedMounts(projection)
	if !ok {
		return ""
	}
	// Docker may omit the otherwise-verified private /tmp tmpfs from an
	// exited container's realized view. Normalize only that optional entry
	// and the semantically irrelevant realized-list order. Configured mounts,
	// HostConfig.Tmpfs and every other frozen field remain in the digest.
	projection.RealizedMounts = realized
	projection.StateStatus = ""
	projection.StartedAt = ""
	projection.StateError = ""
	projection.Running = false
	projection.Paused = false
	projection.Restarting = false
	projection.OOMKilled = false
	projection.Dead = false
	projection.PID = 0
	projection.ExitCode = 0
	return codingProjectionDigest("release-runtime-configuration", projection)
}

func canonicalCodingRealizedMounts(projection codingRuntimeSecurityProjection) ([]codingSafeMount, bool) {
	if len(projection.ConfiguredMounts) != 3 || len(projection.RealizedMounts) < 3 ||
		len(projection.RealizedMounts) > 4 {
		return nil, false
	}
	wants := make(map[string]codingSafeMount, 3)
	for _, configured := range projection.ConfiguredMounts {
		if configured.Type != "volume" || configured.Name == "" ||
			(configured.Target != "/inputs" && configured.Target != "/workspace" &&
				configured.Target != "/outputs") ||
			wants[configured.Target].Target != "" {
			return nil, false
		}
		wants[configured.Target] = codingSafeMount{Type: "volume", Name: configured.Name,
			Target: configured.Target, ReadOnly: configured.ReadOnly}
	}
	var roots []codingSafeMount
	tmpfsCount := 0
	for _, actual := range projection.RealizedMounts {
		if actual == (codingSafeMount{Type: "tmpfs", Target: "/tmp"}) {
			tmpfsCount++
			if tmpfsCount > 1 {
				return nil, false
			}
			continue
		}
		want, exists := wants[actual.Target]
		if !exists || actual != want {
			return nil, false
		}
		roots = append(roots, actual)
		delete(wants, actual.Target)
	}
	if len(wants) != 0 || len(roots) != 3 {
		return nil, false
	}
	slices.SortFunc(roots, func(left, right codingSafeMount) int {
		return strings.Compare(left.Target, right.Target)
	})
	return roots, true
}

// A stopped runtime is still a valid cleanup target if its immutable
// configuration remains the completed effect's exact frozen configuration.
// Reuse the full runtime projection checker after normalizing only its
// mutable process state; never normalize config, privilege, mounts or image.
func (projection codingRuntimeSecurityProjection) recheckDeletionConfiguration(id, name string,
	labels map[string]string, template phase6security.CodingRuntimeTemplateV2,
	slot codingidentity.Slot, mounts []codingidentity.VolumeMount, policy []byte) error {
	switch projection.StateStatus {
	case "running":
		if !projection.Running || projection.PID <= 0 || projection.Paused ||
			projection.Restarting || projection.Dead {
			return ErrInvalidCodingInventory
		}
	case "exited":
		if projection.Running || projection.PID != 0 || projection.Paused ||
			projection.Restarting || projection.Dead {
			return ErrInvalidCodingInventory
		}
	default:
		return ErrInvalidCodingInventory
	}
	configured := projection
	configured.StateStatus = "running"
	configured.Running = true
	configured.PID = 1
	configured.Paused = false
	configured.Restarting = false
	configured.OOMKilled = false
	configured.Dead = false
	configured.ExitCode = 0
	configured.StateError = ""
	if configured.recheck(id, name, labels, template, slot, mounts, policy) != nil {
		return ErrInvalidCodingInventory
	}
	return nil
}

// readDeletePreflight uses the one existing frozen GET-only client and one
// absolute 10-second budget spanning gate admission, full effect inventory,
// exact runtime inspect and daemon identity brackets. It does not rerun the
// initial empty-root/OCI export completion chain: workspace and outputs may
// legitimately contain tenant data by the time a runtime is retired.
func (o *codingUnixObserver) readDeletePreflight(ctx context.Context,
	runtimeID string) (CodingResourceInventory, codingRuntimeSecurityProjection, error) {
	if o == nil || ctx == nil || ctx.Err() != nil || !codingArchiveRuntimeID.MatchString(runtimeID) ||
		o.bounded == nil || o.binding.Validate() != nil ||
		o.template.BindPlan(o.binding.Plan) != nil {
		return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
	}
	boundedCtx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if !o.acquire(boundedCtx) {
		return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
	}
	defer o.release()
	// CloseContext mutates api under this same gate. Checking it before
	// admission races Close and can turn a queued preflight into a nil call.
	if o.api == nil || boundedCtx.Err() != nil {
		return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
	}
	set, err := NewCodingResourceSet(o.binding, o.authority)
	if err != nil {
		return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
	}
	expected := make(map[CodingResourceRole]map[string]string, 2)
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		expected[role], err = set.ContainerLabels(role, o.template, o.documents)
		if err != nil {
			return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
		}
	}
	runtimeName, err := set.ContainerName(CodingRuntimeRole)
	if err != nil {
		return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
	}
	var slot codingidentity.Slot
	for _, candidate := range o.template.Slots {
		if candidate.ID == o.authority.SlotID {
			slot = candidate
		}
	}
	if slot.ID == "" {
		return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
	}
	var inventory CodingResourceInventory
	var projection codingRuntimeSecurityProjection
	daemon, err := ObserveCodingDaemonAround(boundedCtx, o.api, o.binding,
		func(work context.Context) error {
			if readCodingInventoryObjects(work, o.api, set, expected, &inventory) != nil ||
				inventory.Containers[0].Present || !inventory.Containers[1].Present ||
				inventory.Containers[1].ID != runtimeID {
				return ErrInvalidCodingInventory
			}
			inspected, inspectErr := o.api.ContainerInspect(work, runtimeName,
				client.ContainerInspectOptions{})
			if inspectErr != nil || inspected.Container.ID != runtimeID ||
				inspected.Container.Name != "/"+runtimeName ||
				inspected.Container.Config == nil ||
				matchEffectiveCodingContainerLabels(expected[CodingRuntimeRole],
					inspected.Container.Config.Labels) != nil ||
				codingProbeContainerMismatch(inspected.Container, o.template, slot,
					set.Mounts(), fmt.Sprintf("%d:%d", slot.WorkloadUID, slot.WorkloadGID),
					string(o.policy), codingProbeRuntime) != "" {
				return ErrInvalidCodingInventory
			}
			projection, inspectErr = projectCodingRuntimeSecurity(inspected.Container)
			if inspectErr != nil || projection.recheckDeletionConfiguration(runtimeID,
				runtimeName, expected[CodingRuntimeRole], o.template, slot, set.Mounts(),
				o.policy) != nil {
				return ErrInvalidCodingInventory
			}
			return nil
		})
	if err != nil || boundedCtx.Err() != nil {
		return CodingResourceInventory{}, codingRuntimeSecurityProjection{}, ErrInvalidCodingInventory
	}
	inventory.Daemon = daemon
	return inventory, projection, nil
}
