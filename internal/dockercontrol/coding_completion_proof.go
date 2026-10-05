package dockercontrol

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// codingRuntimeSecurityProjection retains only fields needed to independently
// recheck the observed runtime against the frozen template. It intentionally
// excludes Docker host paths, raw seccomp text, storage diagnostics, endpoint
// addresses, and daemon-owned container filesystem sources.
type codingRuntimeSecurityProjection struct {
	ID, Name, ImageID, ManifestDigest, ManifestMediaType, ManifestPlatform string
	ManifestSize                                                           int64
	StateStatus, StartedAt, StateError                                     string
	Running, Paused, Restarting, OOMKilled, Dead                           bool
	PID, ExitCode, RestartCount, ExecIDsCount                              int
	ConfigImage, User, WorkingDir                                          string
	CommandDigest, EnvironmentDigest, LabelsDigest                         string
	EntrypointCount, ConfigVolumesCount, ExposedPortsCount                 int
	Healthcheck, AttachStdin, AttachStdout, AttachStderr                   bool
	OpenStdin, StdinOnce, TTY                                              bool
	NetworkMode, RestartPolicy, Runtime                                    string
	ReadonlyRootfs, Privileged, PublishAllPorts, AutoRemove                bool
	CapDrop                                                                []string
	CapAddCount, GroupAddCount                                             int
	SecurityOptionsDigest, TmpfsDigest                                     string
	Memory, MemorySwap, NanoCPUs, PIDs                                     int64
	PidMode, IpcMode, UTSMode, UsernsMode, CgroupnsMode, Cgroup            string
	BindsCount, DevicesCount, DeviceRequestsCount, DeviceRulesCount        int
	VolumesFromCount, PortBindingsCount, LinksCount, ExtraHostsCount       int
	SysctlsCount, StorageOptionsCount                                      int
	VolumeDriver, ContainerIDFile                                          string
	ConfiguredMounts                                                       []codingSafeMount
	RealizedMounts                                                         []codingSafeMount
	NetworkNames                                                           []string
	NetworkPortsCount                                                      int
}

type codingSafeMount struct {
	Type, Name, Target, Consistency string
	ReadOnly, NoCopy                bool
	ExtraOptionsCount               int
}

func projectCodingRuntimeSecurity(observed container.InspectResponse) (codingRuntimeSecurityProjection, error) {
	if observed.State == nil || observed.Config == nil || observed.HostConfig == nil ||
		observed.NetworkSettings == nil || observed.ImageManifestDescriptor == nil ||
		observed.ImageManifestDescriptor.Platform == nil || observed.HostConfig.PidsLimit == nil {
		return codingRuntimeSecurityProjection{}, ErrInvalidCodingCompletionObservation
	}
	host, config, state := observed.HostConfig, observed.Config, observed.State
	projection := codingRuntimeSecurityProjection{
		ID: observed.ID, Name: observed.Name, ImageID: observed.Image,
		ManifestDigest:    observed.ImageManifestDescriptor.Digest.String(),
		ManifestMediaType: observed.ImageManifestDescriptor.MediaType,
		ManifestSize:      observed.ImageManifestDescriptor.Size,
		ManifestPlatform: fmt.Sprintf("%s/%s/%s", observed.ImageManifestDescriptor.Platform.OS,
			observed.ImageManifestDescriptor.Platform.Architecture,
			observed.ImageManifestDescriptor.Platform.Variant),
		StateStatus: string(state.Status), StartedAt: state.StartedAt, StateError: state.Error,
		Running: state.Running, Paused: state.Paused, Restarting: state.Restarting,
		OOMKilled: state.OOMKilled, Dead: state.Dead, PID: state.Pid,
		ExitCode: state.ExitCode, RestartCount: observed.RestartCount, ExecIDsCount: len(observed.ExecIDs),
		ConfigImage: config.Image, User: config.User, WorkingDir: config.WorkingDir,
		CommandDigest:     codingProjectionDigest("command", config.Cmd),
		EnvironmentDigest: codingProjectionDigest("environment", config.Env),
		LabelsDigest:      codingProjectionDigest("labels", config.Labels),
		EntrypointCount:   len(config.Entrypoint), ConfigVolumesCount: len(config.Volumes),
		ExposedPortsCount: len(config.ExposedPorts), Healthcheck: config.Healthcheck != nil,
		AttachStdin: config.AttachStdin, AttachStdout: config.AttachStdout,
		AttachStderr: config.AttachStderr, OpenStdin: config.OpenStdin,
		StdinOnce: config.StdinOnce, TTY: config.Tty,
		NetworkMode: string(host.NetworkMode), RestartPolicy: string(host.RestartPolicy.Name),
		Runtime: host.Runtime, ReadonlyRootfs: host.ReadonlyRootfs, Privileged: host.Privileged,
		PublishAllPorts: host.PublishAllPorts, AutoRemove: host.AutoRemove,
		CapDrop: slices.Clone(host.CapDrop), CapAddCount: len(host.CapAdd), GroupAddCount: len(host.GroupAdd),
		SecurityOptionsDigest: codingProjectionDigest("security-options", host.SecurityOpt),
		TmpfsDigest:           codingProjectionDigest("tmpfs", host.Tmpfs),
		Memory:                host.Memory, MemorySwap: host.MemorySwap, NanoCPUs: host.NanoCPUs,
		PIDs:    *host.PidsLimit,
		PidMode: string(host.PidMode), IpcMode: string(host.IpcMode), UTSMode: string(host.UTSMode),
		UsernsMode: string(host.UsernsMode), CgroupnsMode: string(host.CgroupnsMode),
		Cgroup: string(host.Cgroup), BindsCount: len(host.Binds), DevicesCount: len(host.Devices),
		DeviceRequestsCount: len(host.DeviceRequests), DeviceRulesCount: len(host.DeviceCgroupRules),
		VolumesFromCount: len(host.VolumesFrom), PortBindingsCount: len(host.PortBindings),
		LinksCount: len(host.Links), ExtraHostsCount: len(host.ExtraHosts),
		SysctlsCount: len(host.Sysctls), StorageOptionsCount: len(host.StorageOpt),
		VolumeDriver: host.VolumeDriver, ContainerIDFile: host.ContainerIDFile,
		NetworkPortsCount: len(observed.NetworkSettings.Ports),
	}
	for name := range observed.NetworkSettings.Networks {
		projection.NetworkNames = append(projection.NetworkNames, name)
	}
	sort.Strings(projection.NetworkNames)
	for _, configured := range host.Mounts {
		entry := codingSafeMount{Type: string(configured.Type), Name: configured.Source,
			Target: configured.Target, ReadOnly: configured.ReadOnly,
			Consistency: string(configured.Consistency)}
		if configured.VolumeOptions != nil {
			entry.NoCopy = configured.VolumeOptions.NoCopy
			entry.ExtraOptionsCount += len(configured.VolumeOptions.Labels)
			if configured.VolumeOptions.Subpath != "" {
				entry.ExtraOptionsCount++
			}
			if configured.VolumeOptions.DriverConfig != nil {
				entry.ExtraOptionsCount++
			}
		}
		for _, extra := range []bool{configured.BindOptions != nil, configured.ImageOptions != nil,
			configured.TmpfsOptions != nil, configured.ClusterOptions != nil} {
			if extra {
				entry.ExtraOptionsCount++
			}
		}
		projection.ConfiguredMounts = append(projection.ConfiguredMounts, entry)
	}
	for _, realized := range observed.Mounts {
		projection.RealizedMounts = append(projection.RealizedMounts, codingSafeMount{
			Type: string(realized.Type), Name: realized.Name, Target: realized.Destination,
			ReadOnly: !realized.RW})
	}
	return projection, nil
}

func codingProjectionDigest(domain string, value any) string {
	document, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-projection-"+domain+"/v1\x00"), document...))
}

func codingProjectionPlatformMatches(observed, expected string) bool {
	switch expected {
	case "linux/arm64/v8":
		return observed == "linux/arm64/v8" || observed == "linux/arm64/"
	case "linux/amd64":
		return observed == "linux/amd64/"
	default:
		return false
	}
}

func (p codingRuntimeSecurityProjection) recheck(id, name string,
	labels map[string]string, template phase6security.CodingRuntimeTemplateV2,
	slot codingidentity.Slot, mounts []codingidentity.VolumeMount, policy []byte) error {
	startedAt, err := time.Parse(time.RFC3339Nano, p.StartedAt)
	if err != nil || startedAt.IsZero() || p.ID != id || p.Name != "/"+name ||
		p.ImageID != template.Image.Descriptor.Digest ||
		p.ManifestDigest != template.Image.SelectedManifestDigest ||
		p.ManifestMediaType != "application/vnd.oci.image.manifest.v1+json" ||
		p.ManifestSize != template.Image.SelectedManifestSize ||
		!codingProjectionPlatformMatches(p.ManifestPlatform, template.Image.Platform) ||
		p.StateStatus != "running" || !p.Running || p.Paused || p.Restarting ||
		p.OOMKilled || p.Dead || p.PID <= 0 || p.ExitCode != 0 || p.StateError != "" ||
		p.RestartCount != 0 || p.ExecIDsCount != 0 ||
		p.ConfigImage != template.Image.Reference ||
		p.User != fmt.Sprintf("%d:%d", slot.WorkloadUID, slot.WorkloadGID) ||
		p.WorkingDir != template.WorkingDirectory ||
		p.CommandDigest != codingProjectionDigest("command", template.Command) ||
		p.EnvironmentDigest != codingProjectionDigest("environment", template.Environment) ||
		p.LabelsDigest != codingProjectionDigest("labels", labels) ||
		p.EntrypointCount != 0 || p.ConfigVolumesCount != 0 || p.ExposedPortsCount != 0 ||
		p.Healthcheck || p.AttachStdin || p.AttachStdout || p.AttachStderr || p.OpenStdin ||
		p.StdinOnce || p.TTY || p.NetworkMode != "none" || p.RestartPolicy != "no" ||
		!p.ReadonlyRootfs || p.Privileged || p.PublishAllPorts || p.AutoRemove ||
		!slices.Equal(p.CapDrop, []string{"ALL"}) || p.CapAddCount != 0 || p.GroupAddCount != 0 ||
		p.SecurityOptionsDigest != codingProjectionDigest("security-options",
			[]string{"no-new-privileges:true", "seccomp=" + string(policy)}) ||
		p.TmpfsDigest != codingProjectionDigest("tmpfs", map[string]string{"/tmp": fmt.Sprintf(
			"rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=%d,gid=%d",
			template.TmpfsBytes, slot.WorkloadUID, slot.WorkloadGID)}) ||
		p.Memory != template.Limits.MemoryBytes || p.MemorySwap != template.Limits.MemoryBytes ||
		p.NanoCPUs != template.Limits.CPUMillis*1_000_000 || p.PIDs != template.Limits.PIDs ||
		p.PidMode != "" || p.IpcMode != "" && p.IpcMode != string(container.IPCModePrivate) ||
		p.UTSMode != "" || p.UsernsMode != "" ||
		p.CgroupnsMode != "" && p.CgroupnsMode != string(container.CgroupnsModePrivate) ||
		p.Cgroup != "" || p.BindsCount != 0 || p.DevicesCount != 0 ||
		p.DeviceRequestsCount != 0 || p.DeviceRulesCount != 0 || p.VolumesFromCount != 0 ||
		p.PortBindingsCount != 0 || p.LinksCount != 0 || p.ExtraHostsCount != 0 ||
		p.SysctlsCount != 0 || p.StorageOptionsCount != 0 ||
		p.Runtime != "" && p.Runtime != "runc" || p.VolumeDriver != "" ||
		p.ContainerIDFile != "" || !slices.Equal(p.NetworkNames, []string{"none"}) ||
		p.NetworkPortsCount != 0 || len(p.ConfiguredMounts) != len(mounts) {
		return ErrInvalidCodingCompletionObservation
	}
	for index, expected := range mounts {
		want := codingSafeMount{Type: string(mount.TypeVolume), Name: expected.Name,
			Target: expected.Target, ReadOnly: expected.ReadOnly, NoCopy: true}
		actual := p.ConfiguredMounts[index]
		if actual.Consistency == string(mount.ConsistencyDefault) {
			actual.Consistency = ""
		}
		if actual != want {
			return ErrInvalidCodingCompletionObservation
		}
	}
	// Docker may include the private tmpfs in the realized list, but cannot
	// substitute a fourth volume or host bind for any of the three roots.
	seen := map[string]bool{}
	tmpfsCount := 0
	for _, actual := range p.RealizedMounts {
		if actual.Type == string(mount.TypeTmpfs) && actual.Target == "/tmp" &&
			actual.Name == "" && !actual.ReadOnly {
			tmpfsCount++
			if tmpfsCount > 1 {
				return ErrInvalidCodingCompletionObservation
			}
			continue
		}
		matched := false
		for _, expected := range mounts {
			if actual == (codingSafeMount{Type: string(mount.TypeVolume), Name: expected.Name,
				Target: expected.Target, ReadOnly: expected.ReadOnly}) && !seen[expected.Target] {
				seen[expected.Target], matched = true, true
				break
			}
		}
		if !matched {
			return ErrInvalidCodingCompletionObservation
		}
	}
	if len(p.RealizedMounts) != len(mounts)+tmpfsCount ||
		len(seen) != len(mounts) || !maps.Equal(seen, map[string]bool{
		"/inputs": true, "/workspace": true, "/outputs": true}) {
		return ErrInvalidCodingCompletionObservation
	}
	return nil
}

// recheck validates the compact, Control-private physical proof without
// trusting an input completion digest. It intentionally does not update a
// receipt: the durable state transition needs a separate current-revision CAS
// and late-effect fencing gate that do not exist in this component.
func (p codingCompletionObservation) recheck(binding CodingReceiptBinding,
	authority CodingCreateAuthority, template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments, policy []byte) error {
	if binding.Validate() != nil || template.BindPlan(binding.Plan) != nil ||
		p.ReceiptRevision == 0 || p.AuthorityDigest != authority.Digest() ||
		p.EffectID != authority.EffectID || p.ProfileDigest != binding.ProfileDigest ||
		p.PlanDigest != binding.PlanDigest || p.TemplateDigest != binding.Plan.TemplateDigest ||
		p.Daemon.MatchBinding(binding) != nil || p.Daemon.Platform != template.Image.Platform ||
		p.InitialInventory.Daemon != p.Daemon || p.FinalInventory.Daemon != p.Daemon ||
		p.InitialInventory.Containers != p.FinalInventory.Containers ||
		p.InitialInventory.Volumes != p.FinalInventory.Volumes ||
		!codingArchiveRuntimeID.MatchString(p.RuntimeID) ||
		p.InitialInventory.Containers[0].Present ||
		!p.InitialInventory.Containers[1].Present ||
		p.InitialInventory.Containers[1].ID != p.RuntimeID ||
		!controlDigest.MatchString(p.InitialRuntimeDigest) ||
		!controlDigest.MatchString(p.FinalRuntimeDigest) ||
		!controlDigest.MatchString(p.SelectedImageDigest) {
		return ErrInvalidCodingCompletionObservation
	}
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		return ErrInvalidCodingCompletionObservation
	}
	runtimeName, _ := set.ContainerName(CodingRuntimeRole)
	prepName, _ := set.ContainerName(CodingPreparationRole)
	runtimeLabels, err := set.ContainerLabels(CodingRuntimeRole, template, documents)
	if err != nil {
		return ErrInvalidCodingCompletionObservation
	}
	prep := p.InitialInventory.Containers[0]
	runtime := p.InitialInventory.Containers[1]
	if prep.Role != CodingPreparationRole || prep.Name != prepName || prep.ID != "" ||
		prep.LabelsDigest != "" || runtime.Role != CodingRuntimeRole ||
		runtime.Name != runtimeName || runtime.LabelsDigest != codingInventoryLabelsDigest(runtimeLabels) {
		return ErrInvalidCodingCompletionObservation
	}
	var slot codingidentity.Slot
	for _, candidate := range template.Slots {
		if candidate.ID == authority.SlotID {
			slot = candidate
		}
	}
	if slot.ID == "" {
		return ErrInvalidCodingCompletionObservation
	}
	mounts := set.Mounts()
	for index, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		wantName, _ := set.VolumeName(role)
		wantLabels, _ := set.Labels(role)
		item := p.InitialInventory.Volumes[index]
		if !item.Present || item.Role != role || item.Name != wantName || item.ID != wantName ||
			item.Driver != "local" || item.Scope != "local" || item.OptionsCount != 0 ||
			item.LabelsDigest != codingInventoryLabelsDigest(wantLabels) {
			return ErrInvalidCodingCompletionObservation
		}
		root := p.ArchiveRoots[index]
		uid, gid, mode := int(slot.WorkloadUID), int(slot.WorkloadGID), int64(template.VolumePrepMode)
		if index == 0 {
			uid, gid, mode = 0, 0, 0o555
		}
		wantRootName := mounts[index].Target[1:]
		if root.Target != mounts[index].Target || root.StatName != wantRootName ||
			root.StatMode != uint32(os.ModeDir|os.FileMode(mode)) ||
			root.StatSize < 0 || root.StatSize > maxCodingArchiveResponseBytes ||
			root.ArchiveName != wantRootName && root.ArchiveName != wantRootName+"/" ||
			root.ArchiveUID != uid || root.ArchiveGID != gid || root.ArchiveMode != mode ||
			root.ArchiveSize != 0 || !controlDigest.MatchString(root.ArchiveDigest) ||
			root.ArchiveDigest != p.ArchiveDigests[index] {
			return ErrInvalidCodingCompletionObservation
		}
	}
	if p.InitialRuntime.recheck(p.RuntimeID, runtimeName, runtimeLabels,
		template, slot, mounts, policy) != nil ||
		p.FinalRuntime.recheck(p.RuntimeID, runtimeName, runtimeLabels,
			template, slot, mounts, policy) != nil ||
		!reflect.DeepEqual(p.InitialRuntime, p.FinalRuntime) {
		return ErrInvalidCodingCompletionObservation
	}
	descriptorProof, err := phase6security.VerifyImageDescriptorDocuments(
		template.Image.Location, template.Image.IdentityKind, template.Image.Reference,
		template.Image.Descriptor.Digest, template.Image.Platform,
		template.Image.SelectedManifestDigest, template.Image.ConfigDigest, documents)
	if err != nil || p.ImageDescriptorProof != descriptorProof.ProofDigest ||
		p.Image.DescriptorProofDigest != descriptorProof.ProofDigest ||
		p.Image.ContainerID != p.RuntimeID ||
		p.Image.ImageReference != template.Image.Reference ||
		p.Image.RuntimeStoreImageID != template.Image.Descriptor.Digest ||
		p.Image.RuntimeStoreDescriptor.Digest != template.Image.Descriptor.Digest ||
		p.Image.RuntimeStoreDescriptor.Size != template.Image.Descriptor.Size ||
		p.Image.SelectedManifestDescriptor.Digest != template.Image.SelectedManifestDigest ||
		p.Image.SelectedManifestDescriptor.Size != template.Image.SelectedManifestSize ||
		p.Image.OCIConfigDigest != template.Image.ConfigDigest ||
		p.Image.RuntimePlatform != template.Image.Platform ||
		p.ImageInspectDigest != p.Image.ImageInspectDigest {
		return ErrInvalidCodingCompletionObservation
	}
	inventoryDocument, err := json.Marshal(p.InitialInventory)
	if err != nil || p.ExactInventoryDigest != digest(append(
		[]byte("sandbox-runtime/docker-control-coding-inventory/v1\x00"), inventoryDocument...)) {
		return ErrInvalidCodingCompletionObservation
	}
	copy := p
	copy.CompletionDigest = ""
	proofDocument, err := json.Marshal(copy)
	if err != nil || p.CompletionDigest != digest(append(
		[]byte("sandbox-runtime/docker-control-coding-completion/v1\x00"), proofDocument...)) {
		return ErrInvalidCodingCompletionObservation
	}
	return nil
}
