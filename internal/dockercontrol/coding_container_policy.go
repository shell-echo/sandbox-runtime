package dockercontrol

import (
	"fmt"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// The stopped-carrier and runtime projections are shared by the original
// real-daemon mechanism probe and the private production observation source.
type codingProbePhase string

const (
	codingProbePreparation codingProbePhase = "preparation"
	codingProbeRuntime     codingProbePhase = "runtime"
)

// Report only closed field names: never include the seccomp body, volume
// source, raw daemon response, or host-local paths in a mismatch.
func codingProbeContainerMismatch(observed container.InspectResponse,
	template phase6security.CodingRuntimeTemplateV2, slot codingidentity.Slot,
	mounts []codingidentity.VolumeMount, user, policy string, phase codingProbePhase) string {
	if observed.Config == nil || observed.HostConfig == nil {
		return "Config/HostConfig absent"
	}
	if phase != codingProbePreparation && phase != codingProbeRuntime {
		return "phase invalid"
	}
	var mismatches []string
	add := func(condition bool, field string) {
		if condition {
			mismatches = append(mismatches, field)
		}
	}
	add(observed.Image != template.Image.Descriptor.Digest, "Image store index ID")
	add(observed.ImageManifestDescriptor == nil ||
		observed.ImageManifestDescriptor.Digest.String() != template.Image.SelectedManifestDigest ||
		observed.ImageManifestDescriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
		observed.ImageManifestDescriptor.Size != template.Image.SelectedManifestSize ||
		observed.ImageManifestDescriptor.Platform == nil ||
		!codingSelectedPlatformMatches(observed.ImageManifestDescriptor.Platform.OS,
			observed.ImageManifestDescriptor.Platform.Architecture,
			observed.ImageManifestDescriptor.Platform.Variant, template.Image.Platform), "Image selected manifest")
	add(observed.Config.Image != template.Image.Reference, "Config.Image")
	add(observed.Config.User != user, "Config.User")
	add(observed.Config.WorkingDir != template.WorkingDirectory, "Config.WorkingDir")
	expectedCommand := template.Command
	if phase == codingProbePreparation {
		expectedCommand = []string{"/bin/false"}
	}
	add(!slices.Equal(observed.Config.Cmd, expectedCommand), "Config.Cmd")
	add(!slices.Equal(observed.Config.Env, template.Environment), "Config.Env")
	add(len(observed.Config.Entrypoint) != 0, "Config.Entrypoint")
	add(len(observed.Config.Volumes) != 0, "Config.Volumes")
	add(observed.Config.Healthcheck != nil, "Config.Healthcheck")
	add(observed.Config.AttachStdin || observed.Config.AttachStdout || observed.Config.AttachStderr ||
		observed.Config.OpenStdin || observed.Config.StdinOnce || observed.Config.Tty ||
		len(observed.Config.ExposedPorts) != 0, "Config interactive/ports")
	add(observed.HostConfig.NetworkMode != container.NetworkMode("none"), "HostConfig.NetworkMode")
	add(observed.HostConfig.ReadonlyRootfs != (phase == codingProbeRuntime) ||
		observed.HostConfig.Privileged, "HostConfig root privilege")
	add(observed.HostConfig.RestartPolicy.Name != "no", "HostConfig.RestartPolicy")
	add(!slices.Equal(observed.HostConfig.CapDrop, []string{"ALL"}) || len(observed.HostConfig.CapAdd) != 0,
		"HostConfig capabilities")
	add(!slices.Equal(observed.HostConfig.SecurityOpt, []string{"no-new-privileges:true", "seccomp=" + policy}),
		"HostConfig.SecurityOpt")
	add(observed.HostConfig.Memory != template.Limits.MemoryBytes ||
		observed.HostConfig.MemorySwap != template.Limits.MemoryBytes ||
		observed.HostConfig.NanoCPUs != template.Limits.CPUMillis*1_000_000 ||
		observed.HostConfig.PidsLimit == nil || *observed.HostConfig.PidsLimit != template.Limits.PIDs,
		"HostConfig.Resources")
	add(len(observed.HostConfig.Mounts) != len(mounts), "HostConfig.Mounts count")
	add(len(observed.HostConfig.Tmpfs) != 1 ||
		observed.HostConfig.Tmpfs["/tmp"] != fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=%d,gid=%d",
			template.TmpfsBytes, slot.WorkloadUID, slot.WorkloadGID), "HostConfig.Tmpfs")
	add(len(observed.HostConfig.Binds) != 0 || len(observed.HostConfig.Devices) != 0,
		"HostConfig extra host access")
	// Docker may materialize empty create-time namespace modes as "private".
	// Host/container sharing and every secondary privilege or data route are
	// not part of the frozen create options, regardless of that normalization.
	add(len(observed.HostConfig.GroupAdd) != 0, "HostConfig.GroupAdd")
	add(observed.HostConfig.PidMode != "" ||
		(observed.HostConfig.IpcMode != "" && observed.HostConfig.IpcMode != container.IPCModePrivate) ||
		observed.HostConfig.UTSMode != "" || observed.HostConfig.UsernsMode != "" ||
		(observed.HostConfig.CgroupnsMode != "" && observed.HostConfig.CgroupnsMode != container.CgroupnsModePrivate) ||
		observed.HostConfig.Cgroup != "", "HostConfig namespaces")
	add(len(observed.HostConfig.DeviceRequests) != 0 || len(observed.HostConfig.DeviceCgroupRules) != 0 ||
		len(observed.HostConfig.VolumesFrom) != 0, "HostConfig secondary device/volume access")
	add(len(observed.HostConfig.PortBindings) != 0 || observed.HostConfig.PublishAllPorts ||
		len(observed.HostConfig.Links) != 0 || len(observed.HostConfig.ExtraHosts) != 0,
		"HostConfig secondary network access")
	add(len(observed.HostConfig.Sysctls) != 0 ||
		(observed.HostConfig.Runtime != "" && observed.HostConfig.Runtime != "runc") ||
		len(observed.HostConfig.StorageOpt) != 0 || observed.HostConfig.VolumeDriver != "" ||
		observed.HostConfig.ContainerIDFile != "" || observed.HostConfig.AutoRemove,
		"HostConfig runtime/system overrides")
	if len(observed.HostConfig.Mounts) == len(mounts) {
		for index, want := range mounts {
			configured := observed.HostConfig.Mounts[index]
			add(configured.Type != mount.TypeVolume || configured.Source != want.Name ||
				configured.Target != want.Target || configured.ReadOnly != want.ReadOnly ||
				(configured.Consistency != "" && configured.Consistency != mount.ConsistencyDefault) ||
				configured.BindOptions != nil || configured.ImageOptions != nil ||
				configured.TmpfsOptions != nil || configured.ClusterOptions != nil ||
				(phase == codingProbeRuntime && (configured.VolumeOptions == nil || !configured.VolumeOptions.NoCopy)) ||
				(phase == codingProbePreparation && configured.VolumeOptions != nil && configured.VolumeOptions.NoCopy) ||
				(configured.VolumeOptions != nil && (configured.VolumeOptions.Subpath != "" ||
					len(configured.VolumeOptions.Labels) != 0 || configured.VolumeOptions.DriverConfig != nil)),
				fmt.Sprintf("HostConfig.Mounts[%d]", index))
		}
	}
	for index, want := range mounts {
		found := false
		for _, actual := range observed.Mounts {
			if actual.Destination == want.Target && actual.Type == mount.TypeVolume &&
				actual.Name == want.Name && actual.RW == !want.ReadOnly {
				found = true
			}
		}
		add(!found, fmt.Sprintf("Mounts[%d]", index))
	}
	// The daemon may omit a configured tmpfs from a stopped container's
	// realized Mounts view. HostConfig.Tmpfs is checked above and an actual
	// /tmp write is checked after start; all reported Mounts must be known.
	tmpfsCount := 0
	for _, actual := range observed.Mounts {
		if actual.Type == mount.TypeTmpfs && actual.Destination == "/tmp" {
			tmpfsCount++
			continue
		}
		knownVolume := false
		for _, want := range mounts {
			if actual.Type == mount.TypeVolume && actual.Destination == want.Target &&
				actual.Name == want.Name && actual.RW == !want.ReadOnly {
				knownVolume = true
			}
		}
		if !knownVolume {
			add(true, "Mounts unknown entry")
		}
	}
	add(tmpfsCount > 1 || len(observed.Mounts) != len(mounts)+tmpfsCount, "Mounts count")
	return strings.Join(mismatches, ", ")
}

func codingSelectedPlatformMatches(osName, architecture, variant, expected string) bool {
	if osName != "linux" {
		return false
	}
	switch expected {
	case "linux/arm64/v8":
		return architecture == "arm64" && (variant == "" || variant == "v8")
	case "linux/amd64":
		return architecture == "amd64" && variant == ""
	default:
		return false
	}
}
