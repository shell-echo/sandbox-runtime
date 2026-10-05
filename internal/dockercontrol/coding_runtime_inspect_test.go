package dockercontrol

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	ocidigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestCodingRuntimeInspectReusesClosedProbePolicy(t *testing.T) {
	set, labels, _ := testCodingInventoryFixture(t)
	template := testVolumeTemplate(t)
	slot := template.Slots[0]
	mounts := set.Mounts()
	id, name, policy := strings.Repeat("a", 64), "runtime-fixture", "fixed-test-policy"
	pids := template.Limits.PIDs
	configured := make([]mount.Mount, 0, len(mounts))
	realized := make([]container.MountPoint, 0, len(mounts))
	for _, item := range mounts {
		configured = append(configured, mount.Mount{Type: mount.TypeVolume,
			Source: item.Name, Target: item.Target, ReadOnly: item.ReadOnly,
			VolumeOptions: &mount.VolumeOptions{NoCopy: true}})
		realized = append(realized, container.MountPoint{Type: mount.TypeVolume,
			Name: item.Name, Destination: item.Target, RW: !item.ReadOnly})
	}
	platform := &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	observed := container.InspectResponse{ID: id, Name: "/" + name,
		Image: template.Image.Descriptor.Digest,
		ImageManifestDescriptor: &ocispec.Descriptor{Digest: ocidigest.Digest(template.Image.SelectedManifestDigest),
			MediaType: "application/vnd.oci.image.manifest.v1+json", Size: template.Image.SelectedManifestSize,
			Platform: platform},
		State: &container.State{Status: "running", Running: true, Pid: 123,
			StartedAt: time.Now().UTC().Format(time.RFC3339Nano)},
		Config: &container.Config{Image: template.Image.Reference,
			User:       fmt.Sprintf("%d:%d", slot.WorkloadUID, slot.WorkloadGID),
			WorkingDir: template.WorkingDirectory, Cmd: slices.Clone(template.Command),
			Env: slices.Clone(template.Environment), Labels: labels[CodingRuntimeRole]},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode("none"),
			ReadonlyRootfs: true, RestartPolicy: container.RestartPolicy{Name: "no"},
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + policy},
			Mounts: configured, Tmpfs: map[string]string{"/tmp": fmt.Sprintf(
				"rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=%d,gid=%d",
				template.TmpfsBytes, slot.WorkloadUID, slot.WorkloadGID)},
			Resources: container.Resources{Memory: template.Limits.MemoryBytes,
				MemorySwap: template.Limits.MemoryBytes,
				NanoCPUs:   template.Limits.CPUMillis * 1_000_000, PidsLimit: &pids}},
		Mounts: realized,
		NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{
			"none": {},
		}},
	}
	if err := validateCodingRuntimeInspect(observed, id, name, labels[CodingRuntimeRole],
		template, slot, mounts, policy); err != nil {
		t.Fatalf("closed running runtime rejected: %v", err)
	}
	wrongNetwork := observed
	wrongNetwork.NetworkSettings = &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{
		"none": {}, "foreign": {},
	}}
	if validateCodingRuntimeInspect(wrongNetwork, id, name, labels[CodingRuntimeRole],
		template, slot, mounts, policy) == nil {
		t.Fatal("extra network admitted")
	}
	wrongState := observed
	state := *observed.State
	state.Paused = true
	wrongState.State = &state
	if validateCodingRuntimeInspect(wrongState, id, name, labels[CodingRuntimeRole],
		template, slot, mounts, policy) == nil {
		t.Fatal("paused runtime admitted")
	}
	if validateCodingRuntimeInspect(observed, strings.Repeat("b", 64), name,
		labels[CodingRuntimeRole], template, slot, mounts, policy) == nil {
		t.Fatal("replaced runtime ID admitted")
	}
	for _, mutation := range []struct {
		name   string
		change func(*container.HostConfig)
	}{
		{"supplementary root group", func(h *container.HostConfig) { h.GroupAdd = []string{"0"} }},
		{"host pid", func(h *container.HostConfig) { h.PidMode = "host" }},
		{"container pid", func(h *container.HostConfig) { h.PidMode = "container:foreign" }},
		{"host ipc", func(h *container.HostConfig) { h.IpcMode = "host" }},
		{"container ipc", func(h *container.HostConfig) { h.IpcMode = "container:foreign" }},
		{"host uts", func(h *container.HostConfig) { h.UTSMode = "host" }},
		{"host userns", func(h *container.HostConfig) { h.UsernsMode = "host" }},
		{"host cgroupns", func(h *container.HostConfig) { h.CgroupnsMode = "host" }},
		{"container cgroup", func(h *container.HostConfig) { h.Cgroup = "container:foreign" }},
		{"device request", func(h *container.HostConfig) { h.DeviceRequests = []container.DeviceRequest{{Count: 1}} }},
		{"device rule", func(h *container.HostConfig) { h.DeviceCgroupRules = []string{"a *:* rwm"} }},
		{"foreign volumes", func(h *container.HostConfig) { h.VolumesFrom = []string{"foreign"} }},
		{"published port", func(h *container.HostConfig) { h.PortBindings = network.PortMap{network.MustParsePort("80/tcp"): {}} }},
		{"publish all ports", func(h *container.HostConfig) { h.PublishAllPorts = true }},
		{"sysctl", func(h *container.HostConfig) { h.Sysctls = map[string]string{"kernel.shm_rmid_forced": "1"} }},
		{"custom runtime", func(h *container.HostConfig) { h.Runtime = "foreign" }},
		{"storage override", func(h *container.HostConfig) { h.StorageOpt = map[string]string{"size": "1G"} }},
		{"auto remove", func(h *container.HostConfig) { h.AutoRemove = true }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			copy := observed
			host := *observed.HostConfig
			copy.HostConfig = &host
			mutation.change(&host)
			if validateCodingRuntimeInspect(copy, id, name, labels[CodingRuntimeRole],
				template, slot, mounts, policy) == nil {
				t.Fatal("privilege or secondary access drift admitted")
			}
		})
	}
}
