package dockercontrol

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
)

type executionRuntimeProjection struct {
	Common                     codingRuntimeSecurityProjection
	SeccompDigest              string
	InitConfigured, Init       bool
	LogDriver                  string
	LogOptions, RestartRetries int
	ShmBytes                   int64
	SecondaryResourcesDigest   string
	AdditionalHostOptions      int
	MaskedPathsDigest          string
	ReadonlyPathsDigest        string
}

// Frozen Linux path protections observed on the local Docker 29.8 fixture.
// Empty or daemon-customized protections cannot inherit this candidate proof.
func executionMaskedPaths() []string {
	return []string{"/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list", "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware"}
}
func executionReadonlyPaths() []string {
	return []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
}

// Preserve a digest of every secondary resource field without retaining host
// paths or driver details. Clearing only the four independently checked limits
// means a newly added SDK field also fails closed when nonzero. Empty slices
// and the documented unset swappiness/disabled OOM override normalize to zero.
func executionSecondaryResourcesDigest(r container.Resources) string {
	r.Memory, r.MemorySwap, r.NanoCPUs, r.PidsLimit = 0, 0, 0, nil
	if r.MemorySwappiness != nil && *r.MemorySwappiness == -1 {
		r.MemorySwappiness = nil
	}
	if r.OomKillDisable != nil && !*r.OomKillDisable {
		r.OomKillDisable = nil
	}
	v := reflect.ValueOf(&r).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Kind() == reflect.Slice && f.Len() == 0 {
			f.SetZero()
		}
	}
	return codingProjectionDigest("execution-secondary-resources", r)
}

func projectExecutionRuntime(v container.InspectResponse) (executionRuntimeProjection, error) {
	p, err := projectCodingRuntimeSecurity(v)
	if err != nil {
		return executionRuntimeProjection{}, err
	}
	h := v.HostConfig
	if len(h.SecurityOpt) != 2 || h.SecurityOpt[0] != "no-new-privileges:true" || !strings.HasPrefix(h.SecurityOpt[1], "seccomp=") {
		return executionRuntimeProjection{}, ErrInvalidCodingCompletionObservation
	}
	policy := strings.TrimPrefix(h.SecurityOpt[1], "seccomp=")
	if len(policy) == 0 || len(policy) > 64<<10 {
		return executionRuntimeProjection{}, ErrInvalidCodingCompletionObservation
	}
	p.SecurityOptionsDigest = "" // raw text replaced by its source-bound digest
	if len(h.Tmpfs) == 0 {
		p.TmpfsDigest = codingProjectionDigest("tmpfs", map[string]string{})
	}
	for _, m := range v.Mounts {
		if m.Driver != "local" || m.Mode != "" || m.Propagation != "" {
			return executionRuntimeProjection{}, ErrInvalidCodingCompletionObservation
		}
	}
	sort.Slice(p.RealizedMounts, func(i, j int) bool { return p.RealizedMounts[i].Target < p.RealizedMounts[j].Target })
	result := executionRuntimeProjection{Common: p, SeccompDigest: digest([]byte(policy)), InitConfigured: h.Init != nil,
		LogDriver: h.LogConfig.Type, LogOptions: len(h.LogConfig.Config), RestartRetries: h.RestartPolicy.MaximumRetryCount, ShmBytes: h.ShmSize,
		SecondaryResourcesDigest: executionSecondaryResourcesDigest(h.Resources),
		MaskedPathsDigest:        codingProjectionDigest("execution-masked-paths", h.MaskedPaths),
		ReadonlyPathsDigest:      codingProjectionDigest("execution-readonly-paths", h.ReadonlyPaths),
		AdditionalHostOptions:    len(h.Annotations) + len(h.DNS) + len(h.DNSOptions) + len(h.DNSSearch)}
	if h.ConsoleSize != [2]uint{} || h.OomScoreAdj != 0 || h.Isolation != "" {
		result.AdditionalHostOptions++
	}
	if h.Init != nil {
		result.Init = *h.Init
	}
	return result, nil
}
func (v executionRuntimeProjection) recheck(b executionBinding, a executionCreate, id string, labels map[string]string) error {
	p := v.Common
	t := b.Template
	r := a.resources(b)
	limit := t.Resources.Resident
	started, err := time.Parse(time.RFC3339Nano, p.StartedAt)
	if err != nil || started.IsZero() || p.PID <= 0 || !codingProjectionPlatformMatches(p.ManifestPlatform, t.Image.Platform) ||
		v.SeccompDigest != t.SeccompPolicyDigest || !v.InitConfigured || v.Init || v.LogDriver != "none" || v.LogOptions != 0 || v.RestartRetries != 0 || v.ShmBytes != t.PrivateShmBytes ||
		v.SecondaryResourcesDigest != executionSecondaryResourcesDigest(container.Resources{}) || v.AdditionalHostOptions != 0 ||
		v.MaskedPathsDigest != codingProjectionDigest("execution-masked-paths", executionMaskedPaths()) || v.ReadonlyPathsDigest != codingProjectionDigest("execution-readonly-paths", executionReadonlyPaths()) ||
		(p.Runtime != "" && p.Runtime != "runc") || (p.IpcMode != "" && p.IpcMode != "private") || (p.CgroupnsMode != "" && p.CgroupnsMode != "private") {
		return ErrInvalidCodingCompletionObservation
	}
	// Comparing a complete safe projection keeps every otherwise-zero count,
	// privilege and secondary access route closed. Only daemon normalization,
	// an observed positive PID and parsed start time are carried from the read.
	want := codingRuntimeSecurityProjection{ID: id, Name: "/" + r.Resident, ImageID: t.Image.Descriptor.Digest,
		ManifestDigest: t.Image.Descriptor.Digest, ManifestMediaType: "application/vnd.oci.image.manifest.v1+json",
		ManifestPlatform: p.ManifestPlatform, ManifestSize: t.Image.SelectedManifestSize,
		StateStatus: "running", StartedAt: p.StartedAt, Running: true, PID: p.PID,
		ConfigImage: t.Image.Reference, User: fmt.Sprintf("%d:%d", r.UID, r.GID), WorkingDir: t.WorkingDirectory,
		CommandDigest: codingProjectionDigest("command", t.ResidentCommand), EnvironmentDigest: codingProjectionDigest("environment", t.Environment), LabelsDigest: codingProjectionDigest("labels", labels),
		NetworkMode: "none", RestartPolicy: "no", Runtime: p.Runtime, ReadonlyRootfs: true, CapDrop: []string{"ALL"},
		TmpfsDigest: codingProjectionDigest("tmpfs", map[string]string{}), Memory: limit.MemoryBytes, MemorySwap: limit.MemoryBytes, NanoCPUs: limit.CPUMillis * 1_000_000, PIDs: limit.PIDs,
		IpcMode: p.IpcMode, CgroupnsMode: p.CgroupnsMode, NetworkNames: []string{"none"}}
	for _, m := range executionMounts(r) {
		want.ConfiguredMounts = append(want.ConfiguredMounts, codingSafeMount{Type: "volume", Name: m.Name, Target: m.Target, ReadOnly: m.ReadOnly, NoCopy: true})
		want.RealizedMounts = append(want.RealizedMounts, codingSafeMount{Type: "volume", Name: m.Name, Target: m.Target, ReadOnly: m.ReadOnly})
	}
	sort.Slice(want.RealizedMounts, func(i, j int) bool { return want.RealizedMounts[i].Target < want.RealizedMounts[j].Target })
	p.ConfiguredMounts = slices.Clone(p.ConfiguredMounts)
	for i := range p.ConfiguredMounts {
		if p.ConfiguredMounts[i].Consistency == "default" {
			p.ConfiguredMounts[i].Consistency = ""
		}
	}
	if !reflect.DeepEqual(p, want) {
		return ErrInvalidCodingCompletionObservation
	}
	return nil
}
