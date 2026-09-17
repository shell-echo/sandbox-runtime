package qualificationoperator

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

func TestValidDockerRuntimeRequiresObservedHostConfiguration(t *testing.T) {
	t.Parallel()
	expected := qualificationprofile.RuntimeLimits{
		SandboxCPUMillis: 750, SandboxMemoryBytes: 268435456,
		SandboxEphemeralStorageBytes: 134217728, SandboxPIDs: 64,
	}
	pids := int64(64)
	actual := dockerContainerInspection{ID: "container"}
	actual.HostConfig = &struct {
		Memory         int64             `json:"Memory"`
		MemorySwap     int64             `json:"MemorySwap"`
		NanoCPUs       int64             `json:"NanoCpus"`
		PidsLimit      *int64            `json:"PidsLimit"`
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		NetworkMode    string            `json:"NetworkMode"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		Tmpfs          map[string]string `json:"Tmpfs"`
	}{
		Memory: 268435456, MemorySwap: 268435456, NanoCPUs: 750000000, PidsLimit: &pids,
		ReadonlyRootfs: true, NetworkMode: "none", CapDrop: []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"}, Tmpfs: map[string]string{"/tmp": "rw,nosuid,nodev,size=134217728"},
	}
	if !validDockerRuntime(actual, expected) {
		t.Fatal("valid observed Docker runtime was rejected")
	}
	actual.HostConfig.NetworkMode = "bridge"
	if validDockerRuntime(actual, expected) {
		t.Fatal("networked Docker runtime was accepted")
	}
}

func TestDockerTmpfsBytes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		options string
		want    int64
		ok      bool
	}{
		{options: "rw,nosuid,size=1048576,nodev", want: 1048576, ok: true},
		{options: "size=0", ok: false},
		{options: "size=1m", ok: false},
		{options: "rw,nosuid", ok: false},
	} {
		got, ok := dockerTmpfsBytes(test.options)
		if got != test.want || ok != test.ok {
			t.Fatalf("dockerTmpfsBytes(%q) = (%d, %t), want (%d, %t)", test.options, got, ok, test.want, test.ok)
		}
	}
}
