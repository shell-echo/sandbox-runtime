package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestMobyEngineProjectsBrowserIsolation(t *testing.T) {
	var captured container.CreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1.55/containers/create" {
			http.NotFound(w, request)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&captured); err != nil {
			t.Errorf("decode create request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"backend-private-id","Warnings":[]}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer apiClient.Close()
	backend := &mobyEngine{client: apiClient}
	seccomp := `{"defaultAction":"SCMP_ACT_ERRNO"}`
	_, err = backend.create(context.Background(), createRequest{
		name: "browser-runtime", image: "example.invalid/browser@sha256:digest",
		labels: map[string]string{managedLabel: "true"}, user: BrowserUser, workingDirectory: "/workspace",
		memoryBytes: 1 << 30, nanoCPUs: 1_000_000_000, pidsLimit: 256,
		inputsBytes: 16 << 20, tmpfsBytes: 256 << 20, workspaceBytes: 512 << 20, outputsBytes: 128 << 20, stopTimeout: 10,
		networkName: "browser-egress-network-1", dnsResolver: "10.88.0.2", seccompProfile: seccomp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.Config == nil || captured.Config.User != BrowserUser || captured.Config.WorkingDir != "/workspace" ||
		len(captured.Config.Cmd) != 0 || len(captured.Config.Entrypoint) != 0 || len(captured.Config.ExposedPorts) != 0 {
		t.Fatalf("container config = %#v", captured.Config)
	}
	host := captured.HostConfig
	if host == nil || host.NetworkMode != "browser-egress-network-1" || host.Privileged || host.AutoRemove ||
		!host.ReadonlyRootfs || host.PublishAllPorts || len(host.PortBindings) != 0 || len(host.Binds) != 0 || len(host.Mounts) != 0 {
		t.Fatalf("host isolation = %#v", host)
	}
	if len(host.DNS) != 1 || host.DNS[0].String() != "10.88.0.2" {
		t.Fatalf("DNS resolvers = %#v", host.DNS)
	}
	if len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" || len(host.CapAdd) != 0 ||
		len(host.SecurityOpt) != 2 || host.SecurityOpt[0] != "no-new-privileges:true" || host.SecurityOpt[1] != "seccomp="+seccomp {
		t.Fatalf("privilege controls = %#v", host)
	}
	if host.Memory != 1<<30 || host.MemorySwap != 1<<30 || host.NanoCPUs != 1_000_000_000 ||
		host.PidsLimit == nil || *host.PidsLimit != 256 {
		t.Fatalf("resource controls = %#v", host.Resources)
	}
	if len(host.Tmpfs) != 4 || host.Tmpfs["/inputs"] != "ro,noexec,nosuid,nodev,size=16777216,mode=0555" ||
		host.Tmpfs["/tmp"] != "rw,noexec,nosuid,nodev,size=268435456,mode=1777" ||
		host.Tmpfs["/workspace"] != "rw,noexec,nosuid,nodev,size=536870912,mode=0700" ||
		host.Tmpfs["/outputs"] != "rw,noexec,nosuid,nodev,size=134217728,mode=0700" {
		t.Fatalf("writable mounts = %#v", host.Tmpfs)
	}
	if host.LogConfig.Type != "local" || host.LogConfig.Config["max-size"] != "10m" || host.LogConfig.Config["max-file"] != "3" {
		t.Fatalf("log bounds = %#v", host.LogConfig)
	}
}
