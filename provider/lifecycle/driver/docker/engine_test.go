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

func TestMobyEngineProjectsFixedIsolationAndMounts(t *testing.T) {
	var captured container.CreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1.55/containers/create" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"backend-secret","Warnings":[]}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &mobyEngine{client: apiClient}
	init := true
	_, err = backend.create(context.Background(), createRequest{
		name: "provider-runtime", image: "example/shell@sha256:digest", command: []string{"sleep", "3600"},
		workingDirectory: "/workspace", labels: map[string]string{managedLabel: "true"},
		memoryBytes: 256 << 20, nanoCPUs: 500_000_000, pidsLimit: 128, stopTimeout: 5,
		init: &init, user: "65532:65532", readonly: true,
		tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=1777"},
		mounts: []bindMount{{source: "/host/inputs", target: "/inputs", readonly: true},
			{source: "/host/workspace", target: "/workspace"}, {source: "/host/outputs", target: "/outputs"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.Config == nil || captured.Config.User != "65532:65532" || captured.Config.WorkingDir != "/workspace" {
		t.Fatalf("container config = %#v", captured.Config)
	}
	host := captured.HostConfig
	if host == nil || host.NetworkMode != "none" || host.Privileged || host.AutoRemove || !host.ReadonlyRootfs {
		t.Fatalf("host isolation = %#v", host)
	}
	if len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" || len(host.SecurityOpt) != 1 || host.SecurityOpt[0] != "no-new-privileges:true" {
		t.Fatalf("privilege controls = %#v", host)
	}
	if host.Memory != 256<<20 || host.MemorySwap != 256<<20 || host.NanoCPUs != 500_000_000 || host.PidsLimit == nil || *host.PidsLimit != 128 {
		t.Fatalf("resource controls = %#v", host.Resources)
	}
	if len(host.Mounts) != 3 || host.Mounts[0].Target != "/inputs" || !host.Mounts[0].ReadOnly ||
		host.Mounts[1].Target != "/workspace" || host.Mounts[1].ReadOnly || host.Mounts[2].Target != "/outputs" {
		t.Fatalf("stable mounts = %#v", host.Mounts)
	}
	if host.Tmpfs["/tmp"] == "" {
		t.Fatalf("tmpfs = %#v", host.Tmpfs)
	}
}
