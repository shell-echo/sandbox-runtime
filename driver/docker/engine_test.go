package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestNewConnectsToLinuxDockerEngine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("API-Version", "1.55")
		w.Header().Set("OSType", "linux")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	options := testOptions()
	options.Host = server.URL
	driver, err := New(context.Background(), options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := driver.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewRejectsNonLinuxDockerEngine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("API-Version", "1.55")
		w.Header().Set("OSType", "windows")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	options := testOptions()
	options.Host = server.URL
	if _, err := New(context.Background(), options); err == nil {
		t.Fatal("expected non-Linux engine error")
	}
}

func TestEnsureImageWaitHonorsContext(t *testing.T) {
	engine := &mobyEngine{pullToken: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.ensureImage(ctx, "example/shell:v1", PullAlways); !errors.Is(err, context.Canceled) {
		t.Fatalf("ensureImage = %v, want context.Canceled", err)
	}
}

func TestMobyEngineCreateUsesSandboxDefaults(t *testing.T) {
	var captured container.CreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1.55/containers/create" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("name"); got != "sandbox-runtime-instance-one" {
			t.Errorf("name = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"docker-id","Warnings":[]}`))
	}))
	defer server.Close()

	apiClient, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	engine := &mobyEngine{client: apiClient}
	init := true
	_, err = engine.create(context.Background(), createRequest{
		name:        "sandbox-runtime-instance-one",
		image:       "example/shell:v1",
		command:     []string{"sleep", "3600"},
		labels:      map[string]string{managedLabel: "true"},
		memoryBytes: 256 << 20,
		nanoCPUs:    500_000_000,
		pidsLimit:   128,
		stopTimeout: 5,
		init:        &init,
		user:        "65532:65532",
		readonly:    true,
		tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if captured.Config == nil || captured.Config.Image != "example/shell:v1" {
		t.Fatalf("Config = %+v", captured.Config)
	}
	if captured.Config.User != "65532:65532" {
		t.Fatalf("User = %q", captured.Config.User)
	}
	if captured.HostConfig == nil {
		t.Fatal("HostConfig is nil")
	}
	host := captured.HostConfig
	if host.NetworkMode != "none" || host.Privileged || host.AutoRemove {
		t.Fatalf("isolation config = %+v", host)
	}
	if !host.ReadonlyRootfs || host.Tmpfs["/tmp"] == "" {
		t.Fatalf("filesystem isolation = %+v", host)
	}
	if len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" {
		t.Fatalf("CapDrop = %v", host.CapDrop)
	}
	if host.Memory != 256<<20 || host.MemorySwap != 256<<20 || host.NanoCPUs != 500_000_000 {
		t.Fatalf("Resources = %+v", host.Resources)
	}
	if host.PidsLimit == nil || *host.PidsLimit != 128 || host.Init == nil || !*host.Init {
		t.Fatalf("PidsLimit/Init = %v/%v", host.PidsLimit, host.Init)
	}
}

func TestMobyEngineListsOnlyManagedControllerNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1.55/containers/json" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("all") != "1" {
			t.Errorf("all = %q", r.URL.Query().Get("all"))
		}
		var filters map[string]map[string]bool
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
			t.Fatalf("decode filters: %v", err)
		}
		labels := filters["label"]
		if !labels[managedLabel+"=true"] || !labels[namespaceLabel+"=team-a"] || !labels[controllerLabel+"=controller-a"] {
			t.Errorf("filters = %+v", filters)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Id":"docker-id","Created":123,"Labels":{"` + managedLabel + `":"true"}}]`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &mobyEngine{client: apiClient}
	containers, err := engine.listManaged(context.Background(), "team-a", "controller-a")
	if err != nil || len(containers) != 1 || containers[0].labels[managedLabel] != "true" || containers[0].createdAt.Unix() != 123 {
		t.Fatalf("listManaged = %+v, %v", containers, err)
	}
}
