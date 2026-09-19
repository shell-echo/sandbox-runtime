package productguest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestDevelopmentClientCarriesMaterializationAndExactAuthority(t *testing.T) {
	root := t.TempDir()
	workspace, state := filepath.Join(root, "workspace"), filepath.Join(root, "state")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	template := product.DevelopmentTemplate{
		ID: product.DevelopmentTemplateID, Revision: digest("template"), RuntimeProfileID: "sandbox-runtime-coding-shell-v1", Image: "ghcr.io/example/image@" + digest("image"),
		Mounts:     []product.DevelopmentMount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}},
		Toolchains: []product.DevelopmentToolchain{{ID: "posix-shell", Version: "test-1", Digest: digest("toolchain"), Executable: "/bin/sh"}},
	}
	service, err := guestdevelopment.New(guestdevelopment.Options{
		WorkspaceRoot: workspace, StateRoot: state,
		Mounts:     []guestdevelopment.Mount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}},
		Toolchains: []guestdevelopment.Toolchain{{ID: "posix-shell", Version: "test-1", Digest: digest("toolchain"), Executable: "/bin/sh"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	auth := &fileTestAuthenticator{publicKey: publicKey}
	hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: auth, AuthorityPollPeriod: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	agent, err := guestagent.NewAgent(guestagent.AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"), GuestID: "gst-files", BindingGeneration: 7, PrivateKey: privateKey, Handlers: service.Handlers(), ReconnectBackoff: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- agent.Run(ctx) }()
	client, err := NewDevelopmentClient(hub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var health product.DevelopmentHealth
	var authority product.DevelopmentAuthority
	deadline := time.Now().Add(2 * time.Second)
	for {
		health, authority, err = client.Health(context.Background(), "tenant-files", "wrk-files", product.PrimarySlotKey)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			probeCtx, stop := context.WithTimeout(context.Background(), time.Second)
			document, identity, probeErr := hub.CallWithIdentity(probeCtx, "tenant-files", "wrk-files", product.PrimarySlotKey, guestdevelopment.CapabilityHealth, struct{}{})
			stop()
			select {
			case runErr := <-runResult:
				t.Fatalf("health err=%v agent err=%v probe=%q identity=%+v probeErr=%v", err, runErr, document, identity, probeErr)
			default:
				t.Fatalf("health err=%v probe=%q identity=%+v probeErr=%v", err, document, identity, probeErr)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !health.Live || health.Ready || authority.GuestID != "gst-files" || authority.SlotGeneration != 3 || authority.BindingGeneration != 7 {
		t.Fatalf("health=%+v authority=%+v", health, authority)
	}
	content := []byte("hello")
	environment := product.DevelopmentEnvironment{ID: "dev-protocol", TenantID: authority.TenantID, WorkspaceID: authority.WorkspaceID, SlotKey: authority.SlotKey, GuestID: authority.GuestID, SlotGeneration: authority.SlotGeneration, BindingGeneration: authority.BindingGeneration, TemplateID: template.ID, TemplateRevision: template.Revision, RevisionID: "rev-protocol", State: "materializing"}
	materialization := product.RevisionMaterialization{RevisionID: environment.RevisionID, ManifestDigest: digest("manifest"), Entries: []product.RevisionManifestEntry{{Path: "README.md", Type: "file", Mode: 0o600, SizeBytes: int64(len(content)), Digest: digest(string(content))}}}
	if got, err := client.Prepare(context.Background(), environment, template, materialization); err != nil || got != authority {
		t.Fatalf("prepare authority=%+v err=%v", got, err)
	}
	if got, err := client.Write(context.Background(), environment, "README.md", 0, content); err != nil || got != authority {
		t.Fatalf("write authority=%+v err=%v", got, err)
	}
	health, got, err := client.Commit(context.Background(), environment)
	if err != nil || got != authority || !health.Ready || health.TemplateRevision != template.Revision || health.WorkspaceRevision != environment.RevisionID {
		t.Fatalf("commit health=%+v authority=%+v err=%v", health, got, err)
	}
	if err := client.Finalize(context.Background(), environment); err != nil {
		t.Fatalf("finalize err=%v", err)
	}
}
