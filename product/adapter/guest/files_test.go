package productguest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestfiles "github.com/shell-echo/sandbox-runtime/guestagent/files"
)

func TestFileClientProjectsConfinedGuestOperationsWithBindingEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileService, err := guestfiles.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fileService.Close()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	auth := &fileTestAuthenticator{publicKey: publicKey}
	hub, _ := guestagent.NewHub(guestagent.HubOptions{Authenticator: auth, AuthorityPollPeriod: 20 * time.Millisecond})
	server := httptest.NewServer(hub)
	defer server.Close()
	agent, _ := guestagent.NewAgent(guestagent.AgentOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"), GuestID: "gst-files", BindingGeneration: 7, PrivateKey: privateKey, Handlers: fileService.Handlers(), ReconnectBackoff: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = agent.Run(ctx) }()
	client, _ := NewFileClient(hub, 2*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for {
		page, authority, err := client.List(context.Background(), "tenant-files", "wrk-files", "primary-code", "src", "", 10)
		if err == nil {
			if len(page.Items) != 1 || page.Items[0].Path != "src/main.go" || authority.GuestID != "gst-files" || authority.BindingGeneration != 7 || authority.SlotGeneration != 3 {
				t.Fatalf("page=%#v authority=%#v", page, authority)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	entry, _, err := client.Stat(context.Background(), "tenant-files", "wrk-files", "primary-code", "src/main.go")
	if err != nil || entry.Type != "file" || !strings.HasPrefix(entry.Revision, "sha256:") {
		t.Fatalf("entry=%#v err=%v", entry, err)
	}
	snapshot, err := client.Snapshot(context.Background(), "tenant-files", "wrk-files", "primary-code", "")
	if err != nil || len(snapshot.Entries) != 2 || snapshot.Authority.GuestID != "gst-files" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
}

type fileTestAuthenticator struct {
	mu        sync.Mutex
	publicKey ed25519.PublicKey
	nonce     string
}

func (a *fileTestAuthenticator) Authenticate(_ context.Context, request guestagent.AuthRequest) (guestagent.Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	signing, _ := request.SigningBytes()
	signature, _ := request.SignatureBytes()
	if !ed25519.Verify(a.publicKey, signing, signature) {
		return guestagent.Identity{}, guestagent.ErrUnauthorized
	}
	a.nonce = request.Hello.ClientNonce
	return guestagent.Identity{TenantID: "tenant-files", WorkspaceID: "wrk-files", SlotKey: "primary-code", GuestID: "gst-files", SlotGeneration: 3, BindingGeneration: 7, ProtocolVersion: guestagent.ProtocolVersion, Capabilities: request.Hello.Capabilities, ClientNonce: a.nonce, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (a *fileTestAuthenticator) CheckAuthority(context.Context, guestagent.Identity) error {
	return nil
}
func (a *fileTestAuthenticator) Disconnected(context.Context, guestagent.Identity) error { return nil }

var _ guestagent.Authenticator = (*fileTestAuthenticator)(nil)
