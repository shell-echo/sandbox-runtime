package egressbroker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egresspolicystate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestOnlinePolicyAuthorityRevocationDrainsLiveBrokerSession(t *testing.T) {
	fixture := newBrokerFixture(t, staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}}, 4)
	defer fixture.close(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(char string) string { return "sha256:" + strings.Repeat(char, 64) }
	profilePolicy := phase6security.EgressPolicy{ID: fixture.policy.ID, Revision: fixture.policy.Revision,
		PrincipalDigest: fixture.policy.Principal.Digest(), BrokerDigest: fixture.policy.Broker.Digest()}
	binding, err := egresspolicystate.NewBinding(egresspolicystate.BindingConfig{
		EnvironmentDigest: digest("a"), ProfileDigest: digest("b"), Policy: profilePolicy,
		OperatorKeyID: "operator-1", OperatorPublicKey: publicKey, MaxAge: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	temporaryRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(temporaryRoot, "p6b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	ledgerDirectory, socketDirectory := filepath.Join(root, "ledger"), filepath.Join(root, "sockets")
	if err := os.Mkdir(ledgerDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(socketDirectory, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketDirectory, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(socketDirectory, -1, os.Getgid()); err != nil {
		t.Fatal(err)
	}
	authority, err := egresspolicystate.OpenAuthority(egresspolicystate.AuthorityConfig{
		Binding: binding, LedgerPath: filepath.Join(ledgerDirectory, "ledger.json"),
		PrivateKey: privateKey,
		Now:        time.Now, AllowInitialize: true})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if _, err := authority.Commit(0, "active", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(socketDirectory, "current.sock")
	server, err := egresspolicystate.ListenAuthority(egresspolicystate.AuthorityServerConfig{
		SocketPath: socketPath, AuthorityUID: uint32(os.Getuid()), BrokerGID: uint32(os.Getgid()),
		ExpectedBrokerUID: uint32(os.Getuid()), ExpectedBrokerGID: uint32(os.Getgid()), MaxConnections: 4}, authority)
	if err != nil {
		t.Fatal(err)
	}
	serverContext, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverContext) }()
	defer func() {
		stopServer()
		<-serverDone
		if err := server.Close(); err != nil {
			t.Errorf("authority socket cleanup: %v", err)
		}
	}()
	client, err := egresspolicystate.NewAuthorityClient(egresspolicystate.AuthorityClientConfig{
		SocketPath: socketPath, ExpectedAuthorityUID: uint32(os.Getuid()), ExpectedAuthorityGID: uint32(os.Getgid()),
		BrokerGID: uint32(os.Getgid()), Binding: binding, Timeout: time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := client.Current(context.Background())
	tracker := new(egresspolicystate.CurrentTracker)
	if err != nil || tracker.Accept(initial, time.Now().UTC()) != nil {
		t.Fatalf("initial online authority state = %v", err)
	}
	pollContext, stopPolling := context.WithCancel(context.Background())
	defer stopPolling()
	pollDone := make(chan error, 1)
	go func() {
		result := egresspolicystate.PollCurrent(pollContext, client, tracker, 50*time.Millisecond, time.Now)
		if result != nil && !errors.Is(result, context.Canceled) {
			_ = fixture.server.RevokePolicy(fixture.policy.Revision)
		}
		pollDone <- result
	}()
	connection, err := fixture.client.Dial(context.Background(), "packages", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := <-fixture.dialer.peers
	defer peer.Close()
	if _, err := authority.Commit(1, "active", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	select {
	case err := <-pollDone:
		t.Fatalf("higher active generation revoked live connection: %v", err)
	default:
	}
	if _, err := connection.Write([]byte("alive")); err != nil {
		t.Fatalf("active session write failed: %v", err)
	}
	buffer := make([]byte, 5)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(buffer); err != nil || string(buffer) != "alive" {
		t.Fatalf("active session read = %q, %v", buffer, err)
	}
	start := time.Now()
	if _, err := authority.Commit(2, "revoked", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-pollDone:
		if !errors.Is(err, egresspolicystate.ErrRevoked) || time.Since(start) > time.Second {
			t.Fatalf("bounded online revocation = %v after %s", err, time.Since(start))
		}
	case <-time.After(time.Second):
		t.Fatal("online revocation did not drain within one second")
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("revoked live session remained readable")
	}
	if _, err := fixture.client.Dial(context.Background(), "packages", time.Second); !errors.Is(err, ErrDenied) {
		t.Fatalf("new connection after signed revocation = %v", err)
	}
}
