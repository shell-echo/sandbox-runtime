package egresspolicystate

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixCurrentAttestationChecksPeerChallengeAndCleanup(t *testing.T) {
	binding, key, _ := stateFixture(t)
	temporaryRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(temporaryRoot, "p6s-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	ledgerDirectory, socketDirectory := filepath.Join(root, "ledger"), filepath.Join(root, "sockets")
	for _, path := range []string{ledgerDirectory, socketDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(socketDirectory, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(socketDirectory, -1, os.Getgid()); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenAuthority(AuthorityConfig{Binding: binding,
		LedgerPath: filepath.Join(ledgerDirectory, "ledger.json"),
		PrivateKey: key, Now: time.Now, AllowInitialize: true})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	active, err := authority.Commit(0, "active", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(socketDirectory, "authority.sock")
	server, err := ListenAuthority(AuthorityServerConfig{SocketPath: socketPath, AuthorityUID: uint32(os.Getuid()),
		BrokerGID: uint32(os.Getgid()), ExpectedBrokerUID: uint32(os.Getuid()), ExpectedBrokerGID: uint32(os.Getgid()),
		MaxConnections: 4}, authority)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	if _, err := ListenAuthority(AuthorityServerConfig{SocketPath: socketPath, AuthorityUID: uint32(os.Getuid()),
		BrokerGID: uint32(os.Getgid()), ExpectedBrokerUID: uint32(os.Getuid()), ExpectedBrokerGID: uint32(os.Getgid()),
		MaxConnections: 4}, authority); !errors.Is(err, ErrInvalid) {
		cancel()
		t.Fatalf("live authority socket was replaced: %v", err)
	}
	client, err := NewAuthorityClient(AuthorityClientConfig{SocketPath: socketPath,
		ExpectedAuthorityUID: uint32(os.Getuid()), ExpectedAuthorityGID: uint32(os.Getgid()),
		BrokerGID: uint32(os.Getgid()), Binding: binding, Timeout: time.Second, Now: time.Now})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	response, err := client.Current(context.Background())
	if err != nil || CompareCurrent(active, response) != nil {
		cancel()
		t.Fatalf("current Unix attestation = %#v, %v", response, err)
	}
	wrongPeer, err := NewAuthorityClient(AuthorityClientConfig{SocketPath: socketPath,
		ExpectedAuthorityUID: uint32(os.Getuid()), ExpectedAuthorityGID: uint32(os.Getgid()) + 1,
		BrokerGID: uint32(os.Getgid()), Binding: binding, Timeout: time.Second, Now: time.Now})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := wrongPeer.Current(context.Background()); !errors.Is(err, ErrInvalid) {
		cancel()
		t.Fatalf("wrong authority peer GID accepted: %v", err)
	}
	tracker := new(CurrentTracker)
	if err := tracker.Accept(response, time.Now().UTC()); err != nil {
		cancel()
		t.Fatal(err)
	}
	pollContext, stopPolling := context.WithCancel(context.Background())
	defer stopPolling()
	polled := make(chan error, 1)
	go func() { polled <- PollCurrent(pollContext, client, tracker, 50*time.Millisecond, time.Now) }()
	time.Sleep(120 * time.Millisecond)
	select {
	case err := <-polled:
		cancel()
		t.Fatalf("healthy authority polling stopped: %v", err)
	default:
	}
	if _, err := authority.Commit(1, "revoked", 10*time.Second); err != nil {
		cancel()
		t.Fatal(err)
	}
	response, err = client.Current(context.Background())
	if err != nil || response.Status != "revoked" || CompareCurrent(active, response) == nil {
		cancel()
		t.Fatalf("revoked Unix authority = %#v, %v", response, err)
	}
	select {
	case err := <-polled:
		if !errors.Is(err, ErrRevoked) {
			cancel()
			t.Fatalf("poll revocation error = %v", err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("online revocation was not observed")
	}
	cancel()
	select {
	case err := <-served:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authority server did not stop")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("authority socket remained after close: %v", err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := ListenAuthority(AuthorityServerConfig{SocketPath: socketPath, AuthorityUID: uint32(os.Getuid()),
		BrokerGID: uint32(os.Getgid()), ExpectedBrokerUID: uint32(os.Getuid()), ExpectedBrokerGID: uint32(os.Getgid()),
		MaxConnections: 4}, authority)
	if err != nil {
		t.Fatalf("same-owner stale socket was not recovered: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
}
