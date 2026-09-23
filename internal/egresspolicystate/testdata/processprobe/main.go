// processprobe is a Docker-only fixture for proving distinct-UID policy-state
// authority and broker-side Unix attestation. It is not a production command.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egresspolicystate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	policy := phase6security.EgressPolicy{ID: "product-egress", Revision: "policy-1",
		PrincipalDigest: "sha256:" + string(bytes.Repeat([]byte{'a'}, 64)),
		BrokerDigest:    "sha256:" + string(bytes.Repeat([]byte{'b'}, 64))}
	binding, err := egresspolicystate.NewBinding(egresspolicystate.BindingConfig{
		EnvironmentDigest: "sha256:" + string(bytes.Repeat([]byte{'c'}, 64)),
		ProfileDigest:     "sha256:" + string(bytes.Repeat([]byte{'d'}, 64)), Policy: policy,
		OperatorKeyID: "operator-1", OperatorPublicKey: publicKey, MaxAge: 10 * time.Second})
	if err != nil {
		fatal(err)
	}
	switch os.Args[1] {
	case "initialize":
		initialize(binding, key)
	case "authority":
		runAuthority(binding, key)
	case "client":
		runClient(binding)
	default:
		os.Exit(2)
	}
}

func initialize(binding egresspolicystate.Binding, key ed25519.PrivateKey) {
	authority, err := egresspolicystate.OpenAuthority(egresspolicystate.AuthorityConfig{
		Binding: binding, LedgerPath: "/state/ledger/ledger.json", SnapshotPath: "/state/ledger/current.json",
		PrivateKey: key, Now: time.Now, AllowInitialize: true})
	if err != nil {
		fatal(err)
	}
	defer authority.Close()
	if _, err := authority.Commit(0, "active", 10*time.Second); err != nil {
		fatal(err)
	}
}

func runAuthority(binding egresspolicystate.Binding, key ed25519.PrivateKey) {
	authority, err := egresspolicystate.OpenAuthority(egresspolicystate.AuthorityConfig{
		Binding: binding, LedgerPath: "/state/ledger/ledger.json", SnapshotPath: "/state/ledger/current.json",
		PrivateKey: key, Now: time.Now, AllowInitialize: false})
	if err != nil {
		fatal(err)
	}
	defer authority.Close()
	committed, err := authority.Committed()
	if err != nil {
		fatal(err)
	}
	if committed.Status == "active" {
		if _, err := authority.Commit(committed.Generation, "active", 10*time.Second); err != nil {
			fatal(err)
		}
	}
	server, err := egresspolicystate.ListenAuthority(egresspolicystate.AuthorityServerConfig{
		SocketPath: "/state/socket/current.sock", AuthorityUID: 20001, BrokerGID: 30000,
		ExpectedBrokerUID: 20002, ExpectedBrokerGID: 30000, MaxConnections: 4}, authority)
	if err != nil {
		fatal(err)
	}
	defer server.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	revoke := make(chan os.Signal, 1)
	signal.Notify(revoke, syscall.SIGUSR1)
	defer signal.Stop(revoke)
	go func() {
		select {
		case <-revoke:
			ledger, ledgerErr := authority.Committed()
			if ledgerErr != nil || ledger.Status != "active" {
				cancel()
				return
			}
			if _, commitErr := authority.Commit(ledger.Generation, "revoked", 10*time.Second); commitErr != nil {
				cancel()
			}
		case <-ctx.Done():
		}
	}()
	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		fatal(err)
	}
}

func runClient(binding egresspolicystate.Binding) {
	client, err := egresspolicystate.NewAuthorityClient(egresspolicystate.AuthorityClientConfig{
		SocketPath: "/state/socket/current.sock", ExpectedAuthorityUID: 20001, ExpectedAuthorityGID: 30001,
		BrokerGID: 30000, Binding: binding, Timeout: time.Second, Now: time.Now})
	if err != nil {
		fatal(err)
	}
	response, err := client.Current(context.Background())
	if err != nil {
		fatal(err)
	}
	_, _ = fmt.Fprintln(os.Stdout, response.Status)
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "fixture failed: %v\n", err)
	os.Exit(1)
}
