//go:build integration

package productpostgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
	productguest "github.com/shell-echo/sandbox-runtime/product/adapter/guest"
)

// This no-issuer component test joins the real PostgreSQL binding transaction
// to the actual Hub/Agent WebSocket lifecycle. It is not the source-bound
// Product/Guest PID1 or TLS/CRL release gate.
func TestIntegrationPrivateGuestReceiptLiveRevocation(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenant = "tenant-private-guest-receipt"
	cleanupProductTenant(t, pool, tenant)
	store, err := New(pool, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	application, err := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	guests, err := product.NewGuestService(store, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-private-guest-receipt"}
	created, err := application.CreateWorkspace(t.Context(), tenant, actor, "guest-receipt-workspace",
		integrationCreateWorkspaceRequest("guest receipt workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE sandbox_runtime_product.workspace_slots SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	workspace, err := application.GetWorkspace(t.Context(), tenant, actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding, replay, err := guests.Provision(t.Context(), tenant, actor, workspace.ID,
		"guest-receipt-provision", product.ProvisionGuestRequest{ExpectedWorkspaceVersion: workspace.Version,
			SlotKey: product.PrimarySlotKey, ProtocolVersion: guestagent.ProtocolVersion,
			Capabilities: []string{"guest.health"}, PublicKey: publicKey, LifetimeSeconds: 600})
	if err != nil || replay || binding.BindingGeneration != 1 {
		t.Fatal("real Product Guest binding unavailable")
	}
	productEvents := make(chan guestagent.Observation, 32)
	guestEvents := make(chan guestagent.Observation, 32)
	revoked := make(chan struct {
		digest     string
		generation int64
	}, 4)
	authenticator, err := productguest.NewAuthenticatorWithRevocationObservation(store,
		func(digest string, generation int64) {
			revoked <- struct {
				digest     string
				generation int64
			}{digest, generation}
		})
	if err != nil {
		t.Fatal(err)
	}
	hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: authenticator,
		AuthorityPollPeriod: 20 * time.Millisecond, Observation: func(value guestagent.Observation) {
			productEvents <- value
		}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub)
	defer server.Close()
	agent, err := guestagent.NewAgent(guestagent.AgentOptions{
		URL: "ws" + strings.TrimPrefix(server.URL, "http"), GuestID: binding.GuestID,
		BindingGeneration: binding.BindingGeneration, PrivateKey: privateKey,
		Handlers: map[string]guestagent.OperationHandler{
			"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil },
		}, ReconnectBackoff: 20 * time.Millisecond,
		Observation: func(value guestagent.Observation) { guestEvents <- value },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- agent.Run(ctx) }()
	await := func(events <-chan guestagent.Observation, kind string) guestagent.Observation {
		t.Helper()
		for {
			select {
			case value := <-events:
				if value.Event == kind {
					return value
				}
			case <-ctx.Done():
				t.Fatalf("private Guest component event %s unavailable", kind)
			}
		}
	}
	installed := await(productEvents, guestagent.ObservationProductPeerInstalled)
	accepted := await(guestEvents, guestagent.ObservationGuestWelcomeAccepted)
	if installed.AttemptDigest == "" || installed.AttemptDigest != accepted.AttemptDigest ||
		installed.BindingGeneration != 1 || accepted.BindingGeneration != 1 {
		t.Fatal("real PostgreSQL accepted Guest attempt correlation unavailable")
	}
	if err := store.RevokeGuest(ctx, tenant, binding.GuestID, "removed"); err != nil {
		t.Fatal(err)
	}
	stale := await(productEvents, guestagent.ObservationProductAuthorityStale)
	closed := await(productEvents, guestagent.ObservationProductCloseCompleted)
	terminated := await(guestEvents, guestagent.ObservationGuestReadTerminated)
	if stale.AttemptDigest != installed.AttemptDigest || closed.AttemptDigest != installed.AttemptDigest ||
		terminated.AttemptDigest != installed.AttemptDigest || closed.Reason != "authority_stale" {
		t.Fatal("real PostgreSQL revocation did not close the original signed transport")
	}
	retry := await(guestEvents, guestagent.ObservationGuestHelloWritten)
	if retry.AttemptDigest == installed.AttemptDigest || retry.BindingGeneration != binding.BindingGeneration {
		t.Fatal("fresh revoked Guest attempt digest unavailable")
	}
	select {
	case observed := <-revoked:
		if observed.digest != retry.AttemptDigest || observed.generation != binding.BindingGeneration {
			t.Fatal("same-transaction signed revoked row did not match fresh Guest hello")
		}
	case <-ctx.Done():
		t.Fatal("same-transaction validated revoked observation unavailable")
	}
	select {
	case err := <-result:
		if !errors.Is(err, guestagent.ErrUnauthorized) {
			t.Fatalf("Guest rejected retry result = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Guest did not terminate after revoked retry")
	}
}
