//go:build integration

package productpostgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
	productdevelopment "github.com/shell-echo/sandbox-runtime/product/adapter/development"
	productguest "github.com/shell-echo/sandbox-runtime/product/adapter/guest"
)

func TestIntegrationDevelopmentStartupPersistenceAuthorityAndReplay(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-development-startup"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 3*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	guests, _ := product.NewGuestService(store, product.CryptoIDGenerator{})
	authenticator, _ := productguest.NewAuthenticator(store)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "development-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "development-workspace", integrationCreateWorkspaceRequest("development workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.workspace_slots SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	workspace, _ := application.GetWorkspace(context.Background(), tenantID, actor, created.Operation.WorkspaceID)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	capabilities := append([]string(nil), developmentCapabilities...)
	binding, _, err := guests.Provision(context.Background(), tenantID, actor, workspace.ID, "development-guest", product.ProvisionGuestRequest{ExpectedWorkspaceVersion: workspace.Version, SlotKey: product.PrimarySlotKey, ProtocolVersion: guestagent.ProtocolVersion, Capabilities: capabilities, PublicKey: publicKey, LifetimeSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticator.Authenticate(context.Background(), signedGuestAuth(t, binding, privateKey, "development-challenge"))
	if err != nil {
		t.Fatal(err)
	}
	template, err := (productdevelopment.LockedCatalog{}).Get(context.Background(), product.DevelopmentTemplateID)
	if err != nil {
		t.Fatal(err)
	}
	request := product.StartDevelopmentRequest{TemplateID: template.ID, StartupTimeoutSeconds: 30}
	requestDigest := sha256.Sum256([]byte("development-request"))
	command := product.BeginDevelopmentCommand{TenantID: tenantID, WorkspaceID: workspace.ID, StartupID: "dev-integration", Actor: actor, EventID: "evt-development", AuditID: "aud-development", IdempotencyKey: "development-start", Path: "/internal/v1/workspaces/" + workspace.ID + "/development-environment", RequestDigest: requestDigest, Request: request, Template: template}
	environment, materialization, replay, err := store.BeginDevelopmentEnvironment(context.Background(), command)
	if err != nil || replay || environment.State != "materializing" || environment.GuestID != binding.GuestID || materialization.RevisionID != "initial-empty" || materialization.ManifestDigest != emptyWorkspaceManifestDigest || len(materialization.Entries) != 0 {
		t.Fatalf("environment=%+v materialization=%+v replay=%v err=%v", environment, materialization, replay, err)
	}
	replayed, replayMaterialization, replay, err := store.BeginDevelopmentEnvironment(context.Background(), command)
	if err != nil || !replay || replayed.ID != environment.ID || replayMaterialization.ManifestDigest != materialization.ManifestDigest {
		t.Fatalf("replayed=%+v materialization=%+v replay=%v err=%v", replayed, replayMaterialization, replay, err)
	}
	conflict := command
	conflict.RequestDigest = sha256.Sum256([]byte("different"))
	if _, _, _, err := store.BeginDevelopmentEnvironment(context.Background(), conflict); !errors.Is(err, product.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict err=%v", err)
	}
	authority := product.DevelopmentAuthority{TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID, SlotKey: identity.SlotKey, GuestID: identity.GuestID, SlotGeneration: identity.SlotGeneration, BindingGeneration: identity.BindingGeneration}
	health := product.DevelopmentHealth{Live: true, Ready: true, TemplateRevision: template.Revision, WorkspaceRevision: materialization.RevisionID, Mounts: template.Mounts, Toolchains: template.Toolchains}
	ready, err := store.CompleteDevelopmentEnvironment(context.Background(), product.CompleteDevelopmentCommand{Environment: environment, Authority: authority, Health: health})
	if err != nil || ready.State != "ready" {
		t.Fatalf("ready=%+v err=%v", ready, err)
	}
	reconstructed, _ := New(pool, 3*time.Second)
	loaded, loadedMaterialization, err := reconstructed.GetDevelopmentEnvironment(context.Background(), tenantID, actor, environment.ID)
	if err != nil || loaded.State != "ready" || loaded.TemplateRevision != template.Revision || loadedMaterialization.RevisionID != materialization.RevisionID {
		t.Fatalf("loaded=%+v materialization=%+v err=%v", loaded, loadedMaterialization, err)
	}
	if _, _, err := reconstructed.GetDevelopmentEnvironment(context.Background(), tenantID, product.ActorRef{Type: product.ActorHuman, ID: "other-owner"}, environment.ID); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-owner read err=%v", err)
	}
	var eventAttributes, auditResource string
	if err := pool.QueryRow(context.Background(), `SELECT attributes::text FROM sandbox_runtime_product.workspace_events WHERE tenant_id=$1 AND event_id='evt-development'`, tenantID).Scan(&eventAttributes); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT resource_id FROM sandbox_runtime_product.security_audit WHERE tenant_id=$1 AND event_id='aud-development'`, tenantID).Scan(&auditResource); err != nil {
		t.Fatal(err)
	}
	if auditResource != product.PrimarySlotKey || containsPrivateDevelopmentValue(eventAttributes, template.Image, binding.GuestID) {
		t.Fatalf("audit/event leaked private state: resource=%q attributes=%s", auditResource, eventAttributes)
	}
}

func containsPrivateDevelopmentValue(document string, values ...string) bool {
	for _, value := range values {
		if value != "" && strings.Contains(document, value) {
			return true
		}
	}
	return false
}
