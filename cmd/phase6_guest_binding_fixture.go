//go:build phase6slice6fixture

package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/product"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	"github.com/spf13/cobra"
)

const guestBindingFixtureProtocol = "sandbox-runtime.phase6-guest-binding-fixture.v1"

// This command exists only in a separately built, digest-bound local gate
// artifact. It is absent from the ordinary Product image and production CLI.
var guestBindingFixtureCmd = &cobra.Command{
	Use: "phase6-guest-binding-fixture", Hidden: true, SilenceUsage: true,
	PersistentPreRunE: loadGuestBindingFixtureConfig,
	RunE:              runGuestBindingFixture,
}

type guestBindingFixtureInput struct {
	Protocol        string `json:"protocol"`
	RunID           string `json:"run_id"`
	ProfileDigest   string `json:"profile_digest"`
	TenantID        string `json:"tenant_id"`
	ActorID         string `json:"actor_id"`
	PublicKey       []byte `json:"public_key"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type guestBindingFixtureReceipt struct {
	Protocol          string `json:"protocol"`
	RunID             string `json:"run_id"`
	ProfileDigest     string `json:"profile_digest"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	WorkspaceID       string `json:"workspace_id"`
	GuestID           string `json:"guest_id"`
	BindingGeneration int64  `json:"binding_generation"`
	SlotGeneration    int64  `json:"slot_generation"`
	EventCount        int    `json:"event_count"`
	AuditCount        int    `json:"audit_count"`
	IdempotentReplay  bool   `json:"idempotent_replay"`
}

func init() { rootCmd.AddCommand(guestBindingFixtureCmd) }

func loadGuestBindingFixtureConfig(*cobra.Command, []string) error {
	if configPath != phase6CoreStartupPath {
		return errors.New("Guest binding fixture requires the exact Product private startup file")
	}
	profile, err := phase6security.VerifySlice6ProfileForDeployment(phase6CoreProfilePath, "product-runtime")
	if err != nil || profile.ProfileDigest == "" {
		return errors.New("Guest binding fixture Product Profile unavailable")
	}
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("Guest binding fixture startup file unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
		return errors.New("Guest binding fixture startup file owner mismatch")
	}
	document, err := secretfile.Read(configPath, 64<<10)
	if err != nil {
		clear(document)
		return errors.New("Guest binding fixture startup file unavailable")
	}
	defer clear(document)
	if config.LoadPhase6CoreBytes(document, "product-runtime") != nil ||
		config.ProductProcess == nil || config.ProductProcess.SchemaVersion != config.ProductProductionSchemaV3 ||
		config.ProductProcess.TLS.SecurityProfileDigest != profile.ProfileDigest {
		return errors.New("Guest binding fixture Product config mismatch")
	}
	return nil
}

func decodeGuestBindingFixtureInput(document []byte) (guestBindingFixtureInput, error) {
	var input guestBindingFixtureInput
	if len(document) < 1 || len(document) > 4096 || json.Unmarshal(document, &input) != nil {
		return guestBindingFixtureInput{}, errors.New("Guest binding fixture input unavailable")
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(canonical, document) || input.Protocol != guestBindingFixtureProtocol ||
		len(input.RunID) != 32 || !guestBindingFixtureHex(input.RunID) ||
		len(input.ProfileDigest) != len("sha256:")+64 ||
		input.ProfileDigest[:len("sha256:")] != "sha256:" ||
		!guestBindingFixtureHex(input.ProfileDigest[len("sha256:"):]) ||
		input.TenantID != "tenant-phase6-"+input.RunID ||
		input.ActorID != "actor-phase6-"+input.RunID ||
		len(input.PublicKey) != ed25519.PublicKeySize {
		return guestBindingFixtureInput{}, errors.New("Guest binding fixture identity mismatch")
	}
	sum := sha256.Sum256(input.PublicKey)
	if input.PublicKeySHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		return guestBindingFixtureInput{}, errors.New("Guest binding fixture public key mismatch")
	}
	return input, nil
}

func guestBindingFixtureHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type guestBindingFixturePrimarySlot struct{}

func (guestBindingFixturePrimarySlot) AuthorizePrimarySlot(_ context.Context, slot product.SlotSpec) error {
	if slot.SlotKey != product.PrimarySlotKey || slot.Kind != "code" ||
		slot.ProfileID != "coding-shell-v1" || slot.DesiredState != "ready" ||
		len(slot.RequiredCapabilities) != 2 ||
		slot.RequiredCapabilities[0] != (product.CapabilityRequirement{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"}) ||
		slot.RequiredCapabilities[1] != (product.CapabilityRequirement{CapabilityID: "sandbox.terminal", Version: "1.0.0", ProfileID: "terminal-v1"}) {
		return product.ErrCapabilityUnsupported
	}
	return nil
}

func runGuestBindingFixture(command *cobra.Command, _ []string) error {
	inputBytes, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		return errors.New("Guest binding fixture input unavailable")
	}
	input, err := decodeGuestBindingFixtureInput(inputBytes)
	clear(inputBytes)
	if err != nil || command == nil || command.Context() == nil {
		return errors.New("Guest binding fixture input rejected")
	}
	defer clear(input.PublicKey)
	ctx, cancel := context.WithTimeout(command.Context(), 2*time.Minute)
	defer cancel()
	cfg := config.ProductProcess
	profile, err := preflightProductV3Postgres(cfg)
	if err != nil || profile.ProfileDigest != input.ProfileDigest {
		return errors.New("Guest binding fixture Product authority unavailable")
	}
	registry, err := newProductRuntimeMaterialRegistry(cfg.Materials, cfg.SchemaVersion, profile)
	if err != nil {
		return errors.New("Guest binding fixture material registry unavailable")
	}
	defer registry.Close()
	startup, stopStartup := context.WithTimeout(ctx, time.Duration(cfg.Postgres.StartupTimeoutSeconds)*time.Second)
	defer stopStartup()
	pool, closePool, err := openProductV3Postgres(startup, ctx, cfg, profile, registry)
	if err != nil {
		return errors.New("Guest binding fixture Product PostgreSQL unavailable")
	}
	defer closePool()
	if productpostgres.VerifyRuntimeRole(ctx, pool, cfg.Postgres.RuntimeRole) != nil ||
		productpostgres.VerifySchemaCompatibility(ctx, pool) != nil {
		return errors.New("Guest binding fixture Product SQL authority mismatch")
	}
	store, err := productpostgres.New(pool, time.Duration(cfg.Postgres.OperationTimeoutSeconds)*time.Second)
	if err != nil {
		return errors.New("Guest binding fixture Product Store unavailable")
	}
	ids := product.CryptoIDGenerator{}
	application, err := product.NewApplication(store, guestBindingFixturePrimarySlot{}, ids)
	if err != nil {
		return errors.New("Guest binding fixture Product application unavailable")
	}
	actor := product.ActorRef{Type: product.ActorHuman, ID: input.ActorID}
	created, err := application.CreateWorkspace(ctx, input.TenantID, actor,
		"phase6-guest-workspace-"+input.RunID, product.CreateWorkspaceRequest{
			DisplayName: "Phase 6 Guest fixture", LifetimeSeconds: 3600,
			PrimarySlot: product.SlotSpec{SlotKey: product.PrimarySlotKey, Kind: "code", ProfileID: "coding-shell-v1",
				DesiredState: "ready", RequiredCapabilities: []product.CapabilityRequirement{
					{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"},
					{CapabilityID: "sandbox.terminal", Version: "1.0.0", ProfileID: "terminal-v1"},
				}},
		})
	if err != nil || created.Replay || created.Operation.WorkspaceID == "" ||
		created.Operation.SubmittedBy != actor {
		return errors.New("Guest binding fixture Workspace seed failed")
	}
	workspaceID := created.Operation.WorkspaceID
	var slotGeneration int64
	if err := pool.QueryRow(ctx, `UPDATE sandbox_runtime_product.workspace_slots
SET observed_state='ready',observed_generation=generation,updated_at=clock_timestamp()
WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3 AND generation=1
AND observed_generation=0 AND observed_state='requested' AND desired_state='ready'
RETURNING generation`, input.TenantID, workspaceID, product.PrimarySlotKey).Scan(&slotGeneration); err != nil || slotGeneration != 1 {
		return errors.New("Guest binding fixture exact ready-slot seed failed")
	}
	workspace, err := application.GetWorkspace(ctx, input.TenantID, actor, workspaceID)
	if err != nil || workspace.ID != workspaceID || workspace.TenantID != input.TenantID ||
		workspace.Owner != actor || workspace.Version < 1 ||
		workspace.PrimarySlotKey != product.PrimarySlotKey || len(workspace.Slots) != 1 ||
		workspace.Slots[0].SlotKey != product.PrimarySlotKey ||
		workspace.Slots[0].Kind != "code" || workspace.Slots[0].ProfileID != "coding-shell-v1" ||
		workspace.Slots[0].DesiredState != "ready" || workspace.Slots[0].ObservedState != "ready" ||
		workspace.Slots[0].Generation != slotGeneration ||
		workspace.Slots[0].ObservedGeneration != slotGeneration ||
		!slices.Equal(workspace.Slots[0].RequiredCapabilities, []product.CapabilityRequirement{
			{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"},
			{CapabilityID: "sandbox.terminal", Version: "1.0.0", ProfileID: "terminal-v1"},
		}) {
		return errors.New("Guest binding fixture Workspace readback failed")
	}
	guests, err := product.NewGuestService(store, ids)
	if err != nil {
		return errors.New("Guest binding fixture Guest service unavailable")
	}
	request := product.ProvisionGuestRequest{ExpectedWorkspaceVersion: workspace.Version,
		SlotKey: product.PrimarySlotKey, ProtocolVersion: guestagent.ProtocolVersion,
		Capabilities: []string{guestdevelopment.CapabilityHealth},
		PublicKey:    append([]byte(nil), input.PublicKey...), LifetimeSeconds: 600}
	binding, replay, err := guests.Provision(ctx, input.TenantID, actor, workspaceID,
		"phase6-guest-binding-"+input.RunID, request)
	if err != nil || replay || binding.GuestID == "" || binding.BindingGeneration != 1 ||
		binding.SlotGeneration != slotGeneration || binding.State != "issued" {
		return errors.New("Guest binding fixture Product provision failed")
	}
	retained, replay, err := guests.Provision(ctx, input.TenantID, actor, workspaceID,
		"phase6-guest-binding-"+input.RunID, request)
	if err != nil || !replay || retained.GuestID != binding.GuestID ||
		retained.BindingGeneration != binding.BindingGeneration {
		return errors.New("Guest binding fixture idempotency replay mismatch")
	}
	var durable, events, audits int
	publicDigest := sha256.Sum256(input.PublicKey)
	if pool.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.guest_bindings
WHERE tenant_id=$1 AND workspace_id=$2 AND guest_id=$3 AND binding_generation=$4
AND slot_key=$5 AND slot_profile_id='coding-shell-v1' AND slot_generation=$6
AND public_key=$7 AND credential_digest=$8 AND protocol_version=$9
AND capabilities='["development.health"]'::jsonb AND state='issued'
AND expires_at > clock_timestamp() AND expires_at <= clock_timestamp()+interval '10 minutes'`,
		input.TenantID, workspaceID, binding.GuestID, binding.BindingGeneration,
		product.PrimarySlotKey, slotGeneration, input.PublicKey, publicDigest[:],
		guestagent.ProtocolVersion).Scan(&durable) != nil || durable != 1 ||
		pool.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.workspace_events
WHERE tenant_id=$1 AND workspace_id=$2 AND event_type='guest.binding.provisioned'
AND subject_type='guest_binding' AND subject_id=$3 AND actor_type='human' AND actor_id=$4`,
			input.TenantID, workspaceID, binding.GuestID, actor.ID).Scan(&events) != nil || events != 1 ||
		pool.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.security_audit
WHERE tenant_id=$1 AND actor_type='human' AND actor_id=$2 AND action='guest.provision'
AND resource_type='guest_binding' AND resource_id=$3 AND outcome='allowed' AND reason_code='authorized'`,
			input.TenantID, actor.ID, binding.GuestID).Scan(&audits) != nil || audits != 1 {
		return errors.New("Guest binding fixture durable event or audit readback failed")
	}
	receipt := guestBindingFixtureReceipt{Protocol: guestBindingFixtureProtocol, RunID: input.RunID,
		ProfileDigest: input.ProfileDigest, PublicKeySHA256: input.PublicKeySHA256,
		WorkspaceID: workspaceID, GuestID: binding.GuestID,
		BindingGeneration: binding.BindingGeneration, SlotGeneration: slotGeneration,
		EventCount: events, AuditCount: audits, IdempotentReplay: true}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > 2048 {
		return errors.New("Guest binding fixture receipt unavailable")
	}
	written, err := os.Stdout.Write(append(encoded, '\n'))
	if err != nil || written != len(encoded)+1 {
		return errors.New("Guest binding fixture receipt delivery failed")
	}
	return nil
}
