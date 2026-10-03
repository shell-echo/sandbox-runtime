//go:build phase6slice6fixture

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/product"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	"github.com/spf13/cobra"
)

const guestRevokeFixtureProtocol = "sandbox-runtime.phase6-guest-revoke-fixture.v1"
const guestRevokeFixtureOperation = "revoke-exact-connected-binding"
const guestRevokeFixtureReason = "phase6-slice6-live-revocation"
const guestRevokeFixtureAdmissionProtocol = "sandbox-runtime.phase6-guest-revoke-admission.v1"

var guestRevokeFixtureCmd = &cobra.Command{
	Use: "phase6-guest-revoke-fixture", Hidden: true, SilenceUsage: true,
	PersistentPreRunE: loadGuestBindingFixtureConfig,
	RunE:              runGuestRevokeFixture,
}

func init() { rootCmd.AddCommand(guestRevokeFixtureCmd) }

type guestRevokeFixtureInput struct {
	Protocol           string                     `json:"protocol"`
	Operation          string                     `json:"operation"`
	RunID              string                     `json:"run_id"`
	ProfileDigest      string                     `json:"profile_digest"`
	ExecutableDigest   string                     `json:"executable_digest"`
	ProductContainerID string                     `json:"product_container_id"`
	InitialBinding     guestBindingFixtureReceipt `json:"initial_binding"`
}

type guestRevokeFixtureReceipt struct {
	Protocol            string  `json:"protocol"`
	RunID               string  `json:"run_id"`
	ProfileDigest       string  `json:"profile_digest"`
	ExecutableDigest    string  `json:"executable_digest"`
	ProductContainerID  string  `json:"product_container_id"`
	GuestID             string  `json:"guest_id"`
	BindingGeneration   int64   `json:"binding_generation"`
	MutationOutcome     string  `json:"mutation_outcome"`
	BeforeConnected     bool    `json:"before_connected"`
	BindingExpiresAt    string  `json:"binding_expires_at"`
	AfterRevoked        bool    `json:"after_revoked"`
	NonceCleared        bool    `json:"nonce_cleared"`
	PostgresBackendPID  int32   `json:"postgres_backend_pid"`
	PostgresBackendPIDs []int32 `json:"postgres_backend_pids"`
}

type guestRevokeFixtureAdmission struct {
	Protocol           string `json:"protocol"`
	RunID              string `json:"run_id"`
	ProfileDigest      string `json:"profile_digest"`
	ExecutableDigest   string `json:"executable_digest"`
	ProductContainerID string `json:"product_container_id"`
	GuestID            string `json:"guest_id"`
	PostgresBackendPID int32  `json:"postgres_backend_pid"`
}

// A one-connection fixture pool cannot borrow Product's other three role
// slots. Every opened backend is recorded before use; replacement is rejected.
type guestRevokeBackendTracker struct {
	mu   sync.Mutex
	pids []int32
}

func (tracker *guestRevokeBackendTracker) record(pid int32) error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if pid < 1 || len(tracker.pids) >= 8 {
		return errors.New("Guest revoke fixture PostgreSQL backend identity invalid")
	}
	if len(tracker.pids) != 0 {
		tracker.pids = append(tracker.pids, pid)
		return errors.New("Guest revoke fixture PostgreSQL backend was replaced")
	}
	tracker.pids = append(tracker.pids, pid)
	return nil
}

func (tracker *guestRevokeBackendTracker) snapshot() []int32 {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return append([]int32(nil), tracker.pids...)
}

func guestRevokeFixtureOpenPostgres(startup, lifetime context.Context, cfg *config.ProductProcessConfig,
	profile phase6security.Profile, registry *secretref.Registry, tracker *guestRevokeBackendTracker) (*pgxpool.Pool, func(), error) {
	return openDirectV3Postgres(startup, lifetime, profile, registry, directV3PostgresSettings{
		Owner: "product-runtime", RuntimeRole: cfg.Postgres.RuntimeRole,
		DSNBindingID: cfg.Postgres.RuntimeDSNBindingID, Purpose: secretref.PurposePostgresRuntimeDSN,
		ClientAgentSocket: cfg.Postgres.ClientAgentSocket,
		ClientAgentUID:    cfg.Postgres.ClientAgentUID, ClientAgentGID: cfg.Postgres.ClientAgentGID,
		PeerCRLRoleFile:            cfg.Postgres.PeerCRLRoleFile,
		PeerCRLRoleDigest:          cfg.Postgres.PeerCRLRoleDigest,
		PeerCRLSourceMappingDigest: cfg.Postgres.PeerCRLSourceMappingDigest,
		OperationTimeout:           time.Duration(cfg.TLS.OperationTimeoutMillis) * time.Millisecond,
		MaxConnections:             1, MinConnections: 1,
		AfterConnect: func(ctx context.Context, connection *pgx.Conn) error {
			if err := productpostgres.VerifyBoundRuntimeConnection(ctx, connection, "product", cfg.Postgres.RuntimeRole); err != nil {
				return err
			}
			return tracker.record(int32(connection.PgConn().PID()))
		},
	})
}

func guestRevokeFixtureVerifySharedRoleCapacity(ctx context.Context, pool *pgxpool.Pool, ownPID int32) error {
	var limit, total, other int
	err := pool.QueryRow(ctx, `SELECT r.rolconnlimit, count(a.pid),
count(a.pid) FILTER (WHERE a.pid<>$1) FROM pg_catalog.pg_roles r
LEFT JOIN pg_catalog.pg_stat_activity a ON a.usename=r.rolname AND a.datname='product'
WHERE r.rolname='product_runtime' GROUP BY r.rolconnlimit`, ownPID).Scan(&limit, &total, &other)
	if err != nil || limit != 4 || total < 2 || total > 4 || other < 1 || other != total-1 {
		return errors.New("Guest revoke fixture shared SQL role capacity or Product connection unavailable")
	}
	return nil
}

func guestRevokeFixtureReadContinuation(reader *bufio.Reader, runID string) error {
	if reader == nil || len(runID) != 32 || !guestBindingFixtureHex(runID) {
		return errors.New("Guest revoke fixture continuation invalid")
	}
	acknowledgement, err := reader.ReadString('\n')
	if err != nil || acknowledgement != "continue:"+runID+"\n" {
		return errors.New("Guest revoke fixture Product service admission denied")
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return errors.New("Guest revoke fixture continuation has trailing input")
	}
	return nil
}

func decodeGuestRevokeFixtureInput(document []byte) (guestRevokeFixtureInput, error) {
	var input guestRevokeFixtureInput
	if len(document) < 1 || len(document) > 4096 || json.Unmarshal(document, &input) != nil {
		return guestRevokeFixtureInput{}, errors.New("Guest revoke fixture input unavailable")
	}
	canonical, err := json.Marshal(input)
	initial := input.InitialBinding
	if err != nil || !bytes.Equal(canonical, document) ||
		input.Protocol != guestRevokeFixtureProtocol || input.Operation != guestRevokeFixtureOperation ||
		len(input.RunID) != 32 || !guestBindingFixtureHex(input.RunID) ||
		!guestRevokeFixtureDigest(input.ProfileDigest) || !guestRevokeFixtureDigest(input.ExecutableDigest) ||
		len(input.ProductContainerID) != 64 || !guestBindingFixtureHex(input.ProductContainerID) ||
		initial.Protocol != guestBindingFixtureProtocol || initial.RunID != input.RunID ||
		initial.ProfileDigest != input.ProfileDigest || !guestRevokeFixtureDigest(initial.PublicKeySHA256) ||
		initial.WorkspaceID == "" || initial.GuestID == "" || initial.BindingGeneration != 1 ||
		initial.SlotGeneration != 1 || initial.EventCount != 1 || initial.AuditCount != 1 ||
		!initial.IdempotentReplay {
		return guestRevokeFixtureInput{}, errors.New("Guest revoke fixture exact run/target/binding mismatch")
	}
	return input, nil
}

func guestRevokeFixtureDigest(value string) bool {
	return len(value) == len("sha256:")+64 && value[:len("sha256:")] == "sha256:" &&
		guestBindingFixtureHex(value[len("sha256:"):])
}

func guestRevokeFixtureSelfDigest() (string, error) {
	path, err := os.Executable()
	if err != nil || !filepath.IsAbs(path) {
		return "", errors.New("Guest revoke fixture executable identity unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 {
		return "", errors.New("Guest revoke fixture executable unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != info.Size() {
		clear(data)
		return "", errors.New("Guest revoke fixture executable read unavailable")
	}
	sum := sha256.Sum256(data)
	clear(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type guestRevokeFixtureBinding struct {
	TenantID, WorkspaceID, SlotKey, SlotProfileID, GuestID, ProtocolVersion, State string
	SlotGeneration, BindingGeneration                                              int64
	PublicKey, CredentialDigest, Capabilities                                      []byte
	ConnectionNonce                                                                string
	ExpiresAt, ObservedAt                                                          time.Time
}

func guestRevokeFixtureReadBinding(ctx context.Context, pool *pgxpool.Pool,
	tenantID, guestID string) (guestRevokeFixtureBinding, error) {
	var binding guestRevokeFixtureBinding
	err := pool.QueryRow(ctx, `SELECT tenant_id,workspace_id,slot_key,slot_profile_id,
slot_generation,binding_generation,guest_id,public_key,credential_digest,
protocol_version,capabilities,state,COALESCE(connection_nonce,''),expires_at,clock_timestamp()
FROM sandbox_runtime_product.guest_bindings WHERE tenant_id=$1 AND guest_id=$2`,
		tenantID, guestID).Scan(&binding.TenantID, &binding.WorkspaceID, &binding.SlotKey,
		&binding.SlotProfileID, &binding.SlotGeneration, &binding.BindingGeneration,
		&binding.GuestID, &binding.PublicKey, &binding.CredentialDigest,
		&binding.ProtocolVersion, &binding.Capabilities, &binding.State,
		&binding.ConnectionNonce, &binding.ExpiresAt, &binding.ObservedAt)
	if err != nil {
		return guestRevokeFixtureBinding{}, errors.New("Guest revoke fixture binding readback unavailable")
	}
	return binding, nil
}

func guestRevokeFixtureBindingMatches(input guestRevokeFixtureInput, binding guestRevokeFixtureBinding) bool {
	publicDigest := sha256.Sum256(binding.PublicKey)
	var capabilities []string
	if json.Unmarshal(binding.Capabilities, &capabilities) != nil || len(capabilities) != 1 ||
		capabilities[0] != guestdevelopment.CapabilityHealth {
		return false
	}
	return binding.TenantID == "tenant-phase6-"+input.RunID &&
		binding.WorkspaceID == input.InitialBinding.WorkspaceID &&
		binding.SlotKey == product.PrimarySlotKey && binding.SlotProfileID == "coding-shell-v1" &&
		binding.SlotGeneration == input.InitialBinding.SlotGeneration &&
		binding.BindingGeneration == input.InitialBinding.BindingGeneration &&
		binding.GuestID == input.InitialBinding.GuestID &&
		binding.ProtocolVersion == guestagent.ProtocolVersion &&
		bytes.Equal(binding.CredentialDigest, publicDigest[:]) &&
		input.InitialBinding.PublicKeySHA256 == "sha256:"+hex.EncodeToString(publicDigest[:])
}

func guestRevokeFixtureAfterMatches(before, after guestRevokeFixtureBinding) bool {
	return before.TenantID == after.TenantID && before.WorkspaceID == after.WorkspaceID &&
		before.SlotKey == after.SlotKey && before.SlotProfileID == after.SlotProfileID &&
		before.SlotGeneration == after.SlotGeneration &&
		before.BindingGeneration == after.BindingGeneration && before.GuestID == after.GuestID &&
		before.ProtocolVersion == after.ProtocolVersion &&
		bytes.Equal(before.PublicKey, after.PublicKey) &&
		bytes.Equal(before.CredentialDigest, after.CredentialDigest) &&
		bytes.Equal(before.Capabilities, after.Capabilities) && before.ExpiresAt.Equal(after.ExpiresAt)
}

func guestRevokeFixtureOutcome(before, after guestRevokeFixtureBinding, mutationErr error) (string, error) {
	if !guestRevokeFixtureAfterMatches(before, after) || !after.ExpiresAt.After(after.ObservedAt) {
		return "", errors.New("Guest revoke fixture mutation outcome unknown")
	}
	switch {
	case mutationErr == nil && after.State == "revoked" && after.ConnectionNonce == "":
		return "confirmed", nil
	case mutationErr != nil && after.State == "revoked" && after.ConnectionNonce == "":
		// The row's final state is known, but this task cannot attribute an
		// unknown write outcome to itself. The gate must reject this receipt.
		return "revoked-after-unknown", nil
	case mutationErr != nil && after.State == "connected" && after.ConnectionNonce == before.ConnectionNonce:
		return "not-committed-after-unknown", nil
	default:
		return "", errors.New("Guest revoke fixture mutation outcome unknown")
	}
}

func runGuestRevokeFixture(command *cobra.Command, _ []string) error {
	inputReader := bufio.NewReader(io.LimitReader(os.Stdin, 4608))
	document, err := inputReader.ReadBytes('\n')
	if err != nil || len(document) < 2 || len(document) > 4097 {
		return errors.New("Guest revoke fixture input unavailable")
	}
	input, err := decodeGuestRevokeFixtureInput(document[:len(document)-1])
	clear(document)
	if err != nil || command == nil || command.Context() == nil {
		return errors.New("Guest revoke fixture input rejected")
	}
	actualDigest, err := guestRevokeFixtureSelfDigest()
	if err != nil || actualDigest != input.ExecutableDigest {
		return errors.New("Guest revoke fixture executable changed")
	}
	ctx, cancel := context.WithTimeout(command.Context(), 90*time.Second)
	defer cancel()
	cfg := config.ProductProcess
	profile, err := preflightProductV3Postgres(cfg)
	if err != nil || profile.ProfileDigest != input.ProfileDigest {
		return errors.New("Guest revoke fixture Product authority unavailable")
	}
	registry, err := newProductRuntimeMaterialRegistry(cfg.Materials, cfg.SchemaVersion, profile)
	if err != nil {
		return errors.New("Guest revoke fixture material registry unavailable")
	}
	defer registry.Close()
	startup, stopStartup := context.WithTimeout(ctx, time.Duration(cfg.Postgres.StartupTimeoutSeconds)*time.Second)
	defer stopStartup()
	tracker := &guestRevokeBackendTracker{}
	pool, closePool, err := guestRevokeFixtureOpenPostgres(startup, ctx, cfg, profile, registry, tracker)
	if err != nil {
		return errors.New("Guest revoke fixture Product PostgreSQL unavailable")
	}
	var closeOnce sync.Once
	closeFixturePool := func() { closeOnce.Do(closePool) }
	defer closeFixturePool()
	if productpostgres.VerifyRuntimeRole(ctx, pool, cfg.Postgres.RuntimeRole) != nil ||
		productpostgres.VerifySchemaCompatibility(ctx, pool) != nil {
		return errors.New("Guest revoke fixture Product SQL authority mismatch")
	}
	var backendPID int32
	if pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID) != nil || backendPID < 1 ||
		len(tracker.snapshot()) != 1 || tracker.snapshot()[0] != backendPID {
		return errors.New("Guest revoke fixture PostgreSQL connection identity unavailable")
	}
	if guestRevokeFixtureVerifySharedRoleCapacity(ctx, pool, backendPID) != nil || len(tracker.snapshot()) != 1 {
		return errors.New("Guest revoke fixture Product SQL role lost capacity before mutation")
	}
	before, err := guestRevokeFixtureReadBinding(ctx, pool, "tenant-phase6-"+input.RunID,
		input.InitialBinding.GuestID)
	if err != nil || !guestRevokeFixtureBindingMatches(input, before) || before.State != "connected" ||
		before.ConnectionNonce == "" || !before.ExpiresAt.After(before.ObservedAt.Add(30*time.Second)) {
		return errors.New("Guest revoke fixture exact live binding unavailable")
	}
	admission := guestRevokeFixtureAdmission{Protocol: guestRevokeFixtureAdmissionProtocol,
		RunID: input.RunID, ProfileDigest: input.ProfileDigest,
		ExecutableDigest: input.ExecutableDigest, ProductContainerID: input.ProductContainerID,
		GuestID: before.GuestID, PostgresBackendPID: backendPID}
	admitted, err := json.Marshal(admission)
	if err != nil || len(admitted) > 512 {
		return errors.New("Guest revoke fixture admission receipt unavailable")
	}
	if written, writeErr := os.Stdout.Write(append(admitted, '\n')); writeErr != nil || written != len(admitted)+1 {
		return errors.New("Guest revoke fixture admission delivery failed")
	}
	if guestRevokeFixtureReadContinuation(inputReader, input.RunID) != nil || ctx.Err() != nil ||
		len(tracker.snapshot()) != 1 {
		return errors.New("Guest revoke fixture continuation input or backend changed")
	}
	store, err := productpostgres.New(pool, time.Duration(cfg.Postgres.OperationTimeoutSeconds)*time.Second)
	if err != nil {
		return errors.New("Guest revoke fixture Product Store unavailable")
	}
	mutationErr := store.RevokeGuest(ctx, before.TenantID, before.GuestID, guestRevokeFixtureReason)
	after, err := guestRevokeFixtureReadBinding(ctx, pool, before.TenantID, before.GuestID)
	if err != nil {
		return errors.New("Guest revoke fixture mutation outcome unknown")
	}
	outcome, err := guestRevokeFixtureOutcome(before, after, mutationErr)
	if err != nil {
		return err
	}
	closeFixturePool()
	backendPIDs := tracker.snapshot()
	if len(backendPIDs) != 1 || backendPIDs[0] != backendPID {
		return errors.New("Guest revoke fixture PostgreSQL backend changed during mutation")
	}
	result := guestRevokeFixtureReceipt{Protocol: guestRevokeFixtureProtocol, RunID: input.RunID,
		ProfileDigest: input.ProfileDigest, ExecutableDigest: input.ExecutableDigest,
		ProductContainerID: input.ProductContainerID, GuestID: before.GuestID,
		BindingGeneration: before.BindingGeneration, BeforeConnected: true,
		BindingExpiresAt: before.ExpiresAt.UTC().Format(time.RFC3339Nano),
		AfterRevoked:     after.State == "revoked", NonceCleared: after.ConnectionNonce == "",
		PostgresBackendPID: backendPID, PostgresBackendPIDs: backendPIDs, MutationOutcome: outcome}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 2048 {
		return errors.New("Guest revoke fixture receipt unavailable")
	}
	written, err := os.Stdout.Write(append(encoded, '\n'))
	if err != nil || written != len(encoded)+1 {
		return errors.New("Guest revoke fixture receipt delivery failed")
	}
	return nil
}
