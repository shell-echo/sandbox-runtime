//go:build integration

package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	slice5evidence "github.com/shell-echo/sandbox-runtime/internal/productphase6slice5evidence"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/vaulttransit"
	"github.com/shell-echo/sandbox-runtime/product"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
)

const (
	vaultIntegrationEnv      = "SANDBOX_RUNTIME_VAULT_TRANSIT_INTEGRATION"
	vaultEvidencePathEnv     = "SANDBOX_RUNTIME_PHASE6_SLICE5_TRANSIT_EVIDENCE"
	desktopCandidateEnv      = "SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST"
	vaultIntegrationImage    = slice5evidence.VaultImage
	postgresIntegrationImage = slice5evidence.PostgresImage
)

type integrationTokenSource struct{ value []byte }

func (s integrationTokenSource) Resolve(context.Context, secretref.Reference) ([]byte, error) {
	return append([]byte(nil), s.value...), nil
}

type integrationPrimarySlotPolicy struct{}

func (integrationPrimarySlotPolicy) AuthorizePrimarySlot(context.Context, product.SlotSpec) error {
	return nil
}

func integrationWorkspaceRequest() product.CreateWorkspaceRequest {
	return product.CreateWorkspaceRequest{DisplayName: "Transit recording workspace", LifetimeSeconds: 3600,
		PrimarySlot: product.SlotSpec{SlotKey: product.PrimarySlotKey, Kind: "code", ProfileID: "coding-shell-v1", DesiredState: "ready",
			RequiredCapabilities: []product.CapabilityRequirement{
				{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"},
				{CapabilityID: "sandbox.terminal", Version: "1.0.0", ProfileID: "terminal-v1"},
			}},
	}
}

func TestVaultTransitRecordingStoreIntegration(t *testing.T) {
	if os.Getenv(vaultIntegrationEnv) != "1" {
		t.Skip("set " + vaultIntegrationEnv + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	containerName := "sandbox-runtime-vault-transit-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	postgresContainer := "sandbox-runtime-recording-postgres-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	rootToken := "phase6-vault-root-integration"
	vaultCleaned, postgresCleaned := false, false
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if !vaultCleaned {
			_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", containerName).Run()
		}
		if !postgresCleaned {
			_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", postgresContainer).Run()
		}
	})

	runIntegrationCommand(t, ctx, "docker", "pull", vaultIntegrationImage)
	runIntegrationCommand(t, ctx, "docker", "pull", postgresIntegrationImage)
	runIntegrationCommand(t, ctx, "docker", "run", "-d", "--name", containerName,
		"-p", "127.0.0.1::8200", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken,
		vaultIntegrationImage, "server", "-dev", "-dev-root-token-id="+rootToken,
		"-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls")
	postgresPool := startRecordingPostgres(t, ctx, postgresContainer)
	defer postgresPool.Close()
	if err := productpostgres.ApplyMigrations(ctx, postgresPool); err != nil {
		t.Fatal(err)
	}

	portOutput := strings.TrimSpace(runIntegrationCommand(t, ctx, "docker", "port", containerName, "8200/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("Vault published port is unavailable")
	}
	port := portOutput[separator+1:]
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal("Vault published port is invalid")
	}
	caPath := filepath.Join(t.TempDir(), "vault-ca.pem")
	waitForVaultCA(t, ctx, containerName, caPath)
	caDocument, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caDocument) {
		t.Fatal("Vault integration CA is invalid")
	}
	endpoint := "https://127.0.0.1:" + port
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	waitForVaultHealth(t, ctx, httpClient, endpoint, rootToken)

	vaultWrite(t, ctx, httpClient, endpoint+"/v1/sys/mounts/transit", rootToken, map[string]any{"type": "transit"}, nil)
	vaultWrite(t, ctx, httpClient, endpoint+"/v1/transit/keys/recording-primary", rootToken, map[string]any{
		"type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false,
	}, nil)
	policy := `path "transit/encrypt/recording-primary" { capabilities = ["update"] }
path "transit/decrypt/recording-primary" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }`
	vaultWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/recording-runtime", rootToken, map[string]any{"policy": policy}, nil)
	var tokenResponse struct {
		Auth struct {
			ClientToken string `json:"client_token"`
			Accessor    string `json:"accessor"`
		} `json:"auth"`
	}
	vaultWrite(t, ctx, httpClient, endpoint+"/v1/auth/token/create", rootToken, map[string]any{
		"policies": []string{"recording-runtime"}, "ttl": "5m", "renewable": false, "no_default_policy": true,
	}, &tokenResponse)
	if tokenResponse.Auth.ClientToken == "" || tokenResponse.Auth.ClientToken == rootToken || tokenResponse.Auth.Accessor == "" {
		t.Fatal("Vault did not issue a distinct scoped token")
	}

	now := time.Now().UTC()
	tokenBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/product/transit-token", Version: "v1",
		Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant,
		Role: secretref.RoleProduct,
	}
	tokenBytes := []byte(tokenResponse.Auth.ClientToken)
	tokenDigest := sha256.Sum256(tokenBytes)
	tokenSourceBytes := append([]byte(nil), tokenBytes...)
	t.Cleanup(func() { clear(tokenSourceBytes) })
	tokenProvider, err := secretref.NewBoundSecretProvider(
		integrationTokenSource{value: tokenSourceBytes}, tokenBinding,
		secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(4 * time.Minute), State: secretref.KeyActive},
		"vault-token-revision-1", "sha256:"+hex.EncodeToString(tokenDigest[:]), func() time.Time { return time.Now().UTC() },
	)
	clear(tokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	transitClient, err := vaulttransit.New(vaulttransit.Config{
		Endpoint: endpoint, Mount: "transit", ReferenceAuthority: "vault",
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return time.Now().UTC() },
	}, httpClient, tokenProvider, tokenBinding)
	if err != nil {
		t.Fatal(err)
	}

	v1 := secretref.EnvelopeKeyVersion{
		Reference: "kms://vault/transit/recording-primary", Version: "v1", KeyID: "recording-primary",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), State: secretref.KeyActive},
	}
	v1Bindings, err := secretref.NewEnvelopeBindingSet(secretref.PurposeRecordingEnvelopeKey, secretref.RoleProduct, v1.KeyID, v1.Version, []secretref.EnvelopeKeyVersion{v1}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	storeRoot := t.TempDir()
	store, err := New(storeRoot, transitClient, v1Bindings)
	if err != nil {
		t.Fatal(err)
	}
	v1Handle, err := store.CreateKeyReference(ctx, "tenant-a", "recording-v1")
	if err != nil {
		t.Fatal(err)
	}
	v1Reference, err := store.PutSegment(ctx, "tenant-a", "recording-v1", v1Handle, 1, []byte("real Vault Transit v1 payload"))
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := store.ReadSegment(ctx, "tenant-a", "recording-v1", v1Handle, 1, v1Reference); err != nil || string(payload) != "real Vault Transit v1 payload" {
		t.Fatalf("Vault v1 round trip = %q, %v", payload, err)
	}

	vaultWrite(t, ctx, httpClient, endpoint+"/v1/transit/keys/recording-primary/rotate", rootToken, map[string]any{}, nil)
	v1.Window.State = secretref.KeyGrace
	v2 := secretref.EnvelopeKeyVersion{
		Reference: v1.Reference, Version: "v2", KeyID: v1.KeyID,
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), State: secretref.KeyActive},
	}
	rotatedBindings, err := secretref.NewEnvelopeBindingSet(secretref.PurposeRecordingEnvelopeKey, secretref.RoleProduct, v2.KeyID, v2.Version, []secretref.EnvelopeKeyVersion{v1, v2}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	restartedStore, err := New(storeRoot, transitClient, rotatedBindings)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := restartedStore.ReadSegment(ctx, "tenant-a", "recording-v1", v1Handle, 1, v1Reference); err != nil || string(payload) != "real Vault Transit v1 payload" {
		t.Fatalf("Vault grace read = %q, %v", payload, err)
	}
	v2Handle, err := restartedStore.CreateKeyReference(ctx, "tenant-a", "recording-v2")
	if err != nil {
		t.Fatal(err)
	}
	decodedV2, err := decodeKeyHandle(v2Handle)
	if err != nil || decodedV2.KMSKeyVersion != "v2" {
		t.Fatalf("Vault rotated handle = %#v, %v", decodedV2, err)
	}
	v2Reference, err := restartedStore.PutSegment(ctx, "tenant-a", "recording-v2", v2Handle, 1, []byte("real Vault Transit v2 payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedStore.ReadSegment(ctx, "tenant-b", "recording-v2", v2Handle, 1, v2Reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("cross-tenant KMS recording read error = %v", err)
	}
	decodedHandle, err := decodeKeyHandle(v2Handle)
	if err != nil {
		t.Fatal(err)
	}
	v2Binding, err := rotatedBindings.BindingForOpen("tenant-a", decodedHandle.BindingDigest, decodedHandle.ProviderKeyID, decodedHandle.KMSKeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := restartedStore.provider.OpenEnvelope(ctx, v2Binding, decodedHandle.envelope(), []byte("substituted-aad")); err == nil {
		clear(plaintext)
		t.Fatal("Vault Transit accepted substituted wrapped-key associated data")
	}
	segmentPath, ok := restartedStore.segmentPath("tenant-a", "recording-v2", v2Reference)
	if !ok {
		t.Fatal("KMS recording segment path unavailable")
	}
	originalSegment, err := os.ReadFile(segmentPath)
	if err != nil {
		t.Fatal(err)
	}
	var tampered segmentDocument
	if err := decodeCanonicalJSON(originalSegment, maxSegmentDocumentSize, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Ciphertext[0] ^= 0x01
	tamperedDocument, err := encodeSegmentDocument(tampered)
	if err != nil || os.WriteFile(segmentPath, tamperedDocument, 0o600) != nil {
		t.Fatal("write tampered KMS recording segment")
	}
	clear(tamperedDocument)
	if _, err := restartedStore.ReadSegment(ctx, "tenant-a", "recording-v2", v2Handle, 1, v2Reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("tampered KMS recording segment error = %v", err)
	}
	if err := os.WriteFile(segmentPath, originalSegment, 0o600); err != nil {
		clear(originalSegment)
		t.Fatal(err)
	}
	clear(originalSegment)
	revokedV1 := v1
	revokedV1.Window.State = secretref.KeyRevoked
	revokedBindings, err := secretref.NewEnvelopeBindingSet(secretref.PurposeRecordingEnvelopeKey, secretref.RoleProduct, v2.KeyID, v2.Version, []secretref.EnvelopeKeyVersion{revokedV1, v2}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	revokedStore, err := New(storeRoot, transitClient, revokedBindings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokedStore.ReadSegment(ctx, "tenant-a", "recording-v1", v1Handle, 1, v1Reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("revoked v1 recording key error = %v", err)
	}

	postgresStore, err := productpostgres.New(postgresPool, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	application, err := product.NewApplication(postgresStore, integrationPrimarySlotPolicy{}, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-transit-recording"}
	workspace, err := application.CreateWorkspace(ctx, "tenant-transit", actor, "create-transit-workspace", integrationWorkspaceRequest())
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "ses_transit_recording"
	if _, err := postgresPool.Exec(ctx, `INSERT INTO sandbox_runtime_product.runtime_sessions(tenant_id,session_id,workspace_id,slot_key,slot_generation,owner_actor_type,owner_actor_id,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at) VALUES($1,$2,$3,'primary-code',1,$4,$5,'terminal','product-terminal.v1','active',true,'required',1,clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp())`, "tenant-transit", sessionID, workspace.Operation.WorkspaceID, string(actor.Type), actor.ID); err != nil {
		t.Fatal(err)
	}
	redactor, err := product.NewPatternRedactor([]string{"TRANSIT-SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	recordings, err := product.NewRecordingService(postgresStore, restartedStore, redactor, product.CryptoIDGenerator{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	recording, err := recordings.Start(ctx, "tenant-transit", actor, workspace.Operation.WorkspaceID, product.StartRecordingRequest{SessionID: sessionID, RecordingType: "terminal", ConsentReference: "consent_transit", RetentionSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recordings.Append(ctx, "tenant-transit", actor, recording.ID, []byte("token=TRANSIT-SECRET\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := recordings.Append(ctx, "tenant-transit", actor, recording.ID, []byte("complete\n")); err != nil {
		t.Fatal(err)
	}
	completed, err := recordings.Finalize(ctx, "tenant-transit", actor, recording.ID)
	if err != nil || completed.State != "available" {
		t.Fatalf("Transit/PostgreSQL recording finalize=%#v error=%v", completed, err)
	}
	replayed, err := recordings.Replay(ctx, "tenant-transit", actor, recording.ID)
	if err != nil || len(replayed) != 2 || bytes.Contains(bytes.Join(replayed, nil), []byte("TRANSIT-SECRET")) || !bytes.Contains(replayed[0], []byte("[REDACTED]")) {
		t.Fatalf("Transit/PostgreSQL recording replay=%q error=%v", replayed, err)
	}
	for _, payload := range replayed {
		clear(payload)
	}
	if _, err := postgresPool.Exec(ctx, `UPDATE sandbox_runtime_product.recordings SET started_at=clock_timestamp()-interval '2 hours',retention_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND recording_id=$2`, "tenant-transit", recording.ID); err != nil {
		t.Fatal(err)
	}

	runIntegrationCommand(t, ctx, "docker", "pause", containerName)
	lossContext, lossCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer lossCancel()
	if _, err := restartedStore.ReadSegment(lossContext, "tenant-a", "recording-v2", v2Handle, 1, v2Reference); !errors.Is(err, product.ErrStoreUnavailable) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Vault loss error = %v", err)
	}
	if err := restartedStore.DeleteRecording(context.Background(), "tenant-a", "recording-v2", v2Handle); err != nil {
		t.Fatalf("Vault-loss cleanup = %v", err)
	}
	if count, err := recordings.CleanupExpired(context.Background(), 10); err != nil || count != 1 {
		t.Fatalf("Vault-loss PostgreSQL recording cleanup = %d, %v", count, err)
	}

	runIntegrationCommand(t, context.Background(), "docker", "unpause", containerName)
	waitForVaultHealth(t, ctx, httpClient, endpoint, rootToken)
	vaultWrite(t, ctx, httpClient, endpoint+"/v1/auth/token/revoke-self", tokenResponse.Auth.ClientToken, map[string]any{}, nil)
	assertVaultAccessorRevoked(t, ctx, httpClient, endpoint, rootToken, tokenResponse.Auth.Accessor)
	clear(tokenSourceBytes)
	if err := restartedStore.DeleteRecording(context.Background(), "tenant-a", "recording-v1", v1Handle); err != nil {
		t.Fatalf("v1 recording cleanup = %v", err)
	}
	if err := os.RemoveAll(storeRoot); err != nil {
		t.Fatal(err)
	}
	postgresPool.Close()
	runIntegrationCommand(t, context.Background(), "docker", "rm", "-f", containerName)
	vaultCleaned = true
	runIntegrationCommand(t, context.Background(), "docker", "rm", "-f", postgresContainer)
	postgresCleaned = true
	remaining := strings.TrimSpace(runIntegrationCommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+containerName+"$"))
	if remaining != "" {
		t.Fatal("Vault integration container cleanup is incomplete")
	}
	if remaining := strings.TrimSpace(runIntegrationCommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+postgresContainer+"$")); remaining != "" {
		t.Fatal("PostgreSQL integration container cleanup is incomplete")
	}
	if _, err := os.Lstat(storeRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recording directory cleanup = %v", err)
	}
	writeRecordingTransitEvidence(t, v1, v2)
}

func startRecordingPostgres(t *testing.T, ctx context.Context, container string) *pgxpool.Pool {
	t.Helper()
	runIntegrationCommand(t, ctx, "docker", "run", "-d", "--name", container,
		"-e", "POSTGRES_PASSWORD=phase6-recording", "-e", "POSTGRES_DB=phase6_recording",
		"-p", "127.0.0.1::5432", postgresIntegrationImage)
	portOutput := strings.TrimSpace(runIntegrationCommand(t, ctx, "docker", "port", container, "5432/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("PostgreSQL published port is unavailable")
	}
	port := portOutput[separator+1:]
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal("PostgreSQL published port is invalid")
	}
	dsn := "postgres://postgres:phase6-recording@127.0.0.1:" + port + "/phase6_recording?sslmode=disable"
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		probeContext, cancel := context.WithTimeout(ctx, time.Second)
		err = pool.Ping(probeContext)
		cancel()
		if err == nil {
			return pool
		}
		time.Sleep(200 * time.Millisecond)
	}
	pool.Close()
	t.Fatal("PostgreSQL did not become healthy")
	return nil
}

func assertVaultAccessorRevoked(t *testing.T, ctx context.Context, client *http.Client, endpoint, rootToken, accessor string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"accessor": accessor})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/auth/token/lookup-accessor", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", rootToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoked Vault token accessor status=%d", response.StatusCode)
	}
}

func writeRecordingTransitEvidence(t *testing.T, v1, v2 secretref.EnvelopeKeyVersion) {
	t.Helper()
	path := os.Getenv(vaultEvidencePathEnv)
	if path == "" {
		return
	}
	if !filepath.IsAbs(path) || !filepath.IsAbs(os.Getenv(desktopCandidateEnv)) {
		t.Fatal("formal recording Transit evidence paths must be absolute")
	}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := desktopcandidate.Load(os.Getenv(desktopCandidateEnv))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := productphase6evidence.BindRuntimeCandidate(candidate, root)
	if err != nil {
		t.Fatal(err)
	}
	bindings := []string{
		(secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindEnvelopeKey, Reference: v1.Reference, Version: v1.Version, KeyID: v1.KeyID, Purpose: secretref.PurposeRecordingEnvelopeKey, TenantID: "tenant-a", Role: secretref.RoleProduct}).Digest(),
		(secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindEnvelopeKey, Reference: v2.Reference, Version: v2.Version, KeyID: v2.KeyID, Purpose: secretref.PurposeRecordingEnvelopeKey, TenantID: "tenant-a", Role: secretref.RoleProduct}).Digest(),
	}
	evidence := slice5evidence.RecordingTransitEvidence{
		Harness:                       slice5evidence.RecordingHarness,
		RuntimeImplementationRevision: binding.RuntimeImplementationRevision, RuntimeImplementationTreeDigest: binding.RuntimeImplementationTreeDigest,
		EvidenceToolRevision: binding.EvidenceToolRevision, EvidenceToolTreeDigest: binding.EvidenceToolTreeDigest,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		CommandDigest: slice5evidence.Digest("sandbox-runtime/phase6-slice5/recording-command/v1", struct {
			Test, IntegrationVariable, VaultImage, PostgresImage string
		}{"TestVaultTransitRecordingStoreIntegration", vaultIntegrationEnv, vaultIntegrationImage, postgresIntegrationImage}),
		ConfigDigest: slice5evidence.Digest("sandbox-runtime/phase6-slice5/recording-config/v1", struct {
			Mount, Purpose, Role string
			Bindings             []string
		}{"transit", string(secretref.PurposeRecordingEnvelopeKey), string(secretref.RoleProduct), bindings}),
		VaultImage: vaultIntegrationImage, PostgresImage: postgresIntegrationImage, VaultTLS: true, VaultTransitMount: "transit",
		VaultKeyIdentityDigest: slice5evidence.Digest("sandbox-runtime/phase6-slice5/vault-key-identity/v1", "transit/recording-primary"),
		BindingDigest:          slice5evidence.Digest("sandbox-runtime/phase6-slice5/recording-binding-set/v1", bindings),
		Purpose:                secretref.PurposeRecordingEnvelopeKey, Role: secretref.RoleProduct, StoreSchema: storeDirectoryName, HandleSchema: "rkms1",
		CredentialClass: "vault_nonrenewable_scoped_token", RootCredentialUsedByAdapter: false, RawKeyExported: false, FreshPostgresSchema: true,
		Cleanup: []slice5evidence.Resource{{Name: "vault_containers", Count: 0}, {Name: "postgres_containers", Count: 0},
			{Name: "recording_directories", Count: 0}, {Name: "database_connections", Count: 0}, {Name: "scoped_vault_tokens", Count: 0}},
	}
	for _, name := range slice5evidence.ScenarioNames("recording") {
		evidence.Scenarios = append(evidence.Scenarios, slice5evidence.Scenario{Name: name, Outcome: "passed",
			EvidenceDigest: slice5evidence.Digest("sandbox-runtime/phase6-slice5/recording-scenario/v1", struct {
				Name, RuntimeRevision, ConfigDigest string
			}{name, binding.RuntimeImplementationRevision, evidence.ConfigDigest})})
	}
	sealed, err := slice5evidence.SealRecording(evidence)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	writePrivateIntegrationEvidence(t, path, document)
	verified, err := slice5evidence.VerifyRecordingFile(path)
	if err != nil || verified.EvidenceDigest != sealed.EvidenceDigest {
		t.Fatalf("verify recording Transit evidence: %#v %v", verified, err)
	}
}

func writePrivateIntegrationEvidence(t *testing.T, path string, document []byte) {
	t.Helper()
	temporary, err := os.CreateTemp(filepath.Dir(path), ".phase6-slice5-recording-*")
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil {
		_ = temporary.Close()
		t.Fatal("set recording evidence mode")
	}
	if _, err := temporary.Write(document); err != nil || temporary.Sync() != nil || temporary.Close() != nil || os.Rename(temporaryPath, path) != nil {
		_ = temporary.Close()
		t.Fatal("write recording evidence")
	}
}

func waitForVaultCA(t *testing.T, ctx context.Context, containerName, destination string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		command := exec.CommandContext(ctx, "docker", "exec", containerName, "cat", "/tmp/vault-tls/vault-ca.pem")
		certificate, err := command.Output()
		if err == nil && bytes.Contains(certificate, []byte("-----BEGIN CERTIFICATE-----")) {
			if err := os.WriteFile(destination, certificate, 0o600); err != nil {
				clear(certificate)
				t.Fatal("Vault integration CA could not be persisted")
			}
			clear(certificate)
			return
		}
		clear(certificate)
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("Vault TLS authority did not become available")
}

func waitForVaultHealth(t *testing.T, ctx context.Context, client *http.Client, endpoint, token string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/sys/health", nil)
		request.Header.Set("X-Vault-Token", token)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("Vault did not become healthy")
}

func vaultWrite(t *testing.T, ctx context.Context, client *http.Client, target, token string, requestBody any, responseTarget any) {
	t.Helper()
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("Vault setup request failed")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	if err != nil || (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent) {
		clear(responseBody)
		t.Fatal("Vault setup request was rejected")
	}
	defer clear(responseBody)
	if responseTarget != nil && json.Unmarshal(responseBody, responseTarget) != nil {
		t.Fatal("Vault setup response is invalid")
	}
}

func runIntegrationCommand(t *testing.T, ctx context.Context, name string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, name, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		clear(output)
		t.Fatalf("integration command %q failed", name)
	}
	result := string(output)
	clear(output)
	return result
}
