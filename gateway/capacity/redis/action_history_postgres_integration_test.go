//go:build integration

package rediscapacity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	integrationPostgresAdminURLVariable    = "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_ADMIN_URL"
	integrationPostgresRuntimeURLVariable  = "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_URL"
	integrationPostgresDeniedURLVariable   = "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_DENIED_URL"
	integrationPostgresMutableRoleVariable = "SANDBOX_RUNTIME_ACTION_HISTORY_MUTABLE_ROLE_TEST"
)

func TestIntegrationPostgresActionHistoryWitnessConcurrentCASAndReconnect(t *testing.T) {
	admin := integrationPostgresPool(t, integrationPostgresAdminURLVariable, 2)
	firstPool := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 4)
	secondPool := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 4)
	options := testOptions(t)
	options.Namespace = integrationNamespace(t)
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	first := integrationPostgresWitness(t, capacity, firstPool, 500*time.Millisecond)
	second := integrationPostgresWitness(t, capacity, secondPool, 500*time.Millisecond)
	provisioner := integrationPostgresWitness(t, capacity, admin, 500*time.Millisecond)
	policy := strings.Repeat("a", 64)
	cleanupIntegrationPostgresWitness(t, admin, first, policy)
	initial := mustActionHistoryCheckpoint(t, 0, "b")

	const provisioners = 16
	start := make(chan struct{})
	provisionErrors := make(chan error, provisioners)
	var wait sync.WaitGroup
	for index := 0; index < provisioners; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			provisionErrors <- provisioner.Provision(context.Background(), policy, initial)
		}(index)
	}
	close(start)
	wait.Wait()
	close(provisionErrors)
	for err := range provisionErrors {
		if err != nil {
			t.Fatalf("concurrent Provision() error = %v", err)
		}
	}

	const contenders = 24
	start = make(chan struct{})
	type casResult struct {
		checkpoint ActionHistoryCheckpoint
		err        error
	}
	results := make(chan casResult, contenders)
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			witness := first
			if index%2 != 0 {
				witness = second
			}
			token := fmt.Sprintf("%064x", index+1)
			replacement, checkpointErr := NewActionHistoryCheckpoint(1, token)
			if checkpointErr != nil {
				results <- casResult{err: checkpointErr}
				return
			}
			results <- casResult{checkpoint: replacement, err: witness.CompareAndSwap(
				context.Background(), policy, initial, replacement,
			)}
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	winners := 0
	var winner ActionHistoryCheckpoint
	for result := range results {
		switch {
		case result.err == nil:
			winners++
			winner = result.checkpoint
		case errors.Is(result.err, ErrActionHistoryConflict):
		default:
			t.Fatalf("concurrent CompareAndSwap() error = %v", result.err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent CAS winners = %d; want 1", winners)
	}

	firstPool.Reset()
	if current, err := first.Load(context.Background(), policy); err != nil || !current.Equal(winner) {
		t.Fatalf("Load() after pool reset = %v, %v; want winner", current, err)
	}
	thirdPool := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 2)
	reconstructed := integrationPostgresWitness(t, capacity, thirdPool, 500*time.Millisecond)
	if current, err := reconstructed.Load(context.Background(), policy); err != nil || !current.Equal(winner) {
		t.Fatalf("reconstructed Load() = %v, %v; want winner", current, err)
	}
	if _, err := reconstructed.Load(context.Background(), strings.Repeat("c", 64)); !errors.Is(err, ErrActionHistoryNotProvisioned) {
		t.Fatalf("missing policy Load() error = %v", err)
	}
}

func TestIntegrationPostgresActionHistoryWitnessSchemaAndRoleFailClosed(t *testing.T) {
	admin := integrationPostgresPool(t, integrationPostgresAdminURLVariable, 2)
	runtime := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 2)
	denied := integrationPostgresPool(t, integrationPostgresDeniedURLVariable, 2)
	options := testOptions(t)
	options.Namespace = integrationNamespace(t)
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	witness := integrationPostgresWitness(t, capacity, runtime, 500*time.Millisecond)
	provisioner := integrationPostgresWitness(t, capacity, admin, 500*time.Millisecond)
	if err := VerifyPostgresActionHistoryRuntimeRole(context.Background(), runtime,
		runtime.Config().ConnConfig.Database, runtime.Config().ConnConfig.User); err != nil {
		t.Fatalf("least-privilege runtime role refused: %v", err)
	}
	for name, pool := range map[string]*pgxpool.Pool{"migration owner": admin, "denied role": denied} {
		t.Run(name+" rejected for runtime", func(t *testing.T) {
			if err := VerifyPostgresActionHistoryRuntimeRole(context.Background(), pool,
				pool.Config().ConnConfig.Database, pool.Config().ConnConfig.User); !errors.Is(err, ErrActionHistoryUnavailable) {
				t.Fatalf("unsafe runtime role accepted: %v", err)
			}
		})
	}
	if err := VerifyPostgresActionHistoryRuntimeRole(context.Background(), runtime,
		"wrong_database", runtime.Config().ConnConfig.User); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("wrong database accepted: %v", err)
	}
	if err := VerifyPostgresActionHistoryRuntimeRole(context.Background(), runtime,
		runtime.Config().ConnConfig.Database, "wrong_role"); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("wrong role accepted: %v", err)
	}
	policy := strings.Repeat("d", 64)
	cleanupIntegrationPostgresWitness(t, admin, witness, policy)
	initial := mustActionHistoryCheckpoint(t, 0, "e")
	if err := provisioner.Provision(context.Background(), policy, initial); err != nil {
		t.Fatal(err)
	}
	if err := witness.Provision(context.Background(), strings.Repeat("9", 64), initial); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("runtime Provision() unexpectedly succeeded: %v", err)
	}

	namespaceBytes := witness.namespaceFingerprint
	policyBytes, err := decodeActionHistoryFingerprint(policy)
	if err != nil {
		t.Fatal(err)
	}
	validToken := bytes.Repeat([]byte{0x7a}, 32)
	deniedPolicy := bytes.Repeat([]byte{0x7b}, 32)
	adminUser := admin.Config().ConnConfig.User
	if adminUser == runtime.Config().ConnConfig.User {
		t.Fatal("migration owner and runtime must be distinct roles")
	}
	for name, attempt := range map[string]func() error{
		"insert": func() error {
			_, err := runtime.Exec(context.Background(), `INSERT INTO sandbox_runtime.action_history_witnesses
(namespace_fingerprint, policy_fingerprint, format_version, sequence, token) VALUES ($1,$2,1,0,$3)`,
				namespaceBytes[:], deniedPolicy, validToken)
			return err
		},
		"delete": func() error {
			_, err := runtime.Exec(context.Background(), `DELETE FROM sandbox_runtime.action_history_witnesses
WHERE namespace_fingerprint=$1 AND policy_fingerprint=$2`, namespaceBytes[:], policyBytes[:])
			return err
		},
		"truncate": func() error {
			_, err := runtime.Exec(context.Background(), `TRUNCATE TABLE sandbox_runtime.action_history_witnesses`)
			return err
		},
		"identity update": func() error {
			_, err := runtime.Exec(context.Background(), `UPDATE sandbox_runtime.action_history_witnesses
SET policy_fingerprint=policy_fingerprint WHERE namespace_fingerprint=$1 AND policy_fingerprint=$2`,
				namespaceBytes[:], policyBytes[:])
			return err
		},
		"table DDL": func() error {
			_, err := runtime.Exec(context.Background(), `CREATE TABLE sandbox_runtime.runtime_must_not_create (value integer)`)
			return err
		},
		"schema DDL": func() error {
			_, err := runtime.Exec(context.Background(), `CREATE SCHEMA runtime_must_not_create`)
			return err
		},
		"role escalation": func() error {
			_, err := runtime.Exec(context.Background(), `ALTER ROLE `+
				pgx.Identifier{runtime.Config().ConnConfig.User}.Sanitize()+` CREATEROLE`)
			return err
		},
		"owner escalation": func() error {
			_, err := runtime.Exec(context.Background(), `ALTER TABLE sandbox_runtime.action_history_witnesses OWNER TO `+
				pgx.Identifier{runtime.Config().ConnConfig.User}.Sanitize())
			return err
		},
		"set admin role": func() error {
			_, err := runtime.Exec(context.Background(), `SET ROLE `+pgx.Identifier{adminUser}.Sanitize())
			return err
		},
		"set provisioner role": func() error {
			_, err := runtime.Exec(context.Background(), `SET ROLE sandbox_witness_provisioner`)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			var pgErr *pgconn.PgError
			if err := attempt(); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("runtime privilege denial SQLSTATE = %v; want 42501", postgresSQLState(err))
			}
		})
	}
	// PostgreSQL can return a successful GRANT command with a warning when a
	// non-owner has no grant option. Assert the effective privilege, not only
	// the command result.
	_, _ = runtime.Exec(context.Background(), `GRANT INSERT ON sandbox_runtime.action_history_witnesses TO `+
		pgx.Identifier{runtime.Config().ConnConfig.User}.Sanitize())
	var canInsert bool
	if err := runtime.QueryRow(context.Background(), `SELECT has_table_privilege(current_user,
'sandbox_runtime.action_history_witnesses', 'INSERT')`).Scan(&canInsert); err != nil || canInsert {
		t.Fatalf("runtime acquired INSERT through GRANT: scan error=%v, privilege=%v", err, canInsert)
	}

	deniedWitness := integrationPostgresWitness(t, capacity, denied, 500*time.Millisecond)
	if _, err := deniedWitness.Load(context.Background(), policy); !errors.Is(err, ErrActionHistoryUnavailable) ||
		strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(err.Error(), policy) {
		t.Fatalf("denied Load() exposed database detail: %v", err)
	}

	for _, test := range []struct {
		name      string
		namespace []byte
		policy    []byte
		version   int16
		sequence  int64
		token     []byte
	}{
		{name: "short namespace", namespace: []byte{1}, policy: bytes.Repeat([]byte{2}, 32), version: 1, token: bytes.Repeat([]byte{3}, 32)},
		{name: "short policy", namespace: bytes.Repeat([]byte{1}, 32), policy: []byte{2}, version: 1, token: bytes.Repeat([]byte{3}, 32)},
		{name: "wrong format", namespace: bytes.Repeat([]byte{1}, 32), policy: bytes.Repeat([]byte{2}, 32), version: 2, token: bytes.Repeat([]byte{3}, 32)},
		{name: "negative sequence", namespace: bytes.Repeat([]byte{1}, 32), policy: bytes.Repeat([]byte{2}, 32), version: 1, sequence: -1, token: bytes.Repeat([]byte{3}, 32)},
		{name: "short token", namespace: bytes.Repeat([]byte{1}, 32), policy: bytes.Repeat([]byte{2}, 32), version: 1, token: []byte{3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := admin.Exec(context.Background(), postgresActionHistoryProvisionQuery,
				test.namespace, test.policy, test.version, test.sequence, test.token); err == nil {
				t.Fatal("schema accepted a malformed witness row")
			}
		})
	}
}

func postgresSQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	if err == nil {
		return "<nil>"
	}
	return "<non-postgres-error>"
}

func TestIntegrationPostgresActionHistoryWitnessOperationTimeout(t *testing.T) {
	pool := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 1)
	connection, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	options := testOptions(t)
	options.Namespace = integrationNamespace(t)
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	witness := integrationPostgresWitness(t, capacity, pool, MinOperationTimeout)
	started := time.Now()
	_, err = witness.Load(context.Background(), strings.Repeat("f", 64))
	if !errors.Is(err, ErrActionHistoryUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Load() error = %v; want bounded deadline", err)
	}
	if elapsed := time.Since(started); elapsed < MinOperationTimeout || elapsed > 4*MinOperationTimeout {
		t.Fatalf("Load() elapsed = %s; want bounded operation", elapsed)
	}
}

func TestIntegrationPostgresActionHistoryRuntimeRoleInheritedPrivilegeDrift(t *testing.T) {
	if os.Getenv(integrationPostgresMutableRoleVariable) != "1" {
		t.Skip("set SANDBOX_RUNTIME_ACTION_HISTORY_MUTABLE_ROLE_TEST=1 only for a disposable witness database")
	}
	admin := integrationPostgresPool(t, integrationPostgresAdminURLVariable, 2)
	runtime := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 2)
	database, role := runtime.Config().ConnConfig.Database, runtime.Config().ConnConfig.User
	if err := VerifyPostgresActionHistoryRuntimeRole(context.Background(), runtime, database, role); err != nil {
		t.Fatalf("initial runtime role unsafe: %v", err)
	}
	roleName := pgx.Identifier{role}.Sanitize()
	const provisioner = `sandbox_witness_provisioner`
	if _, err := admin.Exec(context.Background(), `GRANT `+provisioner+` TO `+roleName); err != nil {
		t.Fatal("grant test-only provisioner membership failed")
	}
	revoke := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := admin.Exec(ctx, `REVOKE `+provisioner+` FROM `+roleName)
		return err
	}
	t.Cleanup(func() {
		if err := revoke(); err != nil {
			t.Error("test-only provisioner membership cleanup failed")
		}
	})
	if err := VerifyPostgresActionHistoryRuntimeRole(context.Background(), runtime, database, role); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("inherited provisioner authority accepted: %v", err)
	}
	if err := revoke(); err != nil {
		t.Fatal("revoke test-only provisioner membership failed")
	}
	if err := VerifyPostgresActionHistoryRuntimeRole(context.Background(), runtime, database, role); err != nil {
		t.Fatalf("runtime role not restored after exact revoke: %v", err)
	}
}

func TestIntegrationPostgresWitnessRejectsRestoredRedisSnapshot(t *testing.T) {
	admin := integrationPostgresPool(t, integrationPostgresAdminURLVariable, 2)
	runtime := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 2)
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	witness := integrationPostgresWitness(t, shared.capacity, runtime, 500*time.Millisecond)
	fencer, err := NewWitnessedActionFencer(shared.capacity, witness)
	if err != nil {
		t.Fatal(err)
	}
	cleanupIntegrationWitnessedActionState(t, shared, fencer)
	cleanupIntegrationPostgresWitness(t, admin, witness, fencer.policyFingerprint())
	provisioner := integrationPostgresWitness(t, shared.capacity, admin, 500*time.Millisecond)
	provisioningFencer, err := NewWitnessedActionFencer(shared.capacity, provisioner)
	if err != nil {
		t.Fatal(err)
	}
	provisionIntegrationWitnessedActionFencer(t, provisioningFencer)
	if err := fencer.VerifyRestoredState(context.Background()); err != nil {
		t.Fatalf("initial VerifyRestoredState() error = %v", err)
	}
	initialState, err := shared.client.HGetAll(context.Background(), fencer.stateKey).Result()
	if err != nil || len(initialState) == 0 {
		t.Fatalf("initial Redis state = %#v, %v", initialState, err)
	}

	capacitySubject := integrationSubject("tenant-postgres-restore", "sandbox-postgres-restore", "browser-postgres-restore", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
	if err != nil || !decision.Activated {
		t.Fatalf("AuthorizeAction() = %#v, %v", decision, err)
	}
	lease.stopOnce.Do(func() { close(lease.stop) })
	<-lease.done

	if err := shared.client.Del(context.Background(), shared.capacity.keys[0], fencer.stateKey).Err(); err != nil {
		t.Fatal(err)
	}
	if err := shared.client.Set(context.Background(), shared.capacity.keys[2], "0", 0).Err(); err != nil {
		t.Fatal(err)
	}
	stateValues := make([]any, 0, len(initialState)*2)
	for field, value := range initialState {
		stateValues = append(stateValues, field, value)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, stateValues...).Err(); err != nil {
		t.Fatal(err)
	}

	reconstructedPool := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 2)
	reconstructedWitness := integrationPostgresWitness(t, shared.capacity, reconstructedPool, 500*time.Millisecond)
	reconstructed, err := NewWitnessedActionFencer(shared.capacity, reconstructedWitness)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconstructed.VerifyRestoredState(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("VerifyRestoredState() after rollback error = %v; want unavailable", err)
	}
	if err := reconstructed.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() after rollback error = %v; want unavailable", err)
	}

	replacement := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	if integrationMemberFence(t, replacement.member) != integrationMemberFence(t, lease.member) {
		t.Fatal("restored capacity counter did not reproduce the stale numerical fence")
	}
	assertWitnessedActionUnavailable(t, reconstructed, actionSubject, integrationActionClaim(t, replacement))
	releaseIntegrationLease(t, replacement)
}

func TestIntegrationPostgresWitnessMissingRowFailsClosed(t *testing.T) {
	admin := integrationPostgresPool(t, integrationPostgresAdminURLVariable, 2)
	runtime := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 2)
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	witness := integrationPostgresWitness(t, shared.capacity, runtime, 500*time.Millisecond)
	fencer, err := NewWitnessedActionFencer(shared.capacity, witness)
	if err != nil {
		t.Fatal(err)
	}
	cleanupIntegrationWitnessedActionState(t, shared, fencer)
	cleanupIntegrationPostgresWitness(t, admin, witness, fencer.policyFingerprint())
	provisioner := integrationPostgresWitness(t, shared.capacity, admin, 500*time.Millisecond)
	provisioningFencer, err := NewWitnessedActionFencer(shared.capacity, provisioner)
	if err != nil {
		t.Fatal(err)
	}
	provisionIntegrationWitnessedActionFencer(t, provisioningFencer)
	before, err := shared.client.HGetAll(context.Background(), fencer.stateKey).Result()
	if err != nil || len(before) == 0 {
		t.Fatal("provisioned Redis checkpoint missing")
	}
	policy, err := decodeActionHistoryFingerprint(fencer.policyFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(context.Background(), `DELETE FROM sandbox_runtime.action_history_witnesses
WHERE namespace_fingerprint=$1 AND policy_fingerprint=$2`, witness.namespaceFingerprint[:], policy[:]); err != nil {
		t.Fatal("admin delete witness failed")
	}
	if err := fencer.VerifyRestoredState(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("VerifyRestoredState() without witness = %v; want unavailable", err)
	}
	if err := fencer.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() without witness = %v; want unavailable", err)
	}
	capacitySubject := integrationSubject("tenant-missing-row", "sandbox-missing-row", "browser-missing-row", time.Minute)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	assertWitnessedActionUnavailable(t, fencer, actionSubject, integrationActionClaim(t, lease))
	releaseIntegrationLease(t, lease)
	if _, err := witness.Load(context.Background(), fencer.policyFingerprint()); !errors.Is(err, ErrActionHistoryNotProvisioned) {
		t.Fatalf("runtime recreated missing witness: %v", err)
	}
	after, err := shared.client.HGetAll(context.Background(), fencer.stateKey).Result()
	if err != nil || len(after) != len(before) {
		t.Fatal("runtime changed Redis checkpoint after missing witness")
	}
	for key, value := range before {
		if after[key] != value {
			t.Fatal("runtime changed Redis checkpoint after missing witness")
		}
	}
}

func TestIntegrationPostgresWitnessRecoversUnwitnessedCommit(t *testing.T) {
	admin := integrationPostgresPool(t, integrationPostgresAdminURLVariable, 2)
	runtime := integrationPostgresPool(t, integrationPostgresRuntimeURLVariable, 2)
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	witness := integrationPostgresWitness(t, shared.capacity, runtime, 500*time.Millisecond)
	failingWitness := &failBeforeAdvanceWitness{ActionHistoryWitness: witness, fail: true}
	fencer, err := NewWitnessedActionFencer(shared.capacity, failingWitness)
	if err != nil {
		t.Fatal(err)
	}
	cleanupIntegrationWitnessedActionState(t, shared, fencer)
	cleanupIntegrationPostgresWitness(t, admin, witness, fencer.policyFingerprint())
	provisioner := integrationPostgresWitness(t, shared.capacity, admin, 500*time.Millisecond)
	provisioningFencer, err := NewWitnessedActionFencer(shared.capacity, provisioner)
	if err != nil {
		t.Fatal(err)
	}
	provisionIntegrationWitnessedActionFencer(t, provisioningFencer)
	capacitySubject := integrationSubject("tenant-pg-interrupt", "sandbox-pg-interrupt", "browser-pg-interrupt", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
	if decision.Activated || err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("interrupted AuthorizeAction() = %#v, %v; want unavailable", decision, err)
	}
	checkpoint, err := witness.Load(context.Background(), fencer.policyFingerprint())
	if err != nil || checkpoint.sequence != 0 {
		t.Fatalf("witness advanced during injected failure: %v, %v", checkpoint, err)
	}
	if err := fencer.VerifyRestoredState(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("strict restore check with Redis ahead = %v; want unavailable", err)
	}
	checkpoint, err = witness.Load(context.Background(), fencer.policyFingerprint())
	if err != nil || checkpoint.sequence != 0 {
		t.Fatalf("strict restore check advanced witness: %v, %v", checkpoint, err)
	}
	if err := fencer.Verify(context.Background()); err != nil {
		t.Fatalf("runtime Verify() failed one-step recovery: %v", err)
	}
	checkpoint, err = witness.Load(context.Background(), fencer.policyFingerprint())
	if err != nil || checkpoint.sequence != 1 {
		t.Fatalf("recovered witness checkpoint = %v, %v; want sequence 1", checkpoint, err)
	}
	if err := fencer.VerifyRestoredState(context.Background()); err != nil {
		t.Fatalf("strict restore check after recovery = %v", err)
	}
	assertWitnessedActionCurrent(t, fencer, actionSubject, claim)
	releaseIntegrationLease(t, lease)
}

func integrationPostgresPool(t *testing.T, variable string, maxConnections int32) *pgxpool.Pool {
	t.Helper()
	connectionString := os.Getenv(variable)
	if connectionString == "" {
		t.Fatalf("%s is required for PostgreSQL integration tests", variable)
	}
	config, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		t.Fatalf("parse %s failed", variable)
	}
	config.MaxConns = maxConnections
	config.MinConns = 0
	config.MinIdleConns = 0
	config.MaxConnLifetime = time.Minute
	config.MaxConnIdleTime = time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	config.PingTimeout = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect %s failed", variable)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping %s failed", variable)
	}
	t.Cleanup(pool.Close)
	return pool
}

func integrationPostgresWitness(
	t *testing.T,
	capacity *Capacity,
	pool *pgxpool.Pool,
	operationTimeout time.Duration,
) *PostgresActionHistoryWitness {
	t.Helper()
	witness, err := NewPostgresActionHistoryWitness(PostgresActionHistoryWitnessOptions{
		Capacity: capacity, Pool: pool, OperationTimeout: operationTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return witness
}

func cleanupIntegrationPostgresWitness(
	t *testing.T,
	admin *pgxpool.Pool,
	witness *PostgresActionHistoryWitness,
	policyFingerprint string,
) {
	t.Helper()
	policy, err := decodeActionHistoryFingerprint(policyFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = admin.Exec(ctx, `DELETE FROM sandbox_runtime.action_history_witnesses
WHERE namespace_fingerprint = $1 AND policy_fingerprint = $2`, witness.namespaceFingerprint[:], policy[:])
	})
}
