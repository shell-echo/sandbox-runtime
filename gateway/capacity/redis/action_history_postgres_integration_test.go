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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	integrationPostgresAdminURLVariable   = "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_ADMIN_URL"
	integrationPostgresRuntimeURLVariable = "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_URL"
	integrationPostgresDeniedURLVariable  = "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_DENIED_URL"
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
			witness := first
			if index%2 != 0 {
				witness = second
			}
			provisionErrors <- witness.Provision(context.Background(), policy, initial)
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
	policy := strings.Repeat("d", 64)
	cleanupIntegrationPostgresWitness(t, admin, witness, policy)
	initial := mustActionHistoryCheckpoint(t, 0, "e")
	if err := witness.Provision(context.Background(), policy, initial); err != nil {
		t.Fatal(err)
	}

	for _, statement := range []string{
		"DELETE FROM sandbox_runtime.action_history_witnesses WHERE false",
		"TRUNCATE TABLE sandbox_runtime.action_history_witnesses",
		"UPDATE sandbox_runtime.action_history_witnesses SET policy_fingerprint = policy_fingerprint WHERE false",
		"CREATE TABLE sandbox_runtime.runtime_must_not_create (value integer)",
		"CREATE SCHEMA runtime_must_not_create",
	} {
		if _, err := runtime.Exec(context.Background(), statement); err == nil {
			t.Fatalf("runtime role executed forbidden statement %q", statement)
		}
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
	provisionIntegrationWitnessedActionFencer(t, fencer)
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
