//go:build integration

package rediscapacity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestIntegrationWitnessedActionFencingDetectsDeletedHistory(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	fencer, witness := newIntegrationWitnessedActionFencer(t, shared)
	if err := fencer.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("unprovisioned Verify() error = %v", err)
	}
	provisionIntegrationWitnessedActionFencer(t, fencer)

	capacitySubject := integrationSubject("tenant-witness", "sandbox-witness", "browser-witness", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)

	const contenders = 16
	start := make(chan struct{})
	results := make(chan gateway.DownstreamFenceDecision, contenders)
	errorsByCall := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
			results <- decision
			errorsByCall <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsByCall)
	activated := 0
	for decision := range results {
		if decision.Activated {
			activated++
		}
	}
	for err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent AuthorizeAction() error = %v", err)
		}
	}
	if activated != 1 {
		t.Fatalf("concurrent activations = %d; want 1", activated)
	}
	checkpoint, err := witness.Load(context.Background(), fencer.policyFingerprint())
	if err != nil || checkpoint.sequence != 1 {
		t.Fatalf("witness checkpoint = %v, %v; want sequence 1", checkpoint, err)
	}

	sessionField := "session:" + integrationSessionFingerprint(capacitySubject)
	highWaterValue, err := shared.client.HGet(context.Background(), fencer.stateKey, sessionField).Result()
	if err != nil || highWaterValue == "" {
		t.Fatalf("high-water value = %q, %v", highWaterValue, err)
	}
	if ttl, err := shared.client.PTTL(context.Background(), fencer.stateKey).Result(); err != nil || ttl != -1 {
		t.Fatalf("state PTTL = %s, %v; want persistent", ttl, err)
	}
	assertNoSensitiveWitnessedActionState(t, shared, fencer, []string{
		capacitySubject.TenantID, capacitySubject.SandboxID, capacitySubject.BrowserSessionID,
	})

	if err := shared.client.HDel(context.Background(), fencer.stateKey, sessionField).Err(); err != nil {
		t.Fatal(err)
	}
	assertWitnessedActionUnavailable(t, fencer, actionSubject, claim)
	if err := shared.client.HSet(context.Background(), fencer.stateKey, "unexpected-replacement", highWaterValue).Err(); err != nil {
		t.Fatal(err)
	}
	if err := fencer.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() after equal-cardinality field replacement error = %v", err)
	}
	if err := shared.client.HDel(context.Background(), fencer.stateKey, "unexpected-replacement").Err(); err != nil {
		t.Fatal(err)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, sessionField, highWaterValue).Err(); err != nil {
		t.Fatal(err)
	}
	assertWitnessedActionCurrent(t, fencer, actionSubject, claim)
	if err := shared.client.HSet(context.Background(), fencer.stateKey, sessionField, "malformed-history").Err(); err != nil {
		t.Fatal(err)
	}
	if err := fencer.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() with malformed retained history error = %v", err)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, sessionField, highWaterValue).Err(); err != nil {
		t.Fatal(err)
	}

	if err := shared.client.Del(context.Background(), fencer.stateKey).Err(); err != nil {
		t.Fatal(err)
	}
	assertWitnessedActionUnavailable(t, fencer, actionSubject, claim)
	releaseIntegrationLease(t, lease)
}

func TestIntegrationWitnessedActionFencingRejectsRestoredRedisSnapshot(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	witnessPath := filepath.Join(t.TempDir(), "independent-witness.json")
	witness, err := OpenFileActionHistoryWitness(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	fencer, err := NewWitnessedActionFencer(shared.capacity, witness)
	if err != nil {
		t.Fatal(err)
	}
	cleanupIntegrationWitnessedActionState(t, shared, fencer)
	provisionIntegrationWitnessedActionFencer(t, fencer)
	initialCheckpoint, err := shared.client.HGetAll(context.Background(), fencer.stateKey).Result()
	if err != nil || len(initialCheckpoint) == 0 {
		t.Fatalf("initial checkpoint = %#v, %v", initialCheckpoint, err)
	}

	capacitySubject := integrationSubject("tenant-restore", "sandbox-restore", "browser-restore", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
	if err != nil || !decision.Activated {
		t.Fatalf("AuthorizeAction() = %#v, %v", decision, err)
	}
	lease.stopOnce.Do(func() { close(lease.stop) })
	<-lease.done

	// Restore the internally consistent pre-activation Redis state. The old
	// capacity fence can now mint the same numerical fence again, but the
	// independently retained witness remains at sequence one.
	if err := shared.client.Del(context.Background(), shared.capacity.keys[0], fencer.stateKey).Err(); err != nil {
		t.Fatal(err)
	}
	if err := shared.client.Set(context.Background(), shared.capacity.keys[2], "0", 0).Err(); err != nil {
		t.Fatal(err)
	}
	checkpointValues := make([]any, 0, len(initialCheckpoint)*2)
	for field, value := range initialCheckpoint {
		checkpointValues = append(checkpointValues, field, value)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, checkpointValues...).Err(); err != nil {
		t.Fatal(err)
	}
	if err := witness.Close(); err != nil {
		t.Fatal(err)
	}
	reconstructedWitness, err := OpenFileActionHistoryWitness(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reconstructedWitness.Close()
	reconstructed, err := NewWitnessedActionFencer(shared.capacity, reconstructedWitness)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconstructed.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() after restored snapshot error = %v; want unavailable", err)
	}

	replacement := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	if integrationMemberFence(t, replacement.member) != integrationMemberFence(t, lease.member) {
		t.Fatal("restored capacity counter did not reproduce the stale numerical fence")
	}
	replacementClaim := integrationActionClaim(t, replacement)
	assertWitnessedActionUnavailable(t, reconstructed, actionSubject, replacementClaim)
	releaseIntegrationLease(t, replacement)
}

func TestIntegrationWitnessedActionFencingRecoversUnwitnessedCommit(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	baseWitness, err := OpenFileActionHistoryWitness(filepath.Join(t.TempDir(), "witness.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer baseWitness.Close()
	failingWitness := &failBeforeAdvanceWitness{ActionHistoryWitness: baseWitness, fail: true}
	fencer, err := NewWitnessedActionFencer(shared.capacity, failingWitness)
	if err != nil {
		t.Fatal(err)
	}
	cleanupIntegrationWitnessedActionState(t, shared, fencer)
	provisionIntegrationWitnessedActionFencer(t, fencer)

	capacitySubject := integrationSubject("tenant-interrupt", "sandbox-interrupt", "browser-interrupt", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
	if decision.Activated || err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("interrupted AuthorizeAction() = %#v, %v; want unavailable", decision, err)
	}
	checkpoint, err := baseWitness.Load(context.Background(), fencer.policyFingerprint())
	if err != nil || checkpoint.sequence != 0 {
		t.Fatalf("witness advanced during injected failure: %v, %v", checkpoint, err)
	}
	if err := fencer.VerifyRestoredState(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("VerifyRestoredState() with Redis ahead error = %v; want unavailable", err)
	}
	checkpoint, err = baseWitness.Load(context.Background(), fencer.policyFingerprint())
	if err != nil || checkpoint.sequence != 0 {
		t.Fatalf("strict restore verification advanced witness: %v, %v", checkpoint, err)
	}
	if err := fencer.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() did not finish the conservative checkpoint: %v", err)
	}
	checkpoint, err = baseWitness.Load(context.Background(), fencer.policyFingerprint())
	if err != nil || checkpoint.sequence != 1 {
		t.Fatalf("recovered witness checkpoint = %v, %v; want sequence 1", checkpoint, err)
	}
	if err := fencer.VerifyRestoredState(context.Background()); err != nil {
		t.Fatalf("VerifyRestoredState() at exact checkpoint error = %v", err)
	}
	assertWitnessedActionCurrent(t, fencer, actionSubject, claim)
	releaseIntegrationLease(t, lease)
}

func TestIntegrationWitnessedActionFencingSuccessorAndStateValidation(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	fencer, _ := newIntegrationWitnessedActionFencer(t, shared)
	provisionIntegrationWitnessedActionFencer(t, fencer)

	capacitySubject := integrationSubject("tenant-successor", "sandbox-successor", "browser-successor", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 3)
	oldLease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	oldClaim := integrationActionClaim(t, oldLease)
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, oldClaim, 50*time.Millisecond)
	if err != nil || !decision.Activated {
		t.Fatalf("initial AuthorizeAction() = %#v, %v", decision, err)
	}

	mutatedSubject := actionSubject
	mutatedSubject.ConnectionGeneration++
	assertWitnessedActionUnavailable(t, fencer, mutatedSubject, oldClaim)
	if err := shared.client.HSet(context.Background(), fencer.stateKey, "history_count", "0").Err(); err != nil {
		t.Fatal(err)
	}
	if err := fencer.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() with invalid history count error = %v", err)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, "history_count", "1").Err(); err != nil {
		t.Fatal(err)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, "unexpected", "value").Err(); err != nil {
		t.Fatal(err)
	}
	if err := fencer.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() with extra state error = %v", err)
	}
	if err := shared.client.HDel(context.Background(), fencer.stateKey, "unexpected").Err(); err != nil {
		t.Fatal(err)
	}
	if err := fencer.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() after exact repair error = %v", err)
	}
	currentToken, err := shared.client.HGet(context.Background(), fencer.stateKey, "token").Result()
	if err != nil {
		t.Fatal(err)
	}
	previousToken, err := shared.client.HGet(context.Background(), fencer.stateKey, "previous_token").Result()
	if err != nil {
		t.Fatal(err)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, "previous_token", currentToken).Err(); err != nil {
		t.Fatal(err)
	}
	if err := fencer.Verify(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Verify() with repeated checkpoint token error = %v", err)
	}
	if err := shared.client.HSet(context.Background(), fencer.stateKey, "previous_token", previousToken).Err(); err != nil {
		t.Fatal(err)
	}

	releaseIntegrationLease(t, oldLease)
	successorLease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	if integrationMemberFence(t, successorLease.member) <= integrationMemberFence(t, oldLease.member) {
		t.Fatal("successor did not receive a higher capacity fence")
	}
	successorClaim := integrationActionClaim(t, successorLease)
	decision, err = fencer.AuthorizeAction(context.Background(), actionSubject, successorClaim, 50*time.Millisecond)
	if err != nil || !decision.Activated {
		t.Fatalf("successor AuthorizeAction() = %#v, %v", decision, err)
	}
	assertWitnessedActionCurrent(t, fencer, actionSubject, successorClaim)
	if decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, oldClaim, 50*time.Millisecond); decision.Activated ||
		err != gateway.ErrDownstreamFenceLost {
		t.Fatalf("stale AuthorizeAction() = %#v, %v; want lost", decision, err)
	}
	releaseIntegrationLease(t, successorLease)
}

func TestIntegrationWitnessedActionFencingDoesNotRewriteV1Namespace(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	legacy := newIntegrationActionFencer(t, shared)
	provisionIntegrationActionFencer(t, legacy)
	witness, err := OpenFileActionHistoryWitness(filepath.Join(t.TempDir(), "witness.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer witness.Close()
	fencer, err := NewWitnessedActionFencer(shared.capacity, witness)
	if err != nil {
		t.Fatal(err)
	}
	if err := fencer.Provision(context.Background()); err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("Provision() over v1 namespace error = %v", err)
	}
	if _, err := witness.Load(context.Background(), fencer.policyFingerprint()); !errors.Is(err, ErrActionHistoryNotProvisioned) {
		t.Fatalf("witness after rejected v1 preflight error = %v; want not provisioned", err)
	}
	format, err := shared.client.HGet(context.Background(), legacy.policyKey, "format").Result()
	if err != nil || format != actionPolicyFormat {
		t.Fatalf("legacy policy format = %q, %v", format, err)
	}
}

func TestIntegrationWitnessedActionFencingFailsClosedAtHistoryBound(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	fencer, witness := newIntegrationWitnessedActionFencer(t, shared)
	provisionIntegrationWitnessedActionFencer(t, fencer)

	fields := make([]any, 0, maxWitnessedActionHistoryEntries*2+2)
	for index := 0; index < maxWitnessedActionHistoryEntries; index++ {
		session := fmt.Sprintf("%064x", index)
		value := fmt.Sprintf("%032x:%020d:%064x:%s:%d:%d:%064x", index+1, 1, index+1, session, 1, 1, index+1)
		fields = append(fields, "session:"+session, value)
	}
	checkpointToken := strings.Repeat("a", 64)
	fields = append(fields,
		"sequence", maxWitnessedActionHistoryEntries,
		"token", checkpointToken,
		"previous_sequence", maxWitnessedActionHistoryEntries-1,
		"previous_token", strings.Repeat("b", 64),
		"history_count", maxWitnessedActionHistoryEntries,
		"capacity_fence", 1,
	)
	if err := shared.client.HSet(context.Background(), fencer.stateKey, fields...).Err(); err != nil {
		t.Fatal(err)
	}
	if err := shared.client.Set(context.Background(), shared.capacity.keys[2], "1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := witness.Close(); err != nil {
		t.Fatal(err)
	}
	witnessState := actionHistoryFileState{
		Version: actionHistoryFileVersion, PolicyFingerprint: fencer.policyFingerprint(),
		Sequence: maxWitnessedActionHistoryEntries, Token: checkpointToken,
	}
	encodedState, err := json.Marshal(witnessState)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(witness.path, append(encodedState, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reconstructedWitness, err := OpenFileActionHistoryWitness(witness.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reconstructedWitness.Close() })
	fencer, err = NewWitnessedActionFencer(shared.capacity, reconstructedWitness)
	if err != nil {
		t.Fatal(err)
	}
	if err := fencer.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() at exact history bound error = %v", err)
	}

	capacitySubject := integrationSubject("tenant-bound", "sandbox-bound", "browser-bound", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)
	assertWitnessedActionUnavailable(t, fencer, actionSubject, claim)
	releaseIntegrationLease(t, lease)
}

type failBeforeAdvanceWitness struct {
	ActionHistoryWitness
	mu   sync.Mutex
	fail bool
}

func (w *failBeforeAdvanceWitness) CompareAndSwap(
	ctx context.Context,
	policyFingerprint string,
	previous ActionHistoryCheckpoint,
	replacement ActionHistoryCheckpoint,
) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail {
		w.fail = false
		return ErrActionHistoryUnavailable
	}
	return w.ActionHistoryWitness.CompareAndSwap(ctx, policyFingerprint, previous, replacement)
}

func newIntegrationWitnessedActionFencer(
	t *testing.T,
	shared *integrationCapacity,
) (*WitnessedActionFencer, *FileActionHistoryWitness) {
	t.Helper()
	witness, err := OpenFileActionHistoryWitness(filepath.Join(t.TempDir(), "action-history-witness.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = witness.Close() })
	fencer, err := NewWitnessedActionFencer(shared.capacity, witness)
	if err != nil {
		t.Fatal(err)
	}
	cleanupIntegrationWitnessedActionState(t, shared, fencer)
	return fencer, witness
}

func cleanupIntegrationWitnessedActionState(t *testing.T, shared *integrationCapacity, fencer *WitnessedActionFencer) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = shared.client.Del(ctx, fencer.policyKey, fencer.stateKey).Err()
	})
}

func provisionIntegrationWitnessedActionFencer(t *testing.T, fencer *WitnessedActionFencer) {
	t.Helper()
	if err := fencer.Provision(context.Background()); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if err := fencer.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func integrationSessionFingerprint(subject gateway.CapacitySubject) string {
	_, session := subjectFingerprints(subject)
	return session
}

func assertWitnessedActionCurrent(
	t *testing.T,
	fencer *WitnessedActionFencer,
	subject gateway.DownstreamFenceSubject,
	claim gateway.DownstreamFence,
) {
	t.Helper()
	decision, err := fencer.AuthorizeAction(context.Background(), subject, claim, 50*time.Millisecond)
	if err != nil || decision.Activated {
		t.Fatalf("AuthorizeAction() = %#v, %v; want current", decision, err)
	}
}

func assertWitnessedActionUnavailable(
	t *testing.T,
	fencer *WitnessedActionFencer,
	subject gateway.DownstreamFenceSubject,
	claim gateway.DownstreamFence,
) {
	t.Helper()
	decision, err := fencer.AuthorizeAction(context.Background(), subject, claim, 50*time.Millisecond)
	if decision.Activated || !errors.Is(err, gateway.ErrDownstreamUnavailable) || err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("AuthorizeAction() = %#v, %v; want bounded unavailable", decision, err)
	}
}

func assertNoSensitiveWitnessedActionState(
	t *testing.T,
	shared *integrationCapacity,
	fencer *WitnessedActionFencer,
	forbidden []string,
) {
	t.Helper()
	state, err := shared.client.HGetAll(context.Background(), fencer.stateKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	values := []string{fencer.policyKey, fencer.stateKey, fmt.Sprint(fencer.Descriptor())}
	for key, value := range state {
		values = append(values, key, value)
	}
	content := strings.Join(values, "\n")
	for _, value := range forbidden {
		if strings.Contains(content, value) {
			t.Fatalf("witnessed action state exposed %q", value)
		}
	}
}
