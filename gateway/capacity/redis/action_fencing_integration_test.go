//go:build integration

package rediscapacity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestIntegrationActionFencingProvisionAndVerify(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	fencer := newIntegrationActionFencer(t, shared)

	assertIntegrationActionUnavailable(t, fencer.Verify(context.Background()))
	assertIntegrationActionUnavailable(t, fencer.Provision(context.Background()))
	provisionIntegrationCapacity(t, shared.capacity)
	assertIntegrationActionUnavailable(t, fencer.Verify(context.Background()))
	if err := fencer.Provision(context.Background()); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if err := fencer.Provision(context.Background()); err != nil {
		t.Fatalf("repeated Provision() error = %v", err)
	}
	if err := fencer.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	mismatch := newIntegrationCapacityForNamespace(t, shared.namespace, 2, 1, 1)
	mismatchFencer, err := NewActionFencer(mismatch.capacity)
	if err != nil {
		t.Fatal(err)
	}
	assertIntegrationActionUnavailable(t, mismatchFencer.Provision(context.Background()))
}

func TestIntegrationActionFencingActivationSuccessorAndRetention(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	fencer := newIntegrationActionFencer(t, shared)
	provisionIntegrationActionFencer(t, fencer)

	capacitySubject := integrationSubject(
		"tenant-action-sensitive", "sandbox-action-sensitive", "browser-action-sensitive", time.Minute,
	)
	actionSubject := integrationActionSubject(capacitySubject, 11)
	oldLease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	oldClaim := integrationActionClaim(t, oldLease)

	const contenders = 32
	start := make(chan struct{})
	results := make(chan gateway.DownstreamFenceDecision, contenders)
	errorsByCall := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, oldClaim, 50*time.Millisecond)
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

	assertIntegrationCurrentAction(t, fencer, actionSubject, oldClaim)
	reconstructed := newIntegrationActionFencer(t, shared)
	if err := reconstructed.Verify(context.Background()); err != nil {
		t.Fatalf("reconstructed Verify() error = %v", err)
	}
	assertIntegrationCurrentAction(t, reconstructed, actionSubject, oldClaim)
	for _, mutate := range []func(*gateway.DownstreamFenceSubject){
		func(subject *gateway.DownstreamFenceSubject) { subject.ConnectionGeneration++ },
		func(subject *gateway.DownstreamFenceSubject) { subject.CapabilityProfileID = "browser-v2" },
	} {
		mismatch := actionSubject
		mutate(&mismatch)
		decision, mismatchErr := fencer.AuthorizeAction(context.Background(), mismatch, oldClaim, 50*time.Millisecond)
		if decision.Activated || !errors.Is(mismatchErr, gateway.ErrDownstreamUnavailable) {
			t.Fatalf("same-fence subject mismatch = %#v, %v; want unavailable", decision, mismatchErr)
		}
	}
	highWaterKey := integrationActionHighWaterKey(capacitySubject, fencer)
	assertIntegrationPositiveTTL(t, shared.client, highWaterKey)
	releaseIntegrationLease(t, oldLease)
	assertIntegrationActionLost(t, fencer, actionSubject, oldClaim)

	successorLease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	successorClaim := integrationActionClaim(t, successorLease)
	if integrationMemberFence(t, successorLease.member) <= integrationMemberFence(t, oldLease.member) {
		t.Fatal("successor did not receive a higher capacity fence")
	}
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, successorClaim, 50*time.Millisecond)
	if err != nil || !decision.Activated {
		t.Fatalf("successor AuthorizeAction() = %#v, %v; want activated", decision, err)
	}
	assertIntegrationCurrentAction(t, fencer, actionSubject, successorClaim)
	releaseIntegrationLease(t, successorLease)
	assertIntegrationActionLost(t, fencer, actionSubject, successorClaim)

	// Model a stale-store replay with an otherwise well-formed, active lower
	// member. The retained successor high-water must still reject it.
	staleScore := time.Now().Add(time.Second).UnixMilli()
	if err := shared.client.ZAdd(context.Background(), shared.capacity.keys[0], goredis.Z{
		Score: float64(staleScore), Member: oldLease.member,
	}).Err(); err != nil {
		t.Fatal(err)
	}
	assertIntegrationActionLost(t, fencer, actionSubject, oldClaim)
	if err := shared.client.ZRem(context.Background(), shared.capacity.keys[0], oldLease.member).Err(); err != nil {
		t.Fatal(err)
	}
	assertIntegrationPositiveTTL(t, shared.client, highWaterKey)

	assertNoSensitiveActionState(t, shared, fencer, []string{
		capacitySubject.TenantID, capacitySubject.SandboxID, capacitySubject.BrowserSessionID,
	})
}

func TestIntegrationActionFencingRequiresSafeWindowAndBoundedClaimLifetime(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	fencer := newIntegrationActionFencer(t, shared)
	provisionIntegrationActionFencer(t, fencer)

	capacitySubject := integrationSubject("tenant-window", "sandbox-window", "browser-window", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 3*time.Second)
	if decision.Activated || !errors.Is(err, gateway.ErrDownstreamFenceLost) {
		t.Fatalf("unsafe action window = %#v, %v; want lost", decision, err)
	}
	assertIntegrationCurrentActionAfterActivation(t, fencer, actionSubject, claim)
	releaseIntegrationLease(t, lease)

	longSubject := integrationSubject("tenant-long", "sandbox-long", "browser-long", gateway.MaxDownstreamClaimLifetime+time.Hour)
	longLease := acquireIntegrationLease(t, shared.capacity, longSubject).(*connectionLease)
	longClaim := integrationActionClaim(t, longLease)
	decision, err = fencer.AuthorizeAction(context.Background(), integrationActionSubject(longSubject, 1), longClaim, 50*time.Millisecond)
	if decision.Activated || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("overlong claim = %#v, %v; want unavailable", decision, err)
	}
	releaseIntegrationLease(t, longLease)
}

func TestIntegrationActionFencingRejectsMalformedSharedState(t *testing.T) {
	tests := []struct {
		name      string
		activate  bool
		corrupt   func(context.Context, *integrationCapacity, *ActionFencer, string) error
		highWater bool
	}{
		{
			name: "capacity policy",
			corrupt: func(ctx context.Context, shared *integrationCapacity, _ *ActionFencer, _ string) error {
				return shared.client.HDel(ctx, shared.capacity.keys[1], "lease_ttl_ms").Err()
			},
		},
		{
			name: "action policy type",
			corrupt: func(ctx context.Context, shared *integrationCapacity, fencer *ActionFencer, _ string) error {
				if err := shared.client.Del(ctx, fencer.policyKey).Err(); err != nil {
					return err
				}
				return shared.client.Set(ctx, fencer.policyKey, "wrong", 0).Err()
			},
		},
		{
			name: "missing counter",
			corrupt: func(ctx context.Context, shared *integrationCapacity, _ *ActionFencer, _ string) error {
				return shared.client.Del(ctx, shared.capacity.keys[2]).Err()
			},
		},
		{
			name: "noncanonical counter",
			corrupt: func(ctx context.Context, shared *integrationCapacity, _ *ActionFencer, _ string) error {
				return shared.client.Set(ctx, shared.capacity.keys[2], "01", 0).Err()
			},
		},
		{
			name:     "counter rollback",
			activate: true,
			corrupt: func(ctx context.Context, shared *integrationCapacity, _ *ActionFencer, _ string) error {
				return shared.client.Set(ctx, shared.capacity.keys[2], "0", 0).Err()
			},
			highWater: true,
		},
		{
			name: "high water type",
			corrupt: func(ctx context.Context, shared *integrationCapacity, _ *ActionFencer, highWaterKey string) error {
				return shared.client.HSet(ctx, highWaterKey, "wrong", "type").Err()
			},
			highWater: true,
		},
		{
			name: "high water value",
			corrupt: func(ctx context.Context, shared *integrationCapacity, _ *ActionFencer, highWaterKey string) error {
				return shared.client.Set(ctx, highWaterKey, "malformed", time.Minute).Err()
			},
			highWater: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
			provisionIntegrationCapacity(t, shared.capacity)
			fencer := newIntegrationActionFencer(t, shared)
			provisionIntegrationActionFencer(t, fencer)
			capacitySubject := integrationSubject("tenant-corrupt", "sandbox-corrupt", "browser-corrupt", time.Minute)
			actionSubject := integrationActionSubject(capacitySubject, 1)
			lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
			claim := integrationActionClaim(t, lease)
			highWaterKey := integrationActionHighWaterKey(capacitySubject, fencer)
			if test.activate {
				decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
				if err != nil || !decision.Activated {
					t.Fatalf("initial AuthorizeAction() = %#v, %v", decision, err)
				}
			}
			if err := test.corrupt(context.Background(), shared, fencer, highWaterKey); err != nil {
				t.Fatal(err)
			}
			decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
			if decision.Activated || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
				t.Fatalf("AuthorizeAction() = %#v, %v; want unavailable", decision, err)
			}
			if err != gateway.ErrDownstreamUnavailable {
				t.Fatalf("AuthorizeAction() exposed diagnostic error %q", err)
			}
			if !test.highWater {
				exists, existsErr := shared.client.Exists(context.Background(), highWaterKey).Result()
				if existsErr != nil || exists != 0 {
					t.Fatalf("rejected action created high-water: exists=%d error=%v", exists, existsErr)
				}
			}
			releaseIntegrationLease(t, lease)
		})
	}
}

func TestIntegrationActionFencingRejectsAmbiguousSessionOwnershipAndExhaustedFence(t *testing.T) {
	t.Run("multiple active members for target session", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		fencer := newIntegrationActionFencer(t, shared)
		provisionIntegrationActionFencer(t, fencer)
		capacitySubject := integrationSubject("tenant-duplicate", "sandbox-duplicate", "browser-duplicate", time.Minute)
		actionSubject := integrationActionSubject(capacitySubject, 1)
		lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
		claim := integrationActionClaim(t, lease)
		lease.stopOnce.Do(func() { close(lease.stop) })
		<-lease.done

		parsed, err := parseCapacityMember(lease.member)
		if err != nil {
			t.Fatal(err)
		}
		owner := strings.Repeat("f", 32)
		if owner == parsed.owner {
			owner = strings.Repeat("e", 32)
		}
		conflictingFence := parsed.fence + 1
		conflictingMember := fmt.Sprintf("%s:%020d:%s:%s:%s", owner, conflictingFence,
			parsed.tenant, parsed.session, parsed.boundExpiry)
		score, err := shared.client.ZScore(context.Background(), shared.capacity.keys[0], lease.member).Result()
		if err != nil {
			t.Fatal(err)
		}
		if err := shared.client.ZAdd(context.Background(), shared.capacity.keys[0], goredis.Z{
			Score: score, Member: conflictingMember,
		}).Err(); err != nil {
			t.Fatal(err)
		}
		if err := shared.client.Set(context.Background(), shared.capacity.keys[2], conflictingFence, 0).Err(); err != nil {
			t.Fatal(err)
		}

		decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
		if decision.Activated || err != gateway.ErrDownstreamUnavailable {
			t.Fatalf("AuthorizeAction() = %#v, %v; want unavailable", decision, err)
		}
		assertIntegrationMissingActionHighWater(t, shared, fencer, capacitySubject)
		releaseIntegrationLease(t, lease)
	})

	t.Run("only non-claim member active for target session", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		fencer := newIntegrationActionFencer(t, shared)
		provisionIntegrationActionFencer(t, fencer)
		capacitySubject := integrationSubject("tenant-replaced", "sandbox-replaced", "browser-replaced", time.Minute)
		actionSubject := integrationActionSubject(capacitySubject, 1)
		lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
		claim := integrationActionClaim(t, lease)
		lease.stopOnce.Do(func() { close(lease.stop) })
		<-lease.done

		parsed, err := parseCapacityMember(lease.member)
		if err != nil {
			t.Fatal(err)
		}
		replacementFence := parsed.fence + 1
		replacementMember := fmt.Sprintf("%s:%020d:%s:%s:%s", strings.Repeat("d", 32), replacementFence,
			parsed.tenant, parsed.session, parsed.boundExpiry)
		score, err := shared.client.ZScore(context.Background(), shared.capacity.keys[0], lease.member).Result()
		if err != nil {
			t.Fatal(err)
		}
		pipeline := shared.client.TxPipeline()
		pipeline.ZRem(context.Background(), shared.capacity.keys[0], lease.member)
		pipeline.ZAdd(context.Background(), shared.capacity.keys[0], goredis.Z{Score: score, Member: replacementMember})
		pipeline.Set(context.Background(), shared.capacity.keys[2], replacementFence, 0)
		if _, err := pipeline.Exec(context.Background()); err != nil {
			t.Fatal(err)
		}

		decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
		if decision.Activated || err != gateway.ErrDownstreamFenceLost {
			t.Fatalf("AuthorizeAction() = %#v, %v; want lost", decision, err)
		}
		assertIntegrationMissingActionHighWater(t, shared, fencer, capacitySubject)
		releaseIntegrationLease(t, lease)
	})

	t.Run("capacity fence exhausted", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		fencer := newIntegrationActionFencer(t, shared)
		provisionIntegrationActionFencer(t, fencer)
		capacitySubject := integrationSubject("tenant-exhausted", "sandbox-exhausted", "browser-exhausted", time.Minute)
		actionSubject := integrationActionSubject(capacitySubject, 1)
		lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
		claim := integrationActionClaim(t, lease)
		if err := shared.client.Set(context.Background(), shared.capacity.keys[2], maxFenceValue, 0).Err(); err != nil {
			t.Fatal(err)
		}

		decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
		if decision.Activated || err != gateway.ErrDownstreamUnavailable {
			t.Fatalf("AuthorizeAction() = %#v, %v; want unavailable", decision, err)
		}
		assertIntegrationMissingActionHighWater(t, shared, fencer, capacitySubject)
		releaseIntegrationLease(t, lease)
	})
}

func TestIntegrationActionFencingOutageAndRecovery(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, shared.capacity)
	fencer := newIntegrationActionFencer(t, shared)
	provisionIntegrationActionFencer(t, fencer)
	capacitySubject := integrationSubject("tenant-outage", "sandbox-outage", "browser-outage", time.Minute)
	actionSubject := integrationActionSubject(capacitySubject, 1)
	lease := acquireIntegrationLease(t, shared.capacity, capacitySubject).(*connectionLease)
	claim := integrationActionClaim(t, lease)
	decision, err := fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
	if err != nil || !decision.Activated {
		t.Fatalf("initial AuthorizeAction() = %#v, %v", decision, err)
	}

	if err := shared.client.Do(context.Background(), "CLIENT", "PAUSE", "350", "ALL").Err(); err != nil {
		t.Fatalf("pause integration backend: %v", err)
	}
	decision, err = fencer.AuthorizeAction(context.Background(), actionSubject, claim, 50*time.Millisecond)
	if decision.Activated || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("paused AuthorizeAction() = %#v, %v; want unavailable", decision, err)
	}
	waitIntegrationBackend(t, shared.client, 2*time.Second)
	assertIntegrationCurrentAction(t, fencer, actionSubject, claim)
	releaseIntegrationLease(t, lease)
}

func newIntegrationActionFencer(t *testing.T, shared *integrationCapacity) *ActionFencer {
	t.Helper()
	fencer, err := NewActionFencer(shared.capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		keys, _ := shared.client.Keys(ctx, fencer.highWaterPrefix+"*").Result()
		keys = append(keys, fencer.policyKey)
		_ = shared.client.Del(ctx, keys...).Err()
	})
	return fencer
}

func provisionIntegrationActionFencer(t *testing.T, fencer *ActionFencer) {
	t.Helper()
	if err := fencer.Provision(context.Background()); err != nil {
		t.Fatalf("action Provision() error = %v", err)
	}
	if err := fencer.Verify(context.Background()); err != nil {
		t.Fatalf("action Verify() error = %v", err)
	}
}

func integrationActionSubject(subject gateway.CapacitySubject, generation int64) gateway.DownstreamFenceSubject {
	return gateway.DownstreamFenceSubject{
		TenantID: subject.TenantID, SandboxID: subject.SandboxID,
		BrowserSessionID: subject.BrowserSessionID, CapabilityProfileID: subject.CapabilityProfileID,
		ConnectionGeneration: generation, ExpiresAt: subject.ExpiresAt,
	}
}

func integrationActionClaim(t *testing.T, lease *connectionLease) gateway.DownstreamFence {
	t.Helper()
	claim, err := lease.DownstreamFence()
	if err != nil {
		t.Fatalf("DownstreamFence() error = %v", err)
	}
	return claim
}

func integrationActionHighWaterKey(subject gateway.CapacitySubject, fencer *ActionFencer) string {
	_, session := subjectFingerprints(subject)
	return fencer.highWaterPrefix + session
}

func assertIntegrationCurrentAction(
	t *testing.T,
	fencer *ActionFencer,
	subject gateway.DownstreamFenceSubject,
	claim gateway.DownstreamFence,
) {
	t.Helper()
	decision, err := fencer.AuthorizeAction(context.Background(), subject, claim, 50*time.Millisecond)
	if err != nil || decision.Activated {
		t.Fatalf("AuthorizeAction() = %#v, %v; want current", decision, err)
	}
}

func assertIntegrationCurrentActionAfterActivation(
	t *testing.T,
	fencer *ActionFencer,
	subject gateway.DownstreamFenceSubject,
	claim gateway.DownstreamFence,
) {
	t.Helper()
	decision, err := fencer.AuthorizeAction(context.Background(), subject, claim, 50*time.Millisecond)
	if err != nil || !decision.Activated {
		t.Fatalf("AuthorizeAction() = %#v, %v; want activated", decision, err)
	}
	assertIntegrationCurrentAction(t, fencer, subject, claim)
}

func assertIntegrationActionLost(
	t *testing.T,
	fencer *ActionFencer,
	subject gateway.DownstreamFenceSubject,
	claim gateway.DownstreamFence,
) {
	t.Helper()
	decision, err := fencer.AuthorizeAction(context.Background(), subject, claim, 50*time.Millisecond)
	if decision.Activated || !errors.Is(err, gateway.ErrDownstreamFenceLost) {
		t.Fatalf("AuthorizeAction() = %#v, %v; want lost", decision, err)
	}
	if err != gateway.ErrDownstreamFenceLost {
		t.Fatalf("AuthorizeAction() exposed diagnostic error %q", err)
	}
}

func assertIntegrationActionUnavailable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("error = %v; want downstream unavailable", err)
	}
	if err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("error exposed diagnostic details: %q", err)
	}
}

func assertIntegrationPositiveTTL(t *testing.T, client *goredis.Client, key string) {
	t.Helper()
	ttl, err := client.PTTL(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 {
		t.Fatalf("PTTL(%q) = %s; want retained state", key, ttl)
	}
}

func assertIntegrationMissingActionHighWater(
	t *testing.T,
	shared *integrationCapacity,
	fencer *ActionFencer,
	subject gateway.CapacitySubject,
) {
	t.Helper()
	exists, err := shared.client.Exists(context.Background(), integrationActionHighWaterKey(subject, fencer)).Result()
	if err != nil {
		t.Fatal(err)
	}
	if exists != 0 {
		t.Fatal("rejected action created a high-water record")
	}
}

func assertNoSensitiveActionState(
	t *testing.T,
	shared *integrationCapacity,
	fencer *ActionFencer,
	forbidden []string,
) {
	t.Helper()
	pattern := "sandbox-runtime:{" + shared.capacity.keyTag + "}:*"
	keys, err := shared.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		t.Fatal(err)
	}
	values := append([]string(nil), keys...)
	leaseValues, err := shared.client.ZRange(context.Background(), shared.capacity.keys[0], 0, -1).Result()
	if err != nil && !errors.Is(err, goredis.Nil) {
		t.Fatal(err)
	}
	values = append(values, leaseValues...)
	highWaterKeys, err := shared.client.Keys(context.Background(), fencer.highWaterPrefix+"*").Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range highWaterKeys {
		value, valueErr := shared.client.Get(context.Background(), key).Result()
		if valueErr != nil {
			t.Fatal(valueErr)
		}
		values = append(values, value)
	}
	content := strings.Join(values, "\n")
	for _, value := range forbidden {
		if strings.Contains(content, value) {
			t.Fatalf("action-fencing state exposed %q", value)
		}
	}
	descriptor := fmt.Sprintf("%+v", fencer.Descriptor())
	for _, value := range append(forbidden, shared.namespace, shared.capacity.keyTag, fencer.policyKey) {
		if strings.Contains(descriptor, value) {
			t.Fatalf("action-fencing descriptor exposed %q", value)
		}
	}
}
