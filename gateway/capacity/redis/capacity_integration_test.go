//go:build integration

package rediscapacity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const integrationRedisURLVariable = "SANDBOX_RUNTIME_SHARED_CAPACITY_REDIS_URL"

func TestIntegrationProvisionAndAtomicPartitions(t *testing.T) {
	first := newIntegrationCapacity(t, integrationNamespace(t), 3, 2, 1)
	second := newIntegrationCapacityForNamespace(t, first.namespace, 3, 2, 1)
	provisionIntegrationCapacity(t, first.capacity)
	provisionIntegrationCapacity(t, second.capacity)

	tenantAOne := integrationSubject("tenant-sensitive-a", "sandbox-a1", "browser-a1", time.Minute)
	tenantATwo := integrationSubject("tenant-sensitive-a", "sandbox-a2", "browser-a2", time.Minute)
	tenantAThree := integrationSubject("tenant-sensitive-a", "sandbox-a3", "browser-a3", time.Minute)
	tenantB := integrationSubject("tenant-sensitive-b", "sandbox-b1", "browser-b1", time.Minute)
	tenantC := integrationSubject("tenant-sensitive-c", "sandbox-c1", "browser-c1", time.Minute)

	leaseAOne := acquireIntegrationLease(t, first.capacity, tenantAOne)
	assertIntegrationExhausted(t, second.capacity, tenantAOne)
	otherProfile := tenantAOne
	otherProfile.CapabilityProfileID = "browser-v2"
	assertIntegrationExhausted(t, second.capacity, otherProfile)
	leaseATwo := acquireIntegrationLease(t, second.capacity, tenantATwo)
	assertIntegrationExhausted(t, first.capacity, tenantAThree)
	leaseB := acquireIntegrationLease(t, second.capacity, tenantB)
	assertIntegrationExhausted(t, first.capacity, tenantC)
	assertIntegrationCardinality(t, first, 3)
	assertNoSensitiveCapacityState(t, first, []string{
		"tenant-sensitive-a", "tenant-sensitive-b", "tenant-sensitive-c",
		"sandbox-a1", "sandbox-a2", "sandbox-b1", "browser-a1", "browser-a2", "browser-b1",
	})

	releaseIntegrationLease(t, leaseAOne)
	replacement := acquireIntegrationLease(t, second.capacity, tenantAOne)
	assertIntegrationCardinality(t, first, 3)
	for _, lease := range []gateway.ConnectionLease{leaseATwo, leaseB, replacement} {
		releaseIntegrationLease(t, lease)
	}
	assertIntegrationCardinality(t, first, 0)
}

func TestIntegrationRenewCrashReclaimFencingAndLoss(t *testing.T) {
	namespace := integrationNamespace(t)
	first := newIntegrationCapacityWithDurations(t, namespace, 1, 1, 1,
		1200*time.Millisecond, 200*time.Millisecond, 350*time.Millisecond)
	second := newIntegrationCapacityWithDurations(t, namespace, 1, 1, 1,
		1200*time.Millisecond, 200*time.Millisecond, 350*time.Millisecond)
	provisionIntegrationCapacity(t, first.capacity)
	provisionIntegrationCapacity(t, second.capacity)

	subject := integrationSubject("tenant-renew", "sandbox-renew", "browser-renew", time.Minute)
	first.capacity.ownerSource = func() (string, error) { return strings.Repeat("a", 32), nil }
	old := acquireIntegrationLease(t, first.capacity, subject).(*connectionLease)
	collision := integrationSubject("tenant-renew", "sandbox-renew", "browser-collision", time.Minute)
	if lease, err := first.capacity.Acquire(context.Background(), collision); lease != nil ||
		!errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("owner-collision Acquire() = %#v, %v; want nil, unavailable", lease, err)
	}
	differentExpiry := subject
	differentExpiry.ExpiresAt = subject.ExpiresAt.Add(time.Second)
	if lease, err := first.capacity.Acquire(context.Background(), differentExpiry); lease != nil ||
		!errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("owner-expiry-collision Acquire() = %#v, %v; want nil, unavailable", lease, err)
	}
	assertIntegrationFence(t, first, 1)
	assertIntegrationCardinality(t, first, 1)
	retry := acquireIntegrationLease(t, first.capacity, subject).(*connectionLease)
	if retry.member != old.member {
		t.Fatal("same active owner did not recover its existing reservation")
	}
	retry.stopOnce.Do(func() { close(retry.stop) })
	<-retry.done
	time.Sleep(2 * first.capacity.leaseTTL)
	assertIntegrationExhausted(t, second.capacity, subject)

	old.stopOnce.Do(func() { close(old.stop) })
	<-old.done
	time.Sleep(first.capacity.leaseTTL + 250*time.Millisecond)
	second.capacity.ownerSource = func() (string, error) { return strings.Repeat("a", 32), nil }
	successor := acquireIntegrationLease(t, second.capacity, subject).(*connectionLease)
	if old.member == successor.member {
		t.Fatal("reclaimed owner reused a stale fencing member")
	}
	if successorFence := integrationMemberFence(t, successor.member); successorFence <= integrationMemberFence(t, old.member) {
		t.Fatalf("successor fence = %d; want greater than stale fence", successorFence)
	}
	if kind, _, _, err := old.renewOnce(context.Background()); kind != "lost" || err == nil {
		t.Fatalf("stale renew = %q, %v; want lost", kind, err)
	}
	if err := old.Release(context.Background()); err != nil {
		t.Fatalf("stale Release() error = %v", err)
	}
	first.capacity.ownerSource = func() (string, error) { return strings.Repeat("b", 32), nil }
	assertIntegrationExhausted(t, first.capacity, subject)

	if err := second.client.ZRem(context.Background(), second.capacity.keys[0], successor.member).Err(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-successor.Events():
		if event.Kind != gateway.CapacityEventLost {
			t.Fatalf("capacity event = %#v; want lost", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("removed shared owner did not emit a lost event")
	}
	releaseIntegrationLease(t, successor)
}

func TestIntegrationWrongTypesAndFenceFailuresAreUnavailable(t *testing.T) {
	subject := integrationSubject("tenant-state", "sandbox-state", "browser-state", time.Minute)

	t.Run("wrong policy type", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		if err := shared.client.Set(context.Background(), shared.capacity.keys[1], "wrong", 0).Err(); err != nil {
			t.Fatal(err)
		}
		assertIntegrationUnavailable(t, shared.capacity, subject)
		if err := shared.capacity.Provision(context.Background()); !errors.Is(err, gateway.ErrCapacityUnavailable) {
			t.Fatalf("Provision() error = %v; want unavailable", err)
		}
	})

	t.Run("wrong lease type", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		if err := shared.client.Set(context.Background(), shared.capacity.keys[0], "wrong", 0).Err(); err != nil {
			t.Fatal(err)
		}
		assertIntegrationUnavailable(t, shared.capacity, subject)
		if err := shared.capacity.Provision(context.Background()); !errors.Is(err, gateway.ErrCapacityUnavailable) {
			t.Fatalf("Provision() error = %v; want unavailable", err)
		}
	})

	t.Run("wrong lease type rejects release", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		lease := acquireIntegrationLease(t, shared.capacity, subject).(*connectionLease)
		lease.stopOnce.Do(func() { close(lease.stop) })
		<-lease.done
		if err := shared.client.Del(context.Background(), shared.capacity.keys[0]).Err(); err != nil {
			t.Fatal(err)
		}
		if err := shared.client.Set(context.Background(), shared.capacity.keys[0], "wrong", 0).Err(); err != nil {
			t.Fatal(err)
		}
		if err := lease.Release(context.Background()); !errors.Is(err, gateway.ErrCapacityUnavailable) {
			t.Fatalf("Release() error = %v; want unavailable", err)
		}
	})

	t.Run("missing fence", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		if err := shared.client.Del(context.Background(), shared.capacity.keys[2]).Err(); err != nil {
			t.Fatal(err)
		}
		assertIntegrationUnavailable(t, shared.capacity, subject)
		if err := shared.capacity.Provision(context.Background()); !errors.Is(err, gateway.ErrCapacityUnavailable) {
			t.Fatalf("Provision() error = %v; want unavailable", err)
		}
	})

	t.Run("rollback behind active member", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		shared.capacity.ownerSource = func() (string, error) { return strings.Repeat("c", 32), nil }
		lease := acquireIntegrationLease(t, shared.capacity, subject).(*connectionLease)
		lease.stopOnce.Do(func() { close(lease.stop) })
		<-lease.done
		if err := shared.client.Set(context.Background(), shared.capacity.keys[2], "0", 0).Err(); err != nil {
			t.Fatal(err)
		}
		shared.capacity.ownerSource = func() (string, error) { return strings.Repeat("d", 32), nil }
		assertIntegrationUnavailable(t, shared.capacity, integrationSubject(
			"tenant-state", "sandbox-state", "browser-other", time.Minute))
		if kind, _, _, err := lease.renewOnce(context.Background()); kind != "unavailable" || err == nil {
			t.Fatalf("rollback renew = %q, %v; want unavailable", kind, err)
		}
		assertIntegrationCardinality(t, shared, 1)
		assertIntegrationFence(t, shared, 0)
		if err := shared.client.Set(context.Background(), shared.capacity.keys[2], "1", 0).Err(); err != nil {
			t.Fatal(err)
		}
		releaseIntegrationLease(t, lease)
	})

	t.Run("fence exhaustion", func(t *testing.T) {
		shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 2, 1)
		provisionIntegrationCapacity(t, shared.capacity)
		if err := shared.client.Set(context.Background(), shared.capacity.keys[2], maxFenceValue, 0).Err(); err != nil {
			t.Fatal(err)
		}
		assertIntegrationUnavailable(t, shared.capacity, subject)
		assertIntegrationCardinality(t, shared, 0)
		assertIntegrationFence(t, shared, maxFenceValue)
	})

	t.Run("active lease observes malformed policy", func(t *testing.T) {
		shared := newIntegrationCapacityWithDurations(t, integrationNamespace(t), 1, 1, 1,
			1200*time.Millisecond, 200*time.Millisecond, 350*time.Millisecond)
		provisionIntegrationCapacity(t, shared.capacity)
		lease := acquireIntegrationLease(t, shared.capacity, subject)
		if err := shared.client.HDel(context.Background(), shared.capacity.keys[1], "lease_ttl_ms").Err(); err != nil {
			t.Fatal(err)
		}
		select {
		case event := <-lease.Events():
			if event.Kind != gateway.CapacityEventUnavailable {
				t.Fatalf("malformed-policy event = %#v; want unavailable", event)
			}
		case <-time.After(time.Second):
			t.Fatal("malformed policy did not terminate active lease")
		}
		releaseIntegrationLease(t, lease)
	})
}

func TestIntegrationBackendOutageFailsClosedAndSignalsBeforeSafetyBoundary(t *testing.T) {
	namespace := integrationNamespace(t)
	shared := newIntegrationCapacityWithDurations(t, namespace, 1, 1, 1,
		1500*time.Millisecond, 200*time.Millisecond, 400*time.Millisecond)
	contender := newIntegrationCapacityWithDurations(t, namespace, 1, 1, 1,
		1500*time.Millisecond, 200*time.Millisecond, 400*time.Millisecond)
	provisionIntegrationCapacity(t, shared.capacity)
	provisionIntegrationCapacity(t, contender.capacity)

	subject := integrationSubject("tenant-outage", "sandbox-outage", "browser-outage", time.Minute)
	lease := acquireIntegrationLease(t, shared.capacity, subject).(*connectionLease)
	safetyBoundary := lease.confirmedUntil.Add(-shared.capacity.safetyMargin)
	if err := shared.client.Do(context.Background(), "CLIENT", "PAUSE", "1300", "ALL").Err(); err != nil {
		t.Fatalf("pause integration backend: %v", err)
	}
	assertIntegrationUnavailable(t, contender.capacity, integrationSubject(
		"tenant-other", "sandbox-other", "browser-other", time.Minute))
	select {
	case event := <-lease.Events():
		if event.Kind != gateway.CapacityEventUnavailable {
			t.Fatalf("outage event = %#v; want unavailable", event)
		}
		if time.Now().After(safetyBoundary.Add(150 * time.Millisecond)) {
			t.Fatalf("outage event crossed safety boundary by %s", time.Since(safetyBoundary))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend outage did not terminate the active lease")
	}
	waitIntegrationBackend(t, contender.client, 2*time.Second)
	releaseIntegrationLease(t, lease)
	replacement := acquireIntegrationLease(t, contender.capacity, subject)
	releaseIntegrationLease(t, replacement)
}

func TestIntegrationPolicyMismatchMalformedStateAndGrantExpiry(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 2, 1, 1)
	subject := integrationSubject("tenant-policy", "sandbox-policy", "browser-policy", time.Minute)
	if lease, err := shared.capacity.Acquire(context.Background(), subject); lease != nil || !errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("unprovisioned Acquire() = %#v, %v", lease, err)
	}
	if err := shared.capacity.Verify(context.Background()); !errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("unprovisioned Verify() error = %v; want unavailable", err)
	}
	provisionIntegrationCapacity(t, shared.capacity)
	verifyIntegrationCapacity(t, shared.capacity)

	mismatch := newIntegrationCapacityForNamespace(t, shared.namespace, 3, 1, 1)
	if err := mismatch.capacity.Provision(context.Background()); !errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("mismatched Provision() error = %v", err)
	}
	if err := shared.client.HDel(context.Background(), shared.capacity.keys[1], "lease_ttl_ms").Err(); err != nil {
		t.Fatal(err)
	}
	if lease, err := shared.capacity.Acquire(context.Background(), subject); lease != nil || !errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("malformed-policy Acquire() = %#v, %v", lease, err)
	}

	corrupt := newIntegrationCapacity(t, integrationNamespace(t), 2, 1, 1)
	provisionIntegrationCapacity(t, corrupt.capacity)
	if err := corrupt.client.ZAdd(context.Background(), corrupt.capacity.keys[0], goredis.Z{
		Score: float64(time.Now().Add(time.Minute).UnixMilli()), Member: "raw-corrupt-member",
	}).Err(); err != nil {
		t.Fatal(err)
	}
	if lease, err := corrupt.capacity.Acquire(context.Background(), subject); lease != nil || !errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("corrupt-state Acquire() = %#v, %v", lease, err)
	}

	expiring := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, expiring.capacity)
	expiringSubject := integrationSubject("tenant-expiry", "sandbox-expiry", "browser-expiry", 900*time.Millisecond)
	lease := acquireIntegrationLease(t, expiring.capacity, expiringSubject)
	score, err := expiring.client.ZScore(context.Background(), expiring.capacity.keys[0], lease.(*connectionLease).member).Result()
	if err != nil {
		t.Fatal(err)
	}
	if int64(score) > expiringSubject.ExpiresAt.UnixMilli() {
		t.Fatalf("lease expiry %d exceeds grant expiry %d", int64(score), expiringSubject.ExpiresAt.UnixMilli())
	}
	select {
	case event := <-lease.Events():
		if event.Kind != gateway.CapacityEventLost {
			t.Fatalf("grant-bounded event = %#v; want lost", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("grant-bounded lease did not expire")
	}
	releaseIntegrationLease(t, lease)

	deleted := newIntegrationCapacity(t, integrationNamespace(t), 1, 1, 1)
	provisionIntegrationCapacity(t, deleted.capacity)
	deletedSubject := integrationSubject("tenant-deleted", "sandbox-deleted", "browser-deleted", 900*time.Millisecond)
	deletedLease := acquireIntegrationLease(t, deleted.capacity, deletedSubject).(*connectionLease)
	if err := deleted.client.ZRem(context.Background(), deleted.capacity.keys[0], deletedLease.member).Err(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-deletedLease.Events():
		if event.Kind != gateway.CapacityEventLost {
			t.Fatalf("grant-bound deletion event = %#v; want lost", event)
		}
	case <-time.After(time.Second):
		t.Fatal("grant-bound lease did not observe deleted ownership")
	}
	releaseIntegrationLease(t, deletedLease)
}

func TestIntegrationConcurrentAcquireAndRenewRelease(t *testing.T) {
	shared := newIntegrationCapacity(t, integrationNamespace(t), 5, 5, 1)
	provisionIntegrationCapacity(t, shared.capacity)

	const contenders = 32
	start := make(chan struct{})
	results := make(chan gateway.ConnectionLease, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			lease, err := shared.capacity.Acquire(context.Background(), integrationSubject(
				"tenant-concurrent", fmt.Sprintf("sandbox-%d", index), fmt.Sprintf("browser-%d", index), time.Minute))
			if err == nil {
				results <- lease
				return
			}
			if !errors.Is(err, gateway.ErrCapacityExhausted) {
				t.Errorf("concurrent Acquire() error = %v", err)
			}
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	var leases []gateway.ConnectionLease
	for lease := range results {
		leases = append(leases, lease)
	}
	if len(leases) != 5 {
		t.Fatalf("concurrent acquisitions = %d; want 5", len(leases))
	}
	assertIntegrationCardinality(t, shared, 5)
	for _, lease := range leases {
		releaseIntegrationLease(t, lease)
	}
	assertIntegrationCardinality(t, shared, 0)

	for index := 0; index < 12; index++ {
		lease := acquireIntegrationLease(t, shared.capacity, integrationSubject(
			"tenant-race", fmt.Sprintf("sandbox-race-%d", index), fmt.Sprintf("browser-race-%d", index), time.Minute))
		time.Sleep(shared.capacity.renewInterval - 10*time.Millisecond)
		releaseIntegrationLease(t, lease)
	}
	concurrent := acquireIntegrationLease(t, shared.capacity, integrationSubject(
		"tenant-release", "sandbox-release", "browser-release", time.Minute))
	errorsByRelease := make(chan error, 8)
	for index := 0; index < cap(errorsByRelease); index++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			errorsByRelease <- concurrent.Release(ctx)
		}()
	}
	for index := 0; index < cap(errorsByRelease); index++ {
		if err := <-errorsByRelease; err != nil {
			t.Fatalf("concurrent Release() error = %v", err)
		}
	}
	assertIntegrationCardinality(t, shared, 0)
}

type integrationCapacity struct {
	capacity  *Capacity
	client    *goredis.Client
	namespace string
}

func newIntegrationCapacity(t *testing.T, namespace string, total, tenant, session int) *integrationCapacity {
	t.Helper()
	return newIntegrationCapacityForNamespace(t, namespace, total, tenant, session)
}

func newIntegrationCapacityForNamespace(t *testing.T, namespace string, total, tenant, session int) *integrationCapacity {
	t.Helper()
	return newIntegrationCapacityWithDurations(t, namespace, total, tenant, session,
		2*time.Second, 400*time.Millisecond, 500*time.Millisecond)
}

func newIntegrationCapacityWithDurations(
	t *testing.T,
	namespace string,
	total, tenant, session int,
	leaseTTL, renewInterval, safetyMargin time.Duration,
) *integrationCapacity {
	t.Helper()
	client := integrationClient(t)
	capacity, err := New(Options{
		Client: client, Namespace: namespace, MaxTotal: total, MaxPerTenant: tenant, MaxPerSession: session,
		LeaseTTL: leaseTTL, RenewInterval: renewInterval,
		RenewalSafetyMargin: safetyMargin, OperationTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = client.Del(ctx, capacity.keys...).Err()
		_ = client.Close()
	})
	return &integrationCapacity{capacity: capacity, client: client, namespace: namespace}
}

func integrationClient(t *testing.T) *goredis.Client {
	t.Helper()
	endpoint := os.Getenv(integrationRedisURLVariable)
	if endpoint == "" {
		t.Fatalf("%s is required for integration tests", integrationRedisURLVariable)
	}
	options, err := goredis.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	options.Protocol = 2
	options.MaxRetries = -1
	options.ContextTimeoutEnabled = true
	options.DisableIdentity = true
	options.DialTimeout = 200 * time.Millisecond
	options.ReadTimeout = 200 * time.Millisecond
	options.WriteTimeout = 200 * time.Millisecond
	options.PoolTimeout = 200 * time.Millisecond
	client := goredis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		t.Fatalf("connect integration Redis-compatible backend: %v", err)
	}
	return client
}

func integrationNamespace(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("shared-capacity-%d", time.Now().UnixNano())
}

func integrationSubject(tenant, sandbox, browser string, lifetime time.Duration) gateway.CapacitySubject {
	return gateway.CapacitySubject{
		TenantID: tenant, SandboxID: sandbox, BrowserSessionID: browser,
		CapabilityProfileID: "browser-v1", ExpiresAt: time.Now().Add(lifetime),
	}
}

func provisionIntegrationCapacity(t *testing.T, capacity *Capacity) {
	t.Helper()
	if err := capacity.Provision(context.Background()); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
}

func verifyIntegrationCapacity(t *testing.T, capacity *Capacity) {
	t.Helper()
	if err := capacity.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func acquireIntegrationLease(t *testing.T, capacity *Capacity, subject gateway.CapacitySubject) gateway.ConnectionLease {
	t.Helper()
	lease, err := capacity.Acquire(context.Background(), subject)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	return lease
}

func assertIntegrationExhausted(t *testing.T, capacity *Capacity, subject gateway.CapacitySubject) {
	t.Helper()
	if lease, err := capacity.Acquire(context.Background(), subject); lease != nil || !errors.Is(err, gateway.ErrCapacityExhausted) {
		t.Fatalf("Acquire() = %#v, %v; want nil, exhausted", lease, err)
	}
}

func assertIntegrationUnavailable(t *testing.T, capacity *Capacity, subject gateway.CapacitySubject) {
	t.Helper()
	if lease, err := capacity.Acquire(context.Background(), subject); lease != nil ||
		!errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("Acquire() = %#v, %v; want nil, unavailable", lease, err)
	}
}

func releaseIntegrationLease(t *testing.T, lease gateway.ConnectionLease) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
}

func assertIntegrationCardinality(t *testing.T, shared *integrationCapacity, want int64) {
	t.Helper()
	got, err := shared.client.ZCard(context.Background(), shared.capacity.keys[0]).Result()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("shared capacity cardinality = %d; want %d", got, want)
	}
}

func assertIntegrationFence(t *testing.T, shared *integrationCapacity, want int64) {
	t.Helper()
	value, err := shared.client.Get(context.Background(), shared.capacity.keys[2]).Int64()
	if err != nil {
		t.Fatal(err)
	}
	if value != want {
		t.Fatalf("shared capacity fence = %d; want %d", value, want)
	}
}

func assertNoSensitiveCapacityState(t *testing.T, shared *integrationCapacity, forbidden []string) {
	t.Helper()
	keys, err := shared.client.Keys(context.Background(), "sandbox-runtime:*").Result()
	if err != nil {
		t.Fatal(err)
	}
	values, err := shared.client.ZRange(context.Background(), shared.capacity.keys[0], 0, -1).Result()
	if err != nil && !errors.Is(err, goredis.Nil) {
		t.Fatal(err)
	}
	content := strings.Join(append(keys, values...), "\n")
	for _, value := range forbidden {
		if strings.Contains(content, value) {
			t.Fatalf("shared capacity state exposed %q", value)
		}
	}
}

func integrationMemberFence(t *testing.T, member string) int64 {
	t.Helper()
	parts := strings.Split(member, ":")
	if len(parts) != 5 {
		t.Fatalf("capacity member has %d parts; want 5", len(parts))
	}
	fence, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		t.Fatalf("parse capacity fence: %v", err)
	}
	return fence
}

func waitIntegrationBackend(t *testing.T, client *goredis.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := client.Ping(ctx).Err()
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("integration backend did not recover: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
