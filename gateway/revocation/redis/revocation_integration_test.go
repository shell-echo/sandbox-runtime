//go:build integration

package redisrevocation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const integrationRedisURLVariable = "SANDBOX_RUNTIME_DISTRIBUTED_REVOCATION_REDIS_URL"

func TestIntegrationProvisionPolicyAndStateValidation(t *testing.T) {
	namespace := integrationNamespace(t)
	first := newIntegrationRevocations(t, namespace, 50*time.Millisecond)
	second := newIntegrationRevocations(t, namespace, 50*time.Millisecond)
	if err := first.revocations.Verify(context.Background()); !errors.Is(err, gateway.ErrRevocationUnavailable) {
		t.Fatalf("Verify() before provision error = %v; want unavailable", err)
	}
	missingPolicySubject := integrationSubject("grant-missing-policy", time.Minute)
	assertIntegrationUnavailableWatch(t, first.revocations, missingPolicySubject)
	if err := first.revocations.Revoke(context.Background(), missingPolicySubject); !errors.Is(err, gateway.ErrRevocationUnavailable) {
		t.Fatalf("Revoke() before provision error = %v; want unavailable", err)
	}
	provisionIntegrationRevocations(t, first.revocations)
	verifyIntegrationRevocations(t, first.revocations)
	verifyIntegrationRevocations(t, second.revocations)
	if err := second.revocations.Provision(context.Background()); err != nil {
		t.Fatalf("idempotent Provision() error = %v", err)
	}

	mismatch := newIntegrationRevocations(t, namespace, 100*time.Millisecond)
	if err := mismatch.revocations.Verify(context.Background()); !errors.Is(err, gateway.ErrRevocationUnavailable) {
		t.Fatalf("mismatched Verify() error = %v; want unavailable", err)
	}

	wrongPolicy := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	if err := wrongPolicy.client.Set(context.Background(), wrongPolicy.revocations.policyKey, "wrong", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := wrongPolicy.revocations.Provision(context.Background()); !errors.Is(err, gateway.ErrRevocationUnavailable) {
		t.Fatalf("wrong-type Provision() error = %v; want unavailable", err)
	}

	wrongTombstone := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	provisionIntegrationRevocations(t, wrongTombstone.revocations)
	subject := integrationSubject("grant-wrong-type", time.Minute)
	key := wrongTombstone.revocations.subjectKeys(subject)[1]
	if err := wrongTombstone.client.HSet(context.Background(), key, "wrong", "type").Err(); err != nil {
		t.Fatal(err)
	}
	assertIntegrationUnavailableWatch(t, wrongTombstone.revocations, subject)
	if err := wrongTombstone.revocations.Revoke(context.Background(), subject); !errors.Is(err, gateway.ErrRevocationUnavailable) {
		t.Fatalf("wrong-type Revoke() error = %v; want unavailable", err)
	}
}

func TestIntegrationDurableLevelTriggeredWatchAndMaximumExpiry(t *testing.T) {
	namespace := integrationNamespace(t)
	reader := newIntegrationRevocations(t, namespace, 50*time.Millisecond)
	writer := newIntegrationRevocations(t, namespace, 50*time.Millisecond)
	provisionIntegrationRevocations(t, reader.revocations)
	verifyIntegrationRevocations(t, writer.revocations)

	base := time.Now().UTC().Add(1400 * time.Millisecond).Truncate(time.Millisecond)
	subject := gateway.RevocationSubject{GrantID: "grant-sensitive-max-expiry", ExpiresAt: base}
	watch, err := reader.revocations.Watch(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	assertWatchOpen(t, watch)

	older := subject
	older.ExpiresAt = base.Add(-300 * time.Millisecond)
	newer := subject
	newer.ExpiresAt = base.Add(500 * time.Millisecond)
	for _, candidate := range []gateway.RevocationSubject{subject, older, newer, subject} {
		if err := writer.revocations.Revoke(context.Background(), candidate); err != nil {
			t.Fatalf("Revoke(%s) error = %v", candidate.ExpiresAt, err)
		}
	}
	assertWatchError(t, watch, gateway.ErrRevoked, time.Second)

	key := reader.revocations.subjectKeys(subject)[1]
	stored, err := reader.client.Get(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if stored != fmt.Sprint(newer.ExpiresAt.UnixMilli()) {
		t.Fatalf("tombstone value = %q; want canonical maximum %d", stored, newer.ExpiresAt.UnixMilli())
	}
	if ttl, err := reader.client.PTTL(context.Background(), key).Result(); err != nil || ttl <= 0 {
		t.Fatalf("tombstone PTTL = %s, %v; want positive", ttl, err)
	}
	lateWatch, err := reader.revocations.Watch(context.Background(), newer)
	if err != nil {
		t.Fatal(err)
	}
	assertWatchError(t, lateWatch, gateway.ErrRevoked, 100*time.Millisecond)
	assertNoSensitiveRevocationState(t, reader, []string{namespace, subject.GrantID})

	waitForMissingIntegrationKey(t, reader.client, key, 3*time.Second)
	clearSubject := gateway.RevocationSubject{GrantID: subject.GrantID, ExpiresAt: time.Now().Add(time.Minute)}
	clearCtx, clearCancel := context.WithCancel(context.Background())
	clearWatch, err := reader.revocations.Watch(clearCtx, clearSubject)
	if err != nil {
		t.Fatal(err)
	}
	assertWatchOpen(t, clearWatch)
	clearCancel()
	assertWatchError(t, clearWatch, context.Canceled, time.Second)
}

func TestIntegrationConcurrentOutOfOrderRevocationRetainsMaximum(t *testing.T) {
	shared := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	provisionIntegrationRevocations(t, shared.revocations)
	base := time.Now().UTC().Add(3 * time.Second).Truncate(time.Millisecond)
	const writers = 24
	start := make(chan struct{})
	errorsFound := make(chan error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			subject := gateway.RevocationSubject{GrantID: "grant-concurrent", ExpiresAt: base.Add(time.Duration(index) * time.Millisecond)}
			errorsFound <- shared.revocations.Revoke(context.Background(), subject)
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent Revoke() error = %v", err)
		}
	}
	key := shared.revocations.subjectKeys(gateway.RevocationSubject{GrantID: "grant-concurrent", ExpiresAt: base})[1]
	stored, err := shared.client.Get(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}
	want := base.Add((writers - 1) * time.Millisecond).UnixMilli()
	if stored != fmt.Sprint(want) {
		t.Fatalf("concurrent tombstone = %q; want %d", stored, want)
	}
}

func TestIntegrationConcurrentWatchEstablishmentCannotMissRevocation(t *testing.T) {
	shared := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	provisionIntegrationRevocations(t, shared.revocations)
	for index := 0; index < 20; index++ {
		subject := integrationSubject(fmt.Sprintf("grant-watch-race-%d", index), time.Minute)
		start := make(chan struct{})
		watchResult := make(chan gateway.RevocationWatch, 1)
		watchErrors := make(chan error, 1)
		revokeErrors := make(chan error, 1)
		go func() {
			<-start
			watch, err := shared.revocations.Watch(context.Background(), subject)
			watchResult <- watch
			watchErrors <- err
		}()
		go func() {
			<-start
			revokeErrors <- shared.revocations.Revoke(context.Background(), subject)
		}()
		close(start)
		watch := <-watchResult
		if err := <-watchErrors; err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
		if err := <-revokeErrors; err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
		assertWatchError(t, watch, gateway.ErrRevoked, time.Second)
	}
}

func TestIntegrationRevokeEnforcesServerTimeLifetimeBounds(t *testing.T) {
	shared := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	provisionIntegrationRevocations(t, shared.revocations)
	for name, subject := range map[string]gateway.RevocationSubject{
		"expired":  integrationSubject("grant-expired", -time.Second),
		"too long": integrationSubject("grant-too-long", 5*time.Minute+time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			if err := shared.revocations.Revoke(context.Background(), subject); !errors.Is(err, gateway.ErrRevocationUnavailable) {
				t.Fatalf("Revoke() error = %v; want unavailable", err)
			}
			key := shared.revocations.subjectKeys(subject)[1]
			if exists, err := shared.client.Exists(context.Background(), key).Result(); err != nil || exists != 0 {
				t.Fatalf("rejected Revoke() key existence = %d, %v; want 0", exists, err)
			}
		})
	}
}

func TestIntegrationContextAndOperationTimeouts(t *testing.T) {
	shared := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	provisionIntegrationRevocations(t, shared.revocations)
	if err := shared.client.Do(context.Background(), "CLIENT", "PAUSE", 250, "ALL").Err(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := shared.revocations.Verify(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("context-bounded Verify() error = %v; want deadline exceeded", err)
	}
	if err := shared.revocations.Verify(context.Background()); !errors.Is(err, gateway.ErrRevocationUnavailable) {
		t.Fatalf("operation-bounded Verify() error = %v; want unavailable", err)
	}
	time.Sleep(300 * time.Millisecond)
	verifyIntegrationRevocations(t, shared.revocations)
}

func TestIntegrationWatchFailsClosedOnStoreError(t *testing.T) {
	shared := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	provisionIntegrationRevocations(t, shared.revocations)
	subject := integrationSubject("grant-outage", time.Minute)
	watch, err := shared.revocations.Watch(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	assertWatchOpen(t, watch)
	if err := shared.client.Close(); err != nil {
		t.Fatal(err)
	}
	assertWatchError(t, watch, gateway.ErrRevocationUnavailable, time.Second)
	if watch.Err() != gateway.ErrRevocationUnavailable {
		t.Fatalf("watch error changed after close: %v", watch.Err())
	}

	closed := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	if err := closed.client.Close(); err != nil {
		t.Fatal(err)
	}
	initial, err := closed.revocations.Watch(context.Background(), integrationSubject("grant-initial-outage", time.Minute))
	if err != nil {
		t.Fatalf("initial outage Watch() error = %v; want terminal watch", err)
	}
	assertWatchError(t, initial, gateway.ErrRevocationUnavailable, 100*time.Millisecond)
}

func TestIntegrationMalformedTombstoneFailsClosed(t *testing.T) {
	shared := newIntegrationRevocations(t, integrationNamespace(t), 50*time.Millisecond)
	provisionIntegrationRevocations(t, shared.revocations)
	subject := integrationSubject("grant-malformed", time.Minute)
	key := shared.revocations.subjectKeys(subject)[1]
	for name, install := range map[string]func() error{
		"noncanonical": func() error { return shared.client.Set(context.Background(), key, "0001", time.Minute).Err() },
		"missing ttl": func() error {
			return shared.client.Set(context.Background(), key, fmt.Sprint(subject.ExpiresAt.UnixMilli()), 0).Err()
		},
		"beyond maximum lifetime": func() error {
			farFuture := time.Now().UTC().Add(6 * time.Minute).Truncate(time.Millisecond)
			return shared.client.Set(context.Background(), key, fmt.Sprint(farFuture.UnixMilli()), 6*time.Minute).Err()
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := shared.client.Del(context.Background(), key).Err(); err != nil {
				t.Fatal(err)
			}
			if err := install(); err != nil {
				t.Fatal(err)
			}
			assertIntegrationUnavailableWatch(t, shared.revocations, subject)
			if err := shared.revocations.Revoke(context.Background(), subject); !errors.Is(err, gateway.ErrRevocationUnavailable) {
				t.Fatalf("Revoke() error = %v; want unavailable", err)
			}
		})
	}
}

type integrationRevocations struct {
	revocations *Revocations
	client      *goredis.Client
	namespace   string
}

func newIntegrationRevocations(t *testing.T, namespace string, pollInterval time.Duration) *integrationRevocations {
	t.Helper()
	client := integrationClient(t)
	revocations, err := New(Options{
		Client: client, Namespace: namespace, MaxGrantLifetime: 5 * time.Minute,
		PollInterval: pollInterval, OperationTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		keys, _ := client.Keys(ctx, "sandbox-runtime:{*}:revocation:*").Result()
		for _, key := range keys {
			if strings.Contains(key, revocations.grantKeyPrefix) || key == revocations.policyKey {
				_ = client.Del(ctx, key).Err()
			}
		}
		_ = client.Close()
	})
	return &integrationRevocations{revocations: revocations, client: client, namespace: namespace}
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
	options.DialTimeout = 50 * time.Millisecond
	options.ReadTimeout = 50 * time.Millisecond
	options.WriteTimeout = 50 * time.Millisecond
	options.PoolTimeout = 50 * time.Millisecond
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
	return fmt.Sprintf("shared-revocation-%d", time.Now().UnixNano())
}

func integrationSubject(grant string, lifetime time.Duration) gateway.RevocationSubject {
	return gateway.RevocationSubject{GrantID: grant, ExpiresAt: time.Now().UTC().Add(lifetime).Truncate(time.Millisecond)}
}

func provisionIntegrationRevocations(t *testing.T, revocations *Revocations) {
	t.Helper()
	if err := revocations.Provision(context.Background()); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
}

func verifyIntegrationRevocations(t *testing.T, revocations *Revocations) {
	t.Helper()
	if err := revocations.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func assertIntegrationUnavailableWatch(t *testing.T, revocations *Revocations, subject gateway.RevocationSubject) {
	t.Helper()
	watch, err := revocations.Watch(context.Background(), subject)
	if err != nil {
		t.Fatalf("Watch() error = %v; want terminal watch", err)
	}
	assertWatchError(t, watch, gateway.ErrRevocationUnavailable, 100*time.Millisecond)
}

func assertWatchOpen(t *testing.T, watch gateway.RevocationWatch) {
	t.Helper()
	select {
	case <-watch.Done():
		t.Fatalf("watch closed early with %v", watch.Err())
	default:
	}
}

func assertWatchError(t *testing.T, watch gateway.RevocationWatch, want error, timeout time.Duration) {
	t.Helper()
	select {
	case <-watch.Done():
		if err := watch.Err(); !errors.Is(err, want) {
			t.Fatalf("watch error = %v; want %v", err, want)
		}
	case <-time.After(timeout):
		t.Fatalf("watch did not close with %v", want)
	}
}

func assertNoSensitiveRevocationState(t *testing.T, shared *integrationRevocations, sensitive []string) {
	t.Helper()
	ctx := context.Background()
	keys, err := shared.client.Keys(ctx, "sandbox-runtime:{*}:revocation:*").Result()
	if err != nil {
		t.Fatal(err)
	}
	var state []string
	for _, key := range keys {
		state = append(state, key)
		typeName, err := shared.client.Type(ctx, key).Result()
		if err != nil {
			t.Fatal(err)
		}
		switch typeName {
		case "string":
			value, err := shared.client.Get(ctx, key).Result()
			if err != nil {
				t.Fatal(err)
			}
			state = append(state, value)
		case "hash":
			values, err := shared.client.HGetAll(ctx, key).Result()
			if err != nil {
				t.Fatal(err)
			}
			for field, value := range values {
				state = append(state, field, value)
			}
		}
	}
	joined := strings.Join(state, "\n")
	for _, value := range sensitive {
		if strings.Contains(joined, value) {
			t.Fatalf("shared revocation state exposed %q", value)
		}
	}
}

func waitForMissingIntegrationKey(t *testing.T, client *goredis.Client, key string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		exists, err := client.Exists(context.Background(), key).Result()
		if err != nil {
			t.Fatal(err)
		}
		if exists == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tombstone %q did not expire", key)
}
