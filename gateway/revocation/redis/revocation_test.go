package redisrevocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestNewRejectsUnsafeOptions(t *testing.T) {
	valid := testOptions(t)
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"nil client", func(options *Options) { options.Client = nil }},
		{"empty namespace", func(options *Options) { options.Namespace = "" }},
		{"invalid namespace", func(options *Options) { options.Namespace = "tenant/{raw}" }},
		{"long namespace", func(options *Options) { options.Namespace = strings.Repeat("a", maxNamespaceLength+1) }},
		{"short maximum lifetime", func(options *Options) { options.MaxGrantLifetime = MinGrantLifetime - time.Millisecond }},
		{"long maximum lifetime", func(options *Options) { options.MaxGrantLifetime = MaxGrantLifetime + time.Millisecond }},
		{"short poll", func(options *Options) { options.PollInterval = MinPollInterval - time.Millisecond }},
		{"long poll", func(options *Options) { options.PollInterval = MaxPollInterval + time.Millisecond }},
		{"short operation", func(options *Options) { options.OperationTimeout = MinOperationTimeout - time.Millisecond }},
		{"long operation", func(options *Options) { options.OperationTimeout = MaxOperationTimeout + time.Millisecond }},
		{"operation beyond poll", func(options *Options) { options.OperationTimeout = options.PollInterval + time.Millisecond }},
		{"sub-millisecond poll", func(options *Options) { options.PollInterval += time.Nanosecond }},
		{"sub-millisecond maximum lifetime", func(options *Options) { options.MaxGrantLifetime += time.Nanosecond }},
		{"sub-millisecond operation", func(options *Options) { options.OperationTimeout += time.Nanosecond }},
		{"client retries", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.MaxRetries = 1 })
		}},
		{"client ignores context", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.ContextTimeoutEnabled = false })
		}},
		{"client RESP3", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.Protocol = 3 })
		}},
		{"client identity", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.DisableIdentity = false })
		}},
		{"client dial exceeds operation", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.DialTimeout = time.Second })
		}},
		{"client read exceeds operation", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.ReadTimeout = time.Second })
		}},
		{"client write exceeds operation", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.WriteTimeout = time.Second })
		}},
		{"client pool exceeds operation", func(options *Options) {
			options.Client = newTestClient(t, func(redis *goredis.Options) { redis.PoolTimeout = time.Second })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if revocations, err := New(options); revocations != nil || !errors.Is(err, gateway.ErrInvalidRequest) {
				t.Fatalf("New() = %#v, %v; want nil, invalid request", revocations, err)
			}
		})
	}
}

func TestNewHashesNamespaceAndGrantIdentity(t *testing.T) {
	options := testOptions(t)
	options.Namespace = "private-revocation-production-a"
	revocations, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject("grant-private-sensitive", time.Minute)
	for _, key := range revocations.subjectKeys(subject) {
		if strings.Contains(key, options.Namespace) || strings.Contains(key, subject.GrantID) ||
			!strings.Contains(key, "{") || !strings.Contains(key, "}") {
			t.Fatalf("revocation key %q exposed a raw identity or omitted its cluster tag", key)
		}
	}
	if keys := revocations.subjectKeys(subject); keys[0] != revocations.policyKey ||
		!strings.HasPrefix(keys[1], revocations.grantKeyPrefix) || len(strings.TrimPrefix(keys[1], revocations.grantKeyPrefix)) != 64 {
		t.Fatalf("subject keys = %#v; want policy and SHA-256 grant key", keys)
	}
	wantDigest := sha256.Sum256([]byte(subject.GrantID))
	if got := strings.TrimPrefix(revocations.subjectKeys(subject)[1], revocations.grantKeyPrefix); got != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("grant digest = %q; want exact grant-id SHA-256", got)
	}
}

func TestOperationsPropagateCanceledContextWithoutDialing(t *testing.T) {
	revocations, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := revocations.Provision(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Provision() error = %v; want canceled", err)
	}
	if err := revocations.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() error = %v; want canceled", err)
	}
	if err := revocations.Revoke(ctx, testSubject("grant-a", time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Revoke() error = %v; want canceled", err)
	}
	if watch, err := revocations.Watch(ctx, testSubject("grant-a", time.Minute)); watch != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch() = %#v, %v; want nil, canceled", watch, err)
	}
}

func TestOperationsRejectInvalidSubjectBeforeDialing(t *testing.T) {
	revocations, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []gateway.RevocationSubject{
		{},
		{GrantID: "grant-a", ExpiresAt: time.UnixMilli(maxLuaExactInteger + 1)},
	} {
		if err := revocations.Revoke(context.Background(), subject); !errors.Is(err, gateway.ErrRevocationUnavailable) {
			t.Fatalf("Revoke(%#v) error = %v; want unavailable", subject, err)
		}
		if watch, err := revocations.Watch(context.Background(), subject); watch != nil || !errors.Is(err, gateway.ErrRevocationUnavailable) {
			t.Fatalf("Watch(%#v) = %#v, %v; want nil, unavailable", subject, watch, err)
		}
	}
}

func TestInitialStoreFailureReturnsStableTerminalWatch(t *testing.T) {
	options := testOptions(t)
	revocations, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := options.Client.Close(); err != nil {
		t.Fatal(err)
	}
	watch, err := revocations.Watch(context.Background(), testSubject("grant-store-unavailable", time.Minute))
	if err != nil {
		t.Fatalf("Watch() error = %v; want terminal watch", err)
	}
	select {
	case <-watch.Done():
	default:
		t.Fatal("Watch() remained open after synchronous store failure")
	}
	for index := 0; index < 3; index++ {
		if err := watch.Err(); err != gateway.ErrRevocationUnavailable {
			t.Fatalf("Err() = %v; want stable ErrRevocationUnavailable", err)
		}
	}
}

func TestWatchErrorIsStable(t *testing.T) {
	watch := &revocationWatch{done: make(chan struct{})}
	watch.finish(gateway.ErrRevoked)
	watch.finish(gateway.ErrRevocationUnavailable)
	<-watch.Done()
	for index := 0; index < 3; index++ {
		if err := watch.Err(); err != gateway.ErrRevoked {
			t.Fatalf("Err() = %v; want stable ErrRevoked", err)
		}
	}
	var nilWatch *revocationWatch
	if nilWatch.Done() != nil || nilWatch.Err() != gateway.ErrRevocationUnavailable {
		t.Fatal("nil watch did not fail closed")
	}
}

func TestDescriptorContainsOnlyStableFingerprints(t *testing.T) {
	options := testOptions(t)
	options.Namespace = "private-revocation-namespace"
	revocations, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := revocations.Descriptor()
	formatted := fmt.Sprintf("%+v", descriptor)
	if strings.Contains(formatted, options.Namespace) || strings.Contains(formatted, "sandbox-runtime:") {
		t.Fatalf("Descriptor() exposed namespace or Redis key: %s", formatted)
	}
	for _, value := range []string{descriptor.PolicyFingerprint, descriptor.ProvisionScript, descriptor.CheckScript, descriptor.RevokeScript} {
		if value == "" {
			t.Fatalf("Descriptor() contains empty fingerprint: %#v", descriptor)
		}
	}
}

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Client: newTestClient(t, nil), Namespace: "shared-revocation-test",
		MaxGrantLifetime: time.Hour, PollInterval: 100 * time.Millisecond, OperationTimeout: 100 * time.Millisecond,
	}
}

func newTestClient(t *testing.T, mutate func(*goredis.Options)) *goredis.Client {
	t.Helper()
	options := &goredis.Options{
		Addr: "127.0.0.1:1", Protocol: 2, MaxRetries: -1, ContextTimeoutEnabled: true, DisableIdentity: true,
		DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond, PoolTimeout: 100 * time.Millisecond,
	}
	if mutate != nil {
		mutate(options)
	}
	client := goredis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func testSubject(grant string, lifetime time.Duration) gateway.RevocationSubject {
	return gateway.RevocationSubject{GrantID: grant, ExpiresAt: time.Now().Add(lifetime)}
}
