package rediscapacity

import (
	"context"
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
		{"missing total", func(options *Options) { options.MaxTotal = 0 }},
		{"excessive total", func(options *Options) { options.MaxTotal = gateway.MaxConnectionCapacity + 1 }},
		{"tenant beyond total", func(options *Options) { options.MaxPerTenant = options.MaxTotal + 1 }},
		{"session beyond tenant", func(options *Options) { options.MaxPerSession = options.MaxPerTenant + 1 }},
		{"short lease", func(options *Options) { options.LeaseTTL = MinLeaseTTL - time.Millisecond }},
		{"long lease", func(options *Options) { options.LeaseTTL = MaxLeaseTTL + time.Millisecond }},
		{"short renew interval", func(options *Options) { options.RenewInterval = MinRenewInterval - time.Millisecond }},
		{"late renew interval", func(options *Options) { options.RenewInterval = options.LeaseTTL/2 + time.Millisecond }},
		{"short operation timeout", func(options *Options) { options.OperationTimeout = MinOperationTimeout - time.Millisecond }},
		{"long operation timeout", func(options *Options) { options.OperationTimeout = MaxOperationTimeout + time.Millisecond }},
		{"small safety margin", func(options *Options) { options.RenewalSafetyMargin = options.OperationTimeout - time.Millisecond }},
		{"late safety boundary", func(options *Options) { options.RenewalSafetyMargin = options.LeaseTTL - options.RenewInterval }},
		{"sub-millisecond lease", func(options *Options) { options.LeaseTTL += time.Nanosecond }},
		{"sub-millisecond renew", func(options *Options) { options.RenewInterval += time.Nanosecond }},
		{"sub-millisecond safety", func(options *Options) { options.RenewalSafetyMargin += time.Nanosecond }},
		{"sub-millisecond operation", func(options *Options) { options.OperationTimeout += time.Nanosecond }},
		{"operation crosses safety boundary", func(options *Options) {
			options.RenewInterval = time.Second
			options.OperationTimeout = 500 * time.Millisecond
			options.RenewalSafetyMargin = 500 * time.Millisecond
		}},
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
			if capacity, err := New(options); capacity != nil || !errors.Is(err, gateway.ErrInvalidRequest) {
				t.Fatalf("New() = %#v, %v; want nil, invalid request", capacity, err)
			}
		})
	}
}

func TestNewHashesNamespaceAndSubjectIdentity(t *testing.T) {
	options := testOptions(t)
	options.Namespace = "shared-capacity-production-a"
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range capacity.keys {
		if strings.Contains(key, options.Namespace) || !strings.Contains(key, "{") || !strings.Contains(key, "}") {
			t.Fatalf("capacity key %q does not contain only a hashed cluster tag", key)
		}
	}
	subject := testSubject("tenant-private", "sandbox-private", "browser-private")
	tenant, session := subjectFingerprints(subject)
	if len(tenant) != 64 || len(session) != 64 || tenant == session {
		t.Fatalf("subject fingerprints = %q, %q", tenant, session)
	}
	for _, value := range []string{tenant, session} {
		if strings.Contains(value, subject.TenantID) || strings.Contains(value, subject.SandboxID) || strings.Contains(value, subject.BrowserSessionID) {
			t.Fatalf("fingerprint exposed raw subject identity: %q", value)
		}
	}
}

func TestAcquireAndProvisionPropagateCanceledContextWithoutDialing(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := capacity.Provision(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Provision() error = %v; want canceled", err)
	}
	if err := capacity.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() error = %v; want canceled", err)
	}
	if lease, err := capacity.Acquire(ctx, testSubject("tenant-a", "sandbox-a", "browser-a")); lease != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire() = %#v, %v; want nil, canceled", lease, err)
	}
}

func TestAcquireRejectsInvalidSubjectBeforeDialing(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject("tenant-a", "sandbox-a", "browser-a")
	subject.BrowserSessionID = ""
	if lease, err := capacity.Acquire(context.Background(), subject); lease != nil || !errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("Acquire() = %#v, %v; want nil, unavailable", lease, err)
	}
}

func TestAcquireRejectsMalformedOwnerBeforeDialing(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	capacity.ownerSource = func() (string, error) { return strings.Repeat("x", 32), nil }
	if lease, err := capacity.Acquire(context.Background(), testSubject("tenant-a", "sandbox-a", "browser-a")); lease != nil ||
		!errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("Acquire() = %#v, %v; want nil, unavailable", lease, err)
	}
}

func TestAcquireRejectsGrantExpiryBeyondLuaExactRange(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject("tenant-a", "sandbox-a", "browser-a")
	subject.ExpiresAt = time.UnixMilli(maxLuaExactInteger + 1)
	ownerCalled := false
	capacity.ownerSource = func() (string, error) {
		ownerCalled = true
		return strings.Repeat("a", 32), nil
	}
	if lease, err := capacity.Acquire(context.Background(), subject); lease != nil ||
		!errors.Is(err, gateway.ErrCapacityUnavailable) {
		t.Fatalf("Acquire() = %#v, %v; want nil, unavailable", lease, err)
	}
	if ownerCalled {
		t.Fatal("Acquire() generated an owner for an unrepresentable grant expiry")
	}
}

func TestReleaseSerializationHonorsWaitingContext(t *testing.T) {
	done := make(chan struct{})
	close(done)
	lease := &connectionLease{
		capacity: &Capacity{}, stop: make(chan struct{}), done: done,
		events: make(chan gateway.CapacityEvent, 1), releaseGate: make(chan struct{}, 1),
	}
	lease.releaseGate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := lease.Release(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Release() error = %v; want deadline exceeded", err)
	}
}

func TestReleaseSuppressesLaterCapacityEvent(t *testing.T) {
	done := make(chan struct{})
	close(done)
	lease := &connectionLease{
		capacity: &Capacity{}, stop: make(chan struct{}), done: done,
		events: make(chan gateway.CapacityEvent, 1), releaseGate: make(chan struct{}, 1),
	}
	lease.stateMu.Lock()
	lease.releasing = true
	lease.stateMu.Unlock()
	lease.signal("lost", errors.New("diagnostic"))
	select {
	case event := <-lease.events:
		t.Fatalf("release emitted capacity event %#v", event)
	default:
	}
}

func TestConfirmedDeadlineUsesServerRelativeLifetime(t *testing.T) {
	before := time.Now()
	deadline, err := confirmedDeadline(before, "1000", "1750")
	if err != nil {
		t.Fatal(err)
	}
	remaining := deadline.Sub(before)
	if remaining < 700*time.Millisecond || remaining > 900*time.Millisecond {
		t.Fatalf("confirmed deadline remaining = %s", remaining)
	}
	for _, values := range [][2]string{{"bad", "1750"}, {"1000", "bad"}, {"1000", "1000"}} {
		if _, err := confirmedDeadline(before, values[0], values[1]); err == nil {
			t.Fatalf("confirmedDeadline(%q, %q) succeeded", values[0], values[1])
		}
	}
}

func TestDescriptorContainsOnlyStableFingerprints(t *testing.T) {
	options := testOptions(t)
	options.Namespace = "private-capacity-namespace"
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := capacity.Descriptor()
	formatted := fmt.Sprintf("%+v", descriptor)
	if strings.Contains(formatted, options.Namespace) || strings.Contains(formatted, "sandbox-runtime:") {
		t.Fatalf("Descriptor() exposed namespace or Redis key: %s", formatted)
	}
	for _, value := range []string{descriptor.PolicyFingerprint, descriptor.ProvisionScript,
		descriptor.AcquireScript, descriptor.RenewScript, descriptor.ReleaseScript} {
		if value == "" {
			t.Fatalf("Descriptor() contains empty fingerprint: %#v", descriptor)
		}
	}
}

func TestSubjectFingerprintMatchesMemoryCapacityPartition(t *testing.T) {
	first := testSubject("tenant-a", "sandbox-a", "browser-a")
	second := first
	second.CapabilityProfileID = "browser-v2"
	firstTenant, firstSession := subjectFingerprints(first)
	secondTenant, secondSession := subjectFingerprints(second)
	if firstTenant != secondTenant || firstSession != secondSession {
		t.Fatal("capability profile changed the tenant or exact-session partition")
	}
}

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Client: newTestClient(t, nil), Namespace: "shared-capacity-test",
		MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1,
		LeaseTTL: 2 * time.Second, RenewInterval: 400 * time.Millisecond,
		RenewalSafetyMargin: 500 * time.Millisecond, OperationTimeout: 100 * time.Millisecond,
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

func testSubject(tenant, sandbox, browser string) gateway.CapacitySubject {
	return gateway.CapacitySubject{
		TenantID: tenant, SandboxID: sandbox, BrowserSessionID: browser,
		CapabilityProfileID: "browser-v1", ExpiresAt: time.Now().Add(time.Minute),
	}
}
