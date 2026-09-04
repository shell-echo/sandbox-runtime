package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewLocalConnectionCapacityRejectsInvalidOptions(t *testing.T) {
	valid := LocalConnectionCapacityOptions{MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1}
	for _, test := range []struct {
		name   string
		mutate func(*LocalConnectionCapacityOptions)
	}{
		{"missing total", func(options *LocalConnectionCapacityOptions) { options.MaxTotal = 0 }},
		{"excessive total", func(options *LocalConnectionCapacityOptions) { options.MaxTotal = MaxConnectionCapacity + 1 }},
		{"missing tenant", func(options *LocalConnectionCapacityOptions) { options.MaxPerTenant = 0 }},
		{"tenant beyond total", func(options *LocalConnectionCapacityOptions) { options.MaxPerTenant = options.MaxTotal + 1 }},
		{"missing session", func(options *LocalConnectionCapacityOptions) { options.MaxPerSession = 0 }},
		{"session beyond tenant", func(options *LocalConnectionCapacityOptions) { options.MaxPerSession = options.MaxPerTenant + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			capacity, err := NewLocalConnectionCapacity(options)
			if capacity != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewLocalConnectionCapacity() = %v, %v; want nil, invalid request", capacity, err)
			}
		})
	}
}

func TestLocalConnectionCapacityEnforcesAtomicPartitionsAndIdempotentRelease(t *testing.T) {
	capacity, err := NewLocalConnectionCapacity(LocalConnectionCapacityOptions{
		MaxTotal: 3, MaxPerTenant: 2, MaxPerSession: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := acquireLocalCapacity(t, capacity, localCapacitySubject("tenant-a", "sandbox-a", "session-a"))
	if events := first.Events(); events == nil {
		t.Fatal("healthy local lease returned nil event stream")
	} else {
		select {
		case event, open := <-events:
			t.Fatalf("healthy local lease event = %#v, open=%t", event, open)
		default:
		}
	}
	if _, err := capacity.Acquire(context.Background(), localCapacitySubject("tenant-a", "sandbox-a", "session-a")); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("same-session Acquire() error = %v; want capacity exhausted", err)
	}
	second := acquireLocalCapacity(t, capacity, localCapacitySubject("tenant-a", "sandbox-a", "session-b"))
	if _, err := capacity.Acquire(context.Background(), localCapacitySubject("tenant-a", "sandbox-a", "session-c")); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("same-tenant Acquire() error = %v; want capacity exhausted", err)
	}
	third := acquireLocalCapacity(t, capacity, localCapacitySubject("tenant-b", "sandbox-b", "session-a"))
	if _, err := capacity.Acquire(context.Background(), localCapacitySubject("tenant-b", "sandbox-b", "session-b")); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("global Acquire() error = %v; want capacity exhausted", err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatalf("idempotent Release() error = %v", err)
	}
	replacement := acquireLocalCapacity(t, capacity, localCapacitySubject("tenant-a", "sandbox-a", "session-c"))
	for _, lease := range []ConnectionLease{second, third, replacement} {
		if err := lease.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocalConnectionCapacityConcurrentAcquisitionRespectsGlobalAndTenantLimits(t *testing.T) {
	capacity, err := NewLocalConnectionCapacity(LocalConnectionCapacityOptions{
		MaxTotal: 8, MaxPerTenant: 4, MaxPerSession: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 64
	type result struct {
		tenant string
		lease  ConnectionLease
		err    error
	}
	results := make(chan result, contenders)
	release := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < contenders; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			tenant := "tenant-a"
			if index%2 == 1 {
				tenant = "tenant-b"
			}
			lease, err := capacity.Acquire(context.Background(), localCapacitySubject(tenant, "sandbox-"+tenant, fmt.Sprintf("session-%d", index)))
			results <- result{tenant: tenant, lease: lease, err: err}
			if lease != nil {
				<-release
				_ = lease.Release(context.Background())
			}
		}(index)
	}
	accepted := 0
	acceptedByTenant := map[string]int{}
	for range contenders {
		result := <-results
		switch {
		case result.err == nil && result.lease != nil:
			accepted++
			acceptedByTenant[result.tenant]++
		case errors.Is(result.err, ErrCapacityExhausted):
		default:
			t.Fatalf("concurrent acquisition = %#v", result)
		}
	}
	if accepted != 8 {
		t.Fatalf("accepted = %d; want 8", accepted)
	}
	if acceptedByTenant["tenant-a"] != 4 || acceptedByTenant["tenant-b"] != 4 {
		t.Fatalf("accepted by tenant = %#v; want four each", acceptedByTenant)
	}
	close(release)
	workers.Wait()
}

func TestLocalConnectionCapacityConcurrentSameSessionAndRelease(t *testing.T) {
	capacity, err := NewLocalConnectionCapacity(LocalConnectionCapacityOptions{
		MaxTotal: 32, MaxPerTenant: 32, MaxPerSession: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 64
	type result struct {
		lease ConnectionLease
		err   error
	}
	results := make(chan result, contenders)
	release := make(chan struct{})
	var workers sync.WaitGroup
	for range contenders {
		workers.Add(1)
		go func() {
			defer workers.Done()
			lease, acquireErr := capacity.Acquire(context.Background(), localCapacitySubject("tenant-a", "sandbox-a", "session-a"))
			results <- result{lease: lease, err: acquireErr}
			if lease != nil {
				<-release
				_ = lease.Release(context.Background())
			}
		}()
	}
	accepted := 0
	for range contenders {
		result := <-results
		switch {
		case result.err == nil && result.lease != nil:
			accepted++
		case errors.Is(result.err, ErrCapacityExhausted):
		default:
			t.Fatalf("same-session acquisition = %#v", result)
		}
	}
	if accepted != 1 {
		t.Fatalf("same-session accepted = %d; want 1", accepted)
	}
	close(release)
	workers.Wait()

	lease := acquireLocalCapacity(t, capacity, localCapacitySubject("tenant-a", "sandbox-a", "session-a"))
	var releases sync.WaitGroup
	for range contenders {
		releases.Add(1)
		go func() {
			defer releases.Done()
			if releaseErr := lease.Release(context.Background()); releaseErr != nil {
				t.Errorf("concurrent Release() error = %v", releaseErr)
			}
		}()
	}
	releases.Wait()
	replacement := acquireLocalCapacity(t, capacity, localCapacitySubject("tenant-a", "sandbox-a", "session-a"))
	if err := replacement.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLocalConnectionCapacityFailsClosedWithoutConsumingOnInvalidInput(t *testing.T) {
	capacity, err := NewLocalConnectionCapacity(LocalConnectionCapacityOptions{
		MaxTotal: 1, MaxPerTenant: 1, MaxPerSession: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := capacity.Acquire(cancelled, localCapacitySubject("tenant-a", "sandbox-a", "session-a")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Acquire() error = %v", err)
	}
	invalid := localCapacitySubject("tenant-a", "sandbox-a", "session-a")
	invalid.RuntimeSessionID = "second-session"
	if _, err := capacity.Acquire(context.Background(), invalid); !errors.Is(err, ErrCapacityUnavailable) {
		t.Fatalf("invalid Acquire() error = %v", err)
	}
	lease := acquireLocalCapacity(t, capacity, localCapacitySubject("tenant-a", "sandbox-a", "session-a"))
	releaseCtx, stop := context.WithCancel(context.Background())
	stop()
	if err := lease.Release(releaseCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Release() error = %v", err)
	}
	if _, err := capacity.Acquire(context.Background(), localCapacitySubject("tenant-b", "sandbox-b", "session-b")); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("canceled release freed capacity: %v", err)
	}
	if err := lease.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := (*LocalConnectionCapacity)(nil).Acquire(context.Background(), localCapacitySubject("tenant-a", "sandbox-a", "session-a")); !errors.Is(err, ErrCapacityUnavailable) {
		t.Fatalf("nil capacity Acquire() error = %v", err)
	}
}

func acquireLocalCapacity(t *testing.T, capacity *LocalConnectionCapacity, subject CapacitySubject) ConnectionLease {
	t.Helper()
	lease, err := capacity.Acquire(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func localCapacitySubject(tenantID, sandboxID, sessionID string) CapacitySubject {
	return CapacitySubject{
		TenantID: tenantID, SandboxID: sandboxID, BrowserSessionID: sessionID,
		CapabilityProfileID: "browser-v1", ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
}
