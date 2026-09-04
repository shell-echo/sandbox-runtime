package edge

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewLocalLimiterRejectsInvalidOptions(t *testing.T) {
	valid := LocalOptions{MaxConcurrent: 2, MaxRequestsPerWindow: 4, Window: time.Second}
	tests := []struct {
		name string
		edit func(*LocalOptions)
	}{
		{"missing concurrency", func(options *LocalOptions) { options.MaxConcurrent = 0 }},
		{"excessive concurrency", func(options *LocalOptions) { options.MaxConcurrent = MaxConcurrentConnections + 1 }},
		{"missing request limit", func(options *LocalOptions) { options.MaxRequestsPerWindow = 0 }},
		{"excessive request limit", func(options *LocalOptions) { options.MaxRequestsPerWindow = MaxRequestsPerWindow + 1 }},
		{"short window", func(options *LocalOptions) { options.Window = MinWindow - time.Nanosecond }},
		{"long window", func(options *LocalOptions) { options.Window = MaxWindow + time.Nanosecond }},
		{"typed nil clock", func(options *LocalOptions) {
			var clock *testClock
			options.Clock = clock
		}},
		{"nil clock function", func(options *LocalOptions) { options.Clock = ClockFunc(nil) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.edit(&options)
			limiter, err := NewLocalLimiter(options)
			if limiter != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("NewLocalLimiter() = %v, %v; want nil, invalid options", limiter, err)
			}
		})
	}
}

func TestLocalLimiterEnforcesRateCapacityAndIdempotentRelease(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)}
	limiter, err := NewLocalLimiter(LocalOptions{
		Clock: clock, MaxConcurrent: 2, MaxRequestsPerWindow: 3, Window: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Acquire(context.Background()); !errors.Is(err, ErrCapacityExhausted) || RetryAfter(err) != time.Second {
		t.Fatalf("capacity Acquire() error = %v retry=%v", err, RetryAfter(err))
	}
	if _, err := limiter.Acquire(context.Background()); !errors.Is(err, ErrRateLimited) || RetryAfter(err) != time.Second {
		t.Fatalf("rate Acquire() error = %v retry=%v", err, RetryAfter(err))
	}
	first.Release()
	first.Release()
	second.Release()
	if _, err := limiter.Acquire(context.Background()); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("released connection bypassed rate limit: %v", err)
	}
	clock.Advance(time.Second)
	replacement, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() after window = %v", err)
	}
	replacement.Release()
}

func TestLocalLimiterConcurrentContentionDoesNotExceedCapacity(t *testing.T) {
	limiter, err := NewLocalLimiter(LocalOptions{
		MaxConcurrent: 4, MaxRequestsPerWindow: 100, Window: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 64
	type result struct {
		lease Lease
		err   error
	}
	results := make(chan result, contenders)
	release := make(chan struct{})
	var workers sync.WaitGroup
	for range contenders {
		workers.Add(1)
		go func() {
			defer workers.Done()
			lease, err := limiter.Acquire(context.Background())
			results <- result{lease: lease, err: err}
			if lease != nil {
				<-release
				lease.Release()
			}
		}()
	}
	accepted, rejected := 0, 0
	for range contenders {
		result := <-results
		switch {
		case result.err == nil && result.lease != nil:
			accepted++
		case errors.Is(result.err, ErrCapacityExhausted):
			rejected++
		default:
			t.Fatalf("contention result = %#v", result)
		}
	}
	if accepted != 4 || rejected != contenders-4 {
		t.Fatalf("contention accepted=%d rejected=%d", accepted, rejected)
	}
	close(release)
	workers.Wait()
	lease, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatalf("capacity was not released: %v", err)
	}
	lease.Release()
}

func TestLocalLimiterFailsClosedForContextAndClockErrors(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)}
	limiter, err := NewLocalLimiter(LocalOptions{
		Clock: clock, MaxConcurrent: 1, MaxRequestsPerWindow: 1, Window: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := limiter.Acquire(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Acquire() error = %v", err)
	}
	lease, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatalf("cancelled request consumed limit: %v", err)
	}
	lease.Release()
	clock.Advance(-time.Second)
	if _, err := limiter.Acquire(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("backwards clock Acquire() error = %v", err)
	}
	if _, err := (*LocalLimiter)(nil).Acquire(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil limiter Acquire() error = %v", err)
	}
	zeroClock := &testClock{}
	zeroLimiter, err := NewLocalLimiter(LocalOptions{
		Clock: zeroClock, MaxConcurrent: 1, MaxRequestsPerWindow: 1, Window: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zeroLimiter.Acquire(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("zero-clock Acquire() error = %v", err)
	}
	if retry := RetryAfter(errors.New("not a rejection")); retry != 0 {
		t.Fatalf("unknown RetryAfter() = %v; want zero", retry)
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}
