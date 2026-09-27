package phase6egress

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
)

const witnessACLJitterAllowance = time.Second

// WitnessRoleGuard checks the effective PostgreSQL ACL once per process-level
// interval, while every action performs only a local freshness check. Its
// terminal failure drains the ingress; removing a bad grant cannot unlock it.
type WitnessRoleGuard struct {
	verify    func(context.Context) error
	interval  time.Duration
	timeout   time.Duration
	freshness time.Duration
	now       func() time.Time

	mu         sync.Mutex
	lastStart  time.Time
	generation uint64
	timer      *time.Timer
	checking   bool
	started    bool
	failed     bool
	closed     bool
	drain      func()
}

// NewWitnessRoleGuard requires P+T+C+J<D, where P is the poll interval, T
// the complete pool-wait/query timeout, C the caller's actual close budget,
// J the scheduler allowance, and D the profile connection-drain bound.
func NewWitnessRoleGuard(pool *pgxpool.Pool, database, role string,
	interval, timeout, closeBudget, drainBudget time.Duration) (*WitnessRoleGuard, error) {
	if pool == nil || database == "" || role == "" || interval < 100*time.Millisecond ||
		interval > 5*time.Second || timeout < time.Second || timeout > 5*time.Second ||
		closeBudget < time.Second || closeBudget > 5*time.Second ||
		drainBudget <= interval+timeout+closeBudget+witnessACLJitterAllowance {
		return nil, ErrUnavailable
	}
	return &WitnessRoleGuard{
		verify: func(ctx context.Context) error {
			return rediscapacity.VerifyPostgresActionHistoryRuntimeRole(ctx, pool, database, role)
		},
		interval: interval, timeout: timeout,
		freshness: interval + timeout + witnessACLJitterAllowance,
		now:       time.Now,
	}, nil
}

// Refresh uses one deadline for pool acquisition and all ACL queries. The
// stored time is the check START, not its finish, so slow checks cannot extend
// the freshness window. A failed or overlapping check latches failure.
func (g *WitnessRoleGuard) Refresh(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	if g.checking {
		g.mu.Unlock()
		g.fail()
		return ErrUnavailable
	}
	if g.failed || g.closed || g.verify == nil || g.now == nil {
		g.mu.Unlock()
		return ErrUnavailable
	}
	g.checking = true
	g.mu.Unlock()
	start := g.now()
	checkCtx, cancel := context.WithTimeout(ctx, g.timeout)
	err := g.verify(checkCtx)
	checkErr := checkCtx.Err()
	cancel()
	if ctx.Err() != nil {
		g.mu.Lock()
		g.checking = false
		g.mu.Unlock()
		return ErrUnavailable
	}
	elapsed := g.now().Sub(start)
	if err != nil || checkErr != nil || elapsed < 0 || elapsed > g.timeout || elapsed >= g.freshness {
		g.mu.Lock()
		g.checking = false
		g.mu.Unlock()
		g.fail()
		return ErrUnavailable
	}
	g.mu.Lock()
	g.checking = false
	if g.failed || g.closed {
		g.mu.Unlock()
		return ErrUnavailable
	}
	g.lastStart = start
	g.generation++
	generation := g.generation
	if g.timer != nil {
		g.timer.Stop()
	}
	g.timer = time.AfterFunc(g.freshness-elapsed, func() { g.expire(generation) })
	g.mu.Unlock()
	return nil
}

// CheckReady is safe on every activation and CDP action: no PostgreSQL query
// runs here, and an expired local observation becomes terminal immediately.
func (g *WitnessRoleGuard) CheckReady() error {
	if g == nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	start, failed, closed, now, freshness := g.lastStart, g.failed, g.closed, g.now, g.freshness
	g.mu.Unlock()
	if failed || closed || start.IsZero() || now == nil {
		return ErrUnavailable
	}
	elapsed := now().Sub(start)
	if elapsed < 0 || elapsed >= freshness {
		g.fail()
		return ErrUnavailable
	}
	return nil
}

func (g *WitnessRoleGuard) expire(generation uint64) {
	g.mu.Lock()
	if g.closed || g.failed || g.generation != generation {
		g.mu.Unlock()
		return
	}
	g.failed = true
	drain := g.drain
	g.mu.Unlock()
	if drain != nil {
		drain()
	}
}

func (g *WitnessRoleGuard) fail() {
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return
	}
	g.failed = true
	if g.timer != nil {
		g.timer.Stop()
	}
	drain := g.drain
	g.mu.Unlock()
	if drain != nil {
		drain()
	}
}

func (g *WitnessRoleGuard) StartPolling(ctx context.Context, drain func()) (<-chan struct{}, error) {
	if g == nil || ctx == nil || ctx.Err() != nil || drain == nil || g.CheckReady() != nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	if g.started || g.closed || g.failed {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	g.started, g.drain = true, drain
	g.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(g.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if g.Refresh(ctx) != nil {
					return
				}
			}
		}
	}()
	return done, nil
}

func (g *WitnessRoleGuard) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.closed = true
	if g.timer != nil {
		g.timer.Stop()
	}
	g.mu.Unlock()
}
