package process

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// DependencyCheck is the bounded production-kernel dependency probe executed
// by the independent monitor worker.
type DependencyCheck func(context.Context) error

// DependencyMonitor owns a continuously refreshed, fail-closed readiness bit.
// Dependency loss does not kill the process; recovery requires a later
// successful complete check.
type DependencyMonitor struct {
	check    DependencyCheck
	interval time.Duration
	timeout  time.Duration
	ready    atomic.Bool
}

func NewDependencyMonitor(check DependencyCheck, interval, timeout time.Duration) (*DependencyMonitor, error) {
	if check == nil || interval < 10*time.Millisecond || interval > time.Minute || timeout < 10*time.Millisecond || timeout > 30*time.Second || timeout > interval {
		return nil, errors.New("invalid Product dependency monitor policy")
	}
	return &DependencyMonitor{check: check, interval: interval, timeout: timeout}, nil
}

func (m *DependencyMonitor) Startup(ctx context.Context) error {
	if m == nil || m.check == nil || ctx == nil {
		return errors.New("Product dependency monitor is not initialized")
	}
	m.runCheck(ctx)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.ready.Store(false)
			return nil
		case <-ticker.C:
			m.runCheck(ctx)
		}
	}
}

func (m *DependencyMonitor) Shutdown(context.Context) error {
	if m != nil {
		m.ready.Store(false)
	}
	return nil
}

func (m *DependencyMonitor) Ready(ctx context.Context) error {
	if m == nil || ctx == nil || ctx.Err() != nil || !m.ready.Load() {
		return errors.New("Product dependency is unavailable")
	}
	return nil
}

func (m *DependencyMonitor) runCheck(parent context.Context) {
	checkContext, cancel := context.WithTimeout(parent, m.timeout)
	err := m.check(checkContext)
	cancel()
	m.ready.Store(err == nil && parent.Err() == nil)
}
