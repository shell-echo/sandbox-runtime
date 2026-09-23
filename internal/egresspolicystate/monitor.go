package egresspolicystate

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

const MaxPollInterval = time.Second

type Monitor struct {
	tracker     *Tracker
	path        string
	interval    time.Duration
	now         func() time.Time
	initialized bool
}

func NewMonitor(binding Binding, path string, interval time.Duration, now func() time.Time) (*Monitor, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || interval < 50*time.Millisecond ||
		interval > MaxPollInterval || now == nil || now().IsZero() {
		return nil, ErrInvalid
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalid
	}
	return &Monitor{tracker: NewTracker(binding), path: path, interval: interval, now: now}, nil
}

func (m *Monitor) Initial() error {
	_, err := m.InitialSnapshot()
	return err
}

func (m *Monitor) InitialSnapshot() (Snapshot, error) {
	if m == nil || m.tracker == nil {
		return Snapshot{}, ErrInvalid
	}
	snapshot, err := m.tracker.ReadFile(m.path, m.now().UTC())
	if err == nil {
		m.initialized = true
	}
	return snapshot, err
}

func (m *Monitor) Run(ctx context.Context) error {
	if m == nil || m.tracker == nil || !m.initialized || ctx == nil {
		return ErrInvalid
	}
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := m.tracker.ReadFile(m.path, m.now().UTC()); err != nil {
				return err
			}
		}
	}
}
