package migration

import (
	"errors"
	"sync"
	"time"
)

var ErrInvalidMetric = errors.New("invalid migration metric sample")

type Sample struct {
	LifecycleLatency      time.Duration
	ExecSucceeded         bool
	ExecAttempted         bool
	Orphaned              bool
	SessionStable         bool
	SessionObserved       bool
	ResourceEvidence      bool
	ResourceObserved      bool
	ReconciliationBacklog int64
}

type Snapshot struct {
	LifecycleSamples      uint64
	LifecycleLatency      time.Duration
	ExecAttempts          uint64
	ExecSuccesses         uint64
	OrphanCount           uint64
	SessionObservations   uint64
	StableSessions        uint64
	ResourceObservations  uint64
	ResourceEvidence      uint64
	ReconciliationSamples uint64
	ReconciliationBacklog int64
}

type Metrics struct {
	mu       sync.Mutex
	snapshot Snapshot
}

func (m *Metrics) Record(sample Sample) error {
	if m == nil || sample.LifecycleLatency < 0 || sample.ReconciliationBacklog < 0 || (sample.ExecSucceeded && !sample.ExecAttempted) || (sample.SessionStable && !sample.SessionObserved) || (sample.ResourceEvidence && !sample.ResourceObserved) {
		return ErrInvalidMetric
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if sample.LifecycleLatency > 0 {
		m.snapshot.LifecycleSamples++
		m.snapshot.LifecycleLatency += sample.LifecycleLatency
	}
	if sample.ExecAttempted {
		m.snapshot.ExecAttempts++
		if sample.ExecSucceeded {
			m.snapshot.ExecSuccesses++
		}
	}
	if sample.Orphaned {
		m.snapshot.OrphanCount++
	}
	if sample.SessionObserved {
		m.snapshot.SessionObservations++
		if sample.SessionStable {
			m.snapshot.StableSessions++
		}
	}
	if sample.ResourceObserved {
		m.snapshot.ResourceObservations++
		if sample.ResourceEvidence {
			m.snapshot.ResourceEvidence++
		}
	}
	if sample.ReconciliationBacklog >= 0 {
		m.snapshot.ReconciliationSamples++
		m.snapshot.ReconciliationBacklog += sample.ReconciliationBacklog
	}
	return nil
}

func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshot
}
