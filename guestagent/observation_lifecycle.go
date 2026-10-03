package guestagent

import (
	"context"
	"sync"
)

// observationLifecycle exists only for the opt-in private receipt. It owns
// every Hub path that may invoke the synchronous observation callback. Once
// quiescence begins, no new path may enter and the caller joins all existing
// handlers, authority monitors and explicit disconnects before sealing.
type observationLifecycle struct {
	mu       sync.Mutex
	active   int
	closing  bool
	finished chan struct{}
}

func newObservationLifecycle() *observationLifecycle {
	return &observationLifecycle{finished: make(chan struct{})}
}

func (l *observationLifecycle) enter() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return false
	}
	l.active++
	return true
}

func (l *observationLifecycle) leave() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.active--
	if l.closing && l.active == 0 {
		close(l.finished)
	}
	l.mu.Unlock()
}

func (l *observationLifecycle) quiesce(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	l.mu.Lock()
	if !l.closing {
		l.closing = true
		if l.active == 0 {
			close(l.finished)
		}
	}
	finished := l.finished
	l.mu.Unlock()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}
