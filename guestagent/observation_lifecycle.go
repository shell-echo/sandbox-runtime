package guestagent

import (
	"context"
	"sync"
)

// observationLifecycle owns every Hub handler, authority monitor and explicit
// disconnect in the production retirement graph, with or without receipts.
// Once quiescence begins no new path enters; a caller with a live shutdown
// context joins all existing producers before optionally sealing a receipt.
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

func (l *observationLifecycle) admitting() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.closing
}

func (l *observationLifecycle) quiesce(ctx context.Context) error {
	if l == nil {
		return nil
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
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}
