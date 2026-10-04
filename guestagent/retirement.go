package guestagent

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RetirementDisposition reports only what happened to one previously
// authenticated connection nonce. Neither inactive nor superseded proves a
// successful same-binding reconnect.
type RetirementDisposition string

const (
	RetirementReleased   RetirementDisposition = "released"
	RetirementInactive   RetirementDisposition = "already_inactive"
	RetirementSuperseded RetirementDisposition = "superseded"
	RetirementStillOwned RetirementDisposition = "still_owned"
)

type RetirementPolicy struct {
	Capacity int
	Retire   func(context.Context, Identity) (RetirementDisposition, error)
	Readback func(context.Context, Identity) (RetirementDisposition, error)
}

var ErrRetirementOutcomeUnknown = errors.New("Guest retirement outcome is unknown")

type retirementState uint8

const (
	retirementReserved retirementState = iota
	retirementActive
	retirementPending
	retirementTerminal
	retirementReleased
)

type retirementItem struct {
	identity          Identity
	attemptDigest     string
	attemptGeneration int64
	state             retirementState
	closed            bool
	started           time.Time
	next              time.Time
	attempts          int
	pins              int
	readback          bool
}

// retirementManager is process-owned, bounded and independent of the
// optional receipt writer. The one worker uses the existing Product pool via
// the injected narrow retirement capability; it never owns database truth.
type retirementManager struct {
	mu       sync.Mutex
	items    map[*retirementItem]struct{}
	capacity int
	retire   func(context.Context, Identity) (RetirementDisposition, error)
	readback func(context.Context, Identity) (RetirementDisposition, error)
	observe  ObservationSink
	closed   bool
	terminal bool
	wake     chan struct{}
	changed  chan struct{}
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

type retirementReservation struct {
	manager *retirementManager
	item    *retirementItem
}

type localOwnerPin struct {
	manager  *retirementManager
	item     *retirementItem
	identity Identity
	once     sync.Once
}

func (m *retirementManager) pinLocalOwner(guestID string, bindingGeneration int64) *localOwnerPin {
	if m == nil || !validID(guestID) || bindingGeneration < 1 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var found *retirementItem
	for item := range m.items {
		if item.identity.GuestID != guestID || item.identity.BindingGeneration != bindingGeneration ||
			(item.state != retirementActive && item.state != retirementPending) {
			continue
		}
		if found != nil {
			return nil
		}
		found = item
	}
	if found == nil {
		return nil
	}
	found.pins++
	return &localOwnerPin{manager: m, item: found, identity: found.identity}
}

func (p *localOwnerPin) release() {
	if p == nil || p.manager == nil {
		return
	}
	p.once.Do(p.releaseOnce)
}

func (p *localOwnerPin) releaseOnce() {
	m := p.manager
	m.mu.Lock()
	if p.item.pins > 0 {
		p.item.pins--
		if p.item.pins == 0 && p.item.state == retirementReleased {
			delete(m.items, p.item)
		}
	}
	m.mu.Unlock()
	m.signal()
}

func newRetirementManager(policy RetirementPolicy, observe ObservationSink) (*retirementManager, error) {
	if policy.Capacity < 1 || policy.Capacity > 4096 || policy.Retire == nil || policy.Readback == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &retirementManager{items: make(map[*retirementItem]struct{}), capacity: policy.Capacity,
		retire: policy.Retire, readback: policy.Readback, observe: observe,
		wake: make(chan struct{}, 1), changed: make(chan struct{}, 1),
		done: make(chan struct{}), ctx: ctx, cancel: cancel}
	go m.run()
	return m, nil
}

func (m *retirementManager) reserve() (*retirementReservation, error) {
	if m == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.terminal || len(m.items) >= m.capacity || m.hasPendingLocked() {
		return nil, ErrUnavailable
	}
	item := &retirementItem{state: retirementReserved}
	m.items[item] = struct{}{}
	return &retirementReservation{manager: m, item: item}, nil
}

func (m *retirementManager) hasPendingLocked() bool {
	for item := range m.items {
		if item.state == retirementPending {
			return true
		}
	}
	return false
}

func (m *retirementManager) ready() bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && !m.terminal && len(m.items) < m.capacity && !m.hasPendingLocked()
}

func (r *retirementReservation) activate(identity Identity) error {
	if r == nil || r.manager == nil || !validID(identity.TenantID) ||
		!validID(identity.WorkspaceID) || !validID(identity.SlotKey) ||
		!validID(identity.GuestID) || !validNonce(identity.ClientNonce) ||
		identity.SlotGeneration < 1 || identity.BindingGeneration < 1 ||
		identity.ProtocolVersion != ProtocolVersion || !identity.ExpiresAt.After(time.Now()) {
		return ErrInvalid
	}
	m := r.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.item.state != retirementReserved {
		return ErrUnavailable
	}
	r.item.identity = identity
	r.item.state = retirementActive
	return nil
}

func (r *retirementReservation) bindAttempt(digest string, generation int64) {
	if r == nil || r.manager == nil {
		return
	}
	m := r.manager
	m.mu.Lock()
	if r.item.state == retirementReserved || r.item.state == retirementActive {
		r.item.attemptDigest = digest
		r.item.attemptGeneration = generation
	}
	m.mu.Unlock()
}

func (r *retirementReservation) attemptGeneration() int64 {
	if r == nil || r.manager == nil {
		return 0
	}
	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()
	return r.item.attemptGeneration
}

// abandon is valid only when authentication definitely did not commit. An
// outcome-unknown attempt must instead retain a terminal hold until scoped
// authoritative reconciliation is available.
func (r *retirementReservation) abandon() {
	if r == nil || r.manager == nil {
		return
	}
	m := r.manager
	m.mu.Lock()
	if r.item.state == retirementReserved {
		r.item.state = retirementReleased
		delete(m.items, r.item)
	}
	m.mu.Unlock()
	m.signal()
}

func (r *retirementReservation) holdUnknown() {
	if r == nil || r.manager == nil {
		return
	}
	m := r.manager
	m.mu.Lock()
	if r.item.state == retirementReserved {
		r.item.state = retirementTerminal
		m.terminal = true
	}
	m.mu.Unlock()
	m.signal()
}

func (r *retirementReservation) failClosed() {
	if r == nil || r.manager == nil {
		return
	}
	m := r.manager
	m.mu.Lock()
	if r.item.state != retirementReleased {
		r.item.state = retirementTerminal
		m.terminal = true
	}
	m.mu.Unlock()
	m.signal()
}

func (r *retirementReservation) state() retirementState {
	if r == nil || r.manager == nil {
		return retirementReleased
	}
	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()
	return r.item.state
}

// pending runs before transport close. It transfers an already reserved slot
// without I/O, so a retry cannot race ahead into the old connected row.
func (r *retirementReservation) pending() error {
	if r == nil || r.manager == nil {
		return ErrInvalid
	}
	m := r.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.item.state != retirementActive {
		return ErrUnavailable
	}
	now := time.Now()
	r.item.state = retirementPending
	r.item.started, r.item.next = now, now
	return nil
}

// closeCompleted permits SQL work only after actual CloseNow succeeded.
func (r *retirementReservation) closeCompleted(success bool) {
	if r == nil || r.manager == nil {
		return
	}
	m := r.manager
	m.mu.Lock()
	if r.item.state == retirementPending {
		if success {
			r.item.closed = true
		} else {
			r.item.state = retirementTerminal
			m.terminal = true
		}
	}
	m.mu.Unlock()
	m.signal()
}

func (m *retirementManager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

func (m *retirementManager) run() {
	defer close(m.done)
	for {
		item, wait, finish := m.nextItem()
		if finish {
			return
		}
		if item == nil {
			if wait < 0 {
				select {
				case <-m.wake:
				case <-m.ctx.Done():
					return
				}
			} else {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-m.wake:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
				case <-m.ctx.Done():
					timer.Stop()
					return
				}
			}
			continue
		}
		deadline := time.Now().Add(time.Second)
		if expiry := item.identity.ExpiresAt; expiry.Before(deadline) {
			deadline = expiry
		}
		if limit := item.started.Add(120 * time.Second); limit.Before(deadline) {
			deadline = limit
		}
		attemptCtx, cancel := context.WithDeadline(m.ctx, deadline)
		var outcome RetirementDisposition
		var err error
		if item.readback {
			outcome, err = m.readback(attemptCtx, item.identity)
		} else {
			outcome, err = m.retire(attemptCtx, item.identity)
		}
		cancel()
		m.finishAttempt(item, outcome, err)
	}
}

func (m *retirementManager) nextItem() (*retirementItem, time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, 0, true
	}
	var next *retirementItem
	for item := range m.items {
		if item.state != retirementPending || !item.closed {
			continue
		}
		deadline := item.started.Add(120 * time.Second)
		if item.identity.ExpiresAt.Before(deadline) {
			deadline = item.identity.ExpiresAt
		}
		if !deadline.After(time.Now()) {
			item.state = retirementTerminal
			m.terminal = true
			m.signal()
			continue
		}
		if item.next.After(deadline) {
			item.next = deadline
		}
		if next == nil || item.next.Before(next.next) {
			next = item
		}
	}
	if next == nil {
		if m.closed && len(m.items) == 0 {
			return nil, 0, true
		}
		return nil, -1, false
	}
	now := time.Now()
	if !next.next.After(now) {
		return next, 0, false
	}
	return nil, next.next.Sub(now), false
}

func (m *retirementManager) finishAttempt(item *retirementItem, outcome RetirementDisposition, err error) {
	m.mu.Lock()
	if item.state != retirementPending {
		m.mu.Unlock()
		return
	}
	var resolved *Observation
	item.attempts++
	if errors.Is(err, ErrRetirementOutcomeUnknown) {
		item.readback = true
	} else if err == nil && outcome == RetirementStillOwned {
		item.readback = false
	}
	if err == nil && (outcome == RetirementReleased || outcome == RetirementInactive) {
		item.state = retirementReleased
		if m.observe != nil && item.attemptDigest != "" {
			resolved = &Observation{Event: ObservationProductDisconnectResolved,
				AttemptDigest: item.attemptDigest, BindingGeneration: item.identity.BindingGeneration,
				Reason: string(outcome)}
		}
		if item.pins == 0 {
			delete(m.items, item)
		}
		m.signal()
		m.mu.Unlock()
		if resolved != nil {
			m.observe(*resolved)
		}
		return
	}
	if err == nil && outcome == RetirementSuperseded {
		item.state = retirementTerminal
		m.terminal = true
		if m.observe != nil && item.attemptDigest != "" {
			resolved = &Observation{Event: ObservationProductDisconnectResolved,
				AttemptDigest: item.attemptDigest, BindingGeneration: item.identity.BindingGeneration,
				Reason: string(outcome)}
		}
		m.signal()
		m.mu.Unlock()
		if resolved != nil {
			m.observe(*resolved)
		}
		return
	}
	now := time.Now()
	if item.attempts >= 16 || now.Sub(item.started) >= 120*time.Second || !item.identity.ExpiresAt.After(now) {
		item.state = retirementTerminal
		m.terminal = true
		m.signal()
		m.mu.Unlock()
		return
	}
	backoff := 250 * time.Millisecond << min(item.attempts-1, 3)
	if backoff > 2*time.Second {
		backoff = 2 * time.Second
	}
	item.next = now.Add(backoff)
	m.signal()
	m.mu.Unlock()
}

func (m *retirementManager) shutdown(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.signal()
	for {
		m.mu.Lock()
		remaining := len(m.items)
		terminal := m.terminal
		m.mu.Unlock()
		if terminal || remaining == 0 {
			m.cancel()
			<-m.done
			if terminal {
				return ErrUnavailable
			}
			return nil
		}
		select {
		case <-m.changed:
		case <-ctx.Done():
			m.cancel()
			<-m.done
			return ErrUnavailable
		}
	}
}
