//go:build darwin || linux

package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

// executionLedger is the held candidate's single create/exec/retirement owner.
// It is intentionally package-private until the new Profile, PG and physical
// observers exist. Tests use bounded callbacks, not a production Docker port.
type executionLedger struct {
	mu             sync.Mutex
	store          executionStateStorage
	binding        executionBinding
	key            string
	current        executionState
	snapshot       controlstorage.StateSnapshot
	clock          func() time.Time
	createReturned map[string]bool
	inFlight       int
	drained        chan struct{}
	closing        bool
	poisoned       bool
	fault          func(string) error
}

// Only the composed source owner implements this port outside tests. The marker
// prevents a raw file Store from accidentally satisfying the ledger dependency.
type executionStateStorage interface {
	ReadState(context.Context, string) (controlstorage.StateSnapshot, error)
	CompareState(context.Context, string, controlstorage.StateSnapshot, []byte) error
	Check(context.Context) error
	Close() error
	executionSourceOwner()
}

// loadExecutionLedger takes exclusive ownership, including on failure. It never
// repairs a missing state on reopen or removes an initialization marker.
func loadExecutionLedger(ctx context.Context, s executionStateStorage, b executionBinding, initialize bool) (*executionLedger, error) {
	if s == nil {
		return nil, ErrInvalidReceiptState
	}
	ok := false
	defer func() {
		if !ok {
			_ = s.Close()
		}
	}()
	if ctx == nil || ctx.Err() != nil || b.validate() != nil {
		return nil, ErrInvalidReceiptState
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if err := s.Check(ctx); err != nil {
		return nil, err
	}
	b = b.clone()
	l := &executionLedger{store: s, binding: b, key: b.digest()[7:39], clock: time.Now, createReturned: map[string]bool{}}
	var err error
	l.snapshot, err = s.ReadState(ctx, l.key)
	if err != nil {
		return nil, err
	}
	if initialize {
		if l.snapshot.Found {
			return nil, ErrInvalidReceiptState
		}
		if err := l.persist(ctx, newExecutionState(b), false); err != nil {
			return nil, err
		}
	} else {
		if !l.snapshot.Found {
			return nil, ErrInvalidReceiptState
		}
		l.current, err = decodeExecutionState(l.snapshot.Data, b, l.clock().UTC())
		if err != nil {
			return nil, err
		}
	}
	ok = true
	return l, nil
}

func (l *executionLedger) check(ctx context.Context) error {
	if l.store == nil || l.closing || l.poisoned || ctx == nil || ctx.Err() != nil {
		return ErrInvalidReceiptState
	}
	s, err := l.store.ReadState(ctx, l.key)
	d, _ := json.Marshal(l.current)
	if err != nil || !s.Found || s.Revision != l.snapshot.Revision || s.Digest != l.snapshot.Digest || !bytes.Equal(d, s.Data) || l.current.validate(l.binding, l.clock().UTC()) != nil {
		return ErrInvalidReceiptState
	}
	return nil
}
func (l *executionLedger) persist(ctx context.Context, next executionState, advance bool) error {
	if advance {
		if next.Revision == ^uint64(0) {
			return ErrReceiptCapacity
		}
		next.Revision++
	}
	if err := next.validate(l.binding, l.clock().UTC()); err != nil {
		return err
	}
	d, _ := json.Marshal(next)
	if l.fault != nil && l.fault("before-state") != nil {
		l.poisoned = true
		return controlstorage.ErrUncertain
	}
	if err := l.store.CompareState(ctx, l.key, l.snapshot, d); err != nil {
		l.poisoned = true
		return err
	}
	if l.fault != nil && l.fault("after-state") != nil {
		l.poisoned = true
		return controlstorage.ErrUncertain
	}
	s, err := l.store.ReadState(ctx, l.key)
	if err != nil || !bytes.Equal(s.Data, d) {
		l.poisoned = true
		return controlstorage.ErrUncertain
	}
	l.current, l.snapshot = next, s
	return nil
}
func (l *executionLedger) beginCallback() {
	if l.inFlight == 0 {
		l.drained = make(chan struct{})
	}
	l.inFlight++
}
func (l *executionLedger) endCallback() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.inFlight--
	if l.inFlight == 0 {
		close(l.drained)
	}
}

func (l *executionLedger) create(ctx context.Context, a executionCreate, physical func(context.Context, executionResources) error) error {
	if l == nil || ctx == nil || physical == nil || ctx.Err() != nil {
		return ErrInvalidAuthority
	}
	l.mu.Lock()
	if l.check(ctx) != nil || a.validate(l.binding, l.clock().UTC()) != nil {
		l.mu.Unlock()
		return ErrInvalidAuthority
	}
	for _, old := range l.current.Allocations {
		if old.Create.digest() == a.digest() {
			l.mu.Unlock()
			return ErrReceiptReplay
		}
		if old.Create.AllocationID == a.AllocationID || old.Create.SlotID == a.SlotID || old.Create.SandboxID == a.SandboxID || old.Create.OperationID == a.OperationID {
			l.mu.Unlock()
			return ErrReceiptConflict
		}
	}
	next := l.current.clone()
	next.Allocations = append(next.Allocations, executionAllocationRecord{Create: a, CreateStatus: executionUnknown, HighFence: a.Fence, UpdatedAt: l.clock().UTC()})
	if err := l.persist(ctx, next, true); err != nil {
		l.mu.Unlock()
		return err
	}
	l.beginCallback()
	resources := a.resources(l.binding)
	l.mu.Unlock()
	defer l.endCallback()
	bounded, cancel := context.WithDeadline(ctx, a.ExpiresAt)
	defer cancel()
	if bounded.Err() != nil {
		return bounded.Err()
	}
	err := physical(bounded, resources)
	if err == nil && bounded.Err() == nil {
		l.mu.Lock()
		l.createReturned[a.digest()] = true
		l.mu.Unlock()
	}
	return errors.Join(err, bounded.Err())
}

// The collector is internal and typed for the NEW resource set. A callback
// acknowledgement by itself never marks create Completed. No production
// collector currently implements this port; old observer types do not match.
type executionCompletionCollector interface {
	observeExecutionCreate(context.Context, executionBinding, executionCreate, uint64, string) (executionCompletionObservation, error)
}

func (l *executionLedger) completeCreate(ctx context.Context, a executionCreate, collector executionCompletionCollector) error {
	if l == nil || ctx == nil || collector == nil {
		return ErrInvalidReceiptState
	}
	l.mu.Lock()
	i := l.current.allocation(a.digest())
	if l.check(ctx) != nil || i < 0 || !l.createReturned[a.digest()] || l.current.Allocations[i].CreateStatus != executionUnknown ||
		l.current.Allocations[i].Retirement != nil || a.validate(l.binding, l.clock().UTC()) != nil {
		l.mu.Unlock()
		return ErrReceiptConflict
	}
	revision, stateDigest := l.current.Revision, l.current.digest()
	b := l.binding.clone()
	l.beginCallback()
	l.mu.Unlock()
	defer l.endCallback()
	bounded, cancel := context.WithDeadline(ctx, a.ExpiresAt)
	defer cancel()
	if bounded.Err() != nil {
		return bounded.Err()
	}
	o, err := collector.observeExecutionCreate(bounded, b, a, revision, stateDigest)
	o = cloneExecutionCompletion(o)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil || bounded.Err() != nil || l.check(ctx) != nil || l.current.Revision != revision || o.SourceRevision != revision || o.SourceStateDigest != stateDigest ||
		o.validate(l.binding, a, l.clock().UTC()) != nil || l.current.Allocations[i].Retirement != nil {
		return ErrReceiptConflict
	}
	next := l.current.clone()
	next.Allocations[i].CreateStatus = executionCompleted
	next.Allocations[i].Completion = &o
	next.Allocations[i].UpdatedAt = l.clock().UTC()
	return l.persist(ctx, next, true)
}

func (l *executionLedger) execute(ctx context.Context, c executionClaim, physical func(context.Context, executionClaim, executionResources) error) error {
	if l == nil || ctx == nil || physical == nil || ctx.Err() != nil {
		return ErrInvalidAuthority
	}
	c = c.clone()
	l.mu.Lock()
	i := l.current.allocation(c.CreateDigest)
	if l.check(ctx) != nil || i < 0 {
		l.mu.Unlock()
		return ErrReceiptConflict
	}
	a := l.current.Allocations[i]
	if c.validate(l.binding, a.Create, l.clock().UTC()) != nil {
		l.mu.Unlock()
		return ErrInvalidAuthority
	}
	if at, err := l.current.existing(c); err != nil || at >= 0 {
		l.mu.Unlock()
		if err != nil {
			return err
		}
		return ErrReceiptReplay
	}
	if a.CreateStatus != executionCompleted || a.Completion == nil || c.CompletionDigest != a.Completion.digest() ||
		a.Retirement != nil || a.CleanupUnknown || l.current.possible(c.CreateDigest) || uint64(c.Request.FencingToken) < a.HighFence {
		l.mu.Unlock()
		return ErrReceiptConflict
	}
	next := l.current.clone()
	next.Allocations[i].HighFence = uint64(c.Request.FencingToken)
	next.Allocations[i].UpdatedAt = l.clock().UTC()
	next.Executions = append(next.Executions, executionRecord{Claim: c, Status: executionUnknown, RecordedAt: l.clock().UTC()})
	if err := l.persist(ctx, next, true); err != nil {
		l.mu.Unlock()
		return err
	}
	l.beginCallback()
	resources := a.Create.resources(l.binding)
	l.mu.Unlock()
	defer l.endCallback()
	bounded, cancel := context.WithDeadline(ctx, c.ExpiresAt)
	defer cancel()
	if bounded.Err() != nil {
		return bounded.Err()
	}
	// Persisted Unknown remains occupied regardless of callback success/error,
	// caller cancellation, local drain, expiration or a later allocation close.
	return errors.Join(physical(bounded, c.clone(), resources), bounded.Err())
}

// closeClaim records an exact historical claim's non-admission BEFORE a late
// arrival. It never downgrades Unknown. This local tombstone is not the future
// authenticated cross-service no-effect evidence or permission for a PG CAS.
func (l *executionLedger) closeClaim(ctx context.Context, c executionClaim) error {
	if l == nil || ctx == nil {
		return ErrInvalidAuthority
	}
	c = c.clone()
	l.mu.Lock()
	defer l.mu.Unlock()
	i := l.current.allocation(c.CreateDigest)
	if l.check(ctx) != nil || i < 0 {
		return ErrReceiptConflict
	}
	a := l.current.Allocations[i]
	if c.validate(l.binding, a.Create, c.AcceptedAt) != nil || c.AcceptedAt.After(l.clock().UTC()) || a.Completion == nil || c.CompletionDigest != a.Completion.digest() {
		return ErrInvalidAuthority
	}
	if at, err := l.current.existing(c); err != nil {
		return err
	} else if at >= 0 {
		if l.current.Executions[at].Status != executionClosedBeforeEffect {
			return ErrReceiptConflict
		}
		return nil
	}
	next := l.current.clone()
	// Closing a newer claim is also a fence observation. Otherwise a distinct
	// older claim could arrive after this tombstone and still be dispatched.
	fence := uint64(c.Request.FencingToken)
	if fence > a.HighFence {
		if a.Retirement != nil {
			return ErrReceiptConflict
		}
		next.Allocations[i].HighFence = fence
		next.Allocations[i].UpdatedAt = l.clock().UTC()
	}
	next.Executions = append(next.Executions, executionRecord{Claim: c, Status: executionClosedBeforeEffect, RecordedAt: l.clock().UTC()})
	return l.persist(ctx, next, true)
}

func (l *executionLedger) retire(ctx context.Context, a executionCreate, r executionRetirement) error {
	if l == nil || ctx == nil {
		return ErrInvalidAuthority
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.check(ctx) != nil || a.validate(l.binding, a.IssuedAt) != nil || r.validate(l.binding, a, l.clock().UTC()) != nil {
		return ErrInvalidAuthority
	}
	next := l.current.clone()
	i := next.allocation(a.digest())
	if i < 0 {
		// Closure can win before the original create message arrives.
		for _, old := range next.Allocations {
			if old.Create.AllocationID == a.AllocationID || old.Create.SlotID == a.SlotID || old.Create.SandboxID == a.SandboxID || old.Create.OperationID == a.OperationID {
				return ErrReceiptConflict
			}
		}
		next.Allocations = append(next.Allocations, executionAllocationRecord{Create: a, CreateStatus: executionClosedBeforeEffect, HighFence: a.Fence, UpdatedAt: r.IssuedAt})
		i = len(next.Allocations) - 1
	}
	aRecord := &next.Allocations[i]
	if aRecord.Retirement != nil {
		if *aRecord.Retirement == r {
			return nil
		}
		return ErrReceiptConflict
	}
	if r.Fence < aRecord.HighFence {
		return ErrReceiptConflict
	}
	aRecord.Retirement = &r
	aRecord.HighFence = r.Fence
	aRecord.UpdatedAt = l.clock().UTC()
	return l.persist(ctx, next, true)
}
func (l *executionLedger) cleanup(ctx context.Context, a executionCreate, r executionRetirement, physical func(context.Context, executionResources) error) error {
	if l == nil || ctx == nil || physical == nil {
		return ErrInvalidAuthority
	}
	l.mu.Lock()
	i := l.current.allocation(a.digest())
	if l.check(ctx) != nil || i < 0 || r.validate(l.binding, a, l.clock().UTC()) != nil {
		l.mu.Unlock()
		return ErrReceiptConflict
	}
	record := l.current.Allocations[i]
	if record.CreateStatus != executionCompleted || record.Retirement == nil || *record.Retirement != r || record.CleanupUnknown ||
		l.current.possible(a.digest()) || l.inFlight != 0 {
		l.mu.Unlock()
		return ErrReceiptConflict
	}
	next := l.current.clone()
	next.Allocations[i].CleanupUnknown = true
	next.Allocations[i].UpdatedAt = l.clock().UTC()
	if err := l.persist(ctx, next, true); err != nil {
		l.mu.Unlock()
		return err
	}
	l.beginCallback()
	resources := a.resources(l.binding)
	l.mu.Unlock()
	defer l.endCallback()
	bounded, cancel := context.WithDeadline(ctx, r.ExpiresAt)
	defer cancel()
	if bounded.Err() != nil {
		return bounded.Err()
	}
	return errors.Join(physical(bounded, resources), bounded.Err()) // no Released transition
}

func (l *executionLedger) close(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrInvalidReceiptState
	}
	l.mu.Lock()
	l.closing = true
	for l.inFlight != 0 {
		wait := l.drained
		l.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
		l.mu.Lock()
	}
	defer l.mu.Unlock()
	if l.store == nil {
		return nil
	}
	err := l.store.Close()
	l.store = nil
	return err
}
