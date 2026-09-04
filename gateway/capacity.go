package gateway

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

var (
	errCapacityLeaseLost        = errors.New("Runtime Gateway connection capacity lease was lost")
	errCapacityLeaseUnavailable = errors.New("Runtime Gateway connection capacity lease signal is unavailable")
	localCapacityEvents         = make(chan CapacityEvent)
)

type connectionCapacity struct {
	mu            sync.Mutex
	maxTotal      int
	maxPerSession int
	total         int
	bySession     map[connectionSessionKey]int
}

type connectionSessionKey struct {
	tenantID         string
	sandboxID        string
	runtimeSessionID string
	browserSessionID string
}

func newConnectionCapacity(maxTotal, maxPerSession int) (*connectionCapacity, error) {
	if maxTotal == 0 && maxPerSession == 0 {
		return nil, nil
	}
	if maxTotal < 1 || maxTotal > MaxConnectionCapacity || maxPerSession < 1 || maxPerSession > maxTotal {
		return nil, ErrInvalidRequest
	}
	return &connectionCapacity{
		maxTotal: maxTotal, maxPerSession: maxPerSession,
		bySession: make(map[connectionSessionKey]int),
	}, nil
}

func (c *connectionCapacity) acquire(grant Grant) (func(), error) {
	if c == nil {
		return func() {}, nil
	}
	key := connectionSessionKey{
		tenantID: grant.TenantID, sandboxID: grant.SandboxID,
		runtimeSessionID: grant.RuntimeSessionID, browserSessionID: grant.BrowserSessionID,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total >= c.maxTotal || c.bySession[key] >= c.maxPerSession {
		return nil, ErrCapacityExhausted
	}
	c.total++
	c.bySession[key]++

	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.total--
			c.bySession[key]--
			if c.bySession[key] == 0 {
				delete(c.bySession, key)
			}
		})
	}, nil
}

// LocalConnectionCapacityOptions define a process-local reference adapter for
// the authenticated-capacity port. It provides atomic global, tenant, and
// session accounting, but no cross-process or distributed guarantee.
type LocalConnectionCapacityOptions struct {
	MaxTotal      int
	MaxPerTenant  int
	MaxPerSession int
}

type LocalConnectionCapacity struct {
	mu sync.Mutex

	maxTotal      int
	maxPerTenant  int
	maxPerSession int
	total         int
	byTenant      map[string]int
	bySession     map[connectionSessionKey]int
}

func NewLocalConnectionCapacity(options LocalConnectionCapacityOptions) (*LocalConnectionCapacity, error) {
	if options.MaxTotal < 1 || options.MaxTotal > MaxConnectionCapacity ||
		options.MaxPerTenant < 1 || options.MaxPerTenant > options.MaxTotal ||
		options.MaxPerSession < 1 || options.MaxPerSession > options.MaxPerTenant {
		return nil, fmt.Errorf("%w: authenticated connection capacity", ErrInvalidRequest)
	}
	return &LocalConnectionCapacity{
		maxTotal: options.MaxTotal, maxPerTenant: options.MaxPerTenant, maxPerSession: options.MaxPerSession,
		byTenant: make(map[string]int), bySession: make(map[connectionSessionKey]int),
	}, nil
}

func (c *LocalConnectionCapacity) Acquire(ctx context.Context, subject CapacitySubject) (ConnectionLease, error) {
	if c == nil {
		return nil, ErrCapacityUnavailable
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := subject.validate(); err != nil {
		return nil, errors.Join(ErrCapacityUnavailable, err)
	}
	key := connectionSessionKey{
		tenantID: subject.TenantID, sandboxID: subject.SandboxID,
		runtimeSessionID: subject.RuntimeSessionID, browserSessionID: subject.BrowserSessionID,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total >= c.maxTotal || c.byTenant[subject.TenantID] >= c.maxPerTenant || c.bySession[key] >= c.maxPerSession {
		return nil, ErrCapacityExhausted
	}
	c.total++
	c.byTenant[subject.TenantID]++
	c.bySession[key]++
	return &localConnectionLease{capacity: c, tenantID: subject.TenantID, sessionKey: key}, nil
}

func (s CapacitySubject) validate() error {
	if !identifierPattern.MatchString(s.TenantID) || !identifierPattern.MatchString(s.SandboxID) ||
		!identifierPattern.MatchString(s.CapabilityProfileID) || s.ExpiresAt.IsZero() {
		return ErrInvalidRequest
	}
	sessions := 0
	if s.RuntimeSessionID != "" {
		if !identifierPattern.MatchString(s.RuntimeSessionID) {
			return ErrInvalidRequest
		}
		sessions++
	}
	if s.BrowserSessionID != "" {
		if !identifierPattern.MatchString(s.BrowserSessionID) {
			return ErrInvalidRequest
		}
		sessions++
	}
	if sessions != 1 {
		return ErrInvalidRequest
	}
	return nil
}

type localConnectionLease struct {
	mu sync.Mutex

	capacity   *LocalConnectionCapacity
	tenantID   string
	sessionKey connectionSessionKey
	released   bool
}

func (l *localConnectionLease) Events() <-chan CapacityEvent { return localCapacityEvents }

func (l *localConnectionLease) Release(ctx context.Context) error {
	if l == nil || l.capacity == nil {
		return ErrCapacityUnavailable
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.capacity.mu.Lock()
	defer l.capacity.mu.Unlock()
	l.capacity.total--
	l.capacity.byTenant[l.tenantID]--
	if l.capacity.byTenant[l.tenantID] == 0 {
		delete(l.capacity.byTenant, l.tenantID)
	}
	l.capacity.bySession[l.sessionKey]--
	if l.capacity.bySession[l.sessionKey] == 0 {
		delete(l.capacity.bySession, l.sessionKey)
	}
	l.released = true
	return nil
}

func capacitySubjectForGrant(grant Grant) CapacitySubject {
	return CapacitySubject{
		TenantID: grant.TenantID, SandboxID: grant.SandboxID,
		RuntimeSessionID: grant.RuntimeSessionID, BrowserSessionID: grant.BrowserSessionID,
		CapabilityProfileID: grant.CapabilityProfileID, ExpiresAt: grant.ExpiresAt.UTC(),
	}
}

func initialCapacityEventError(events <-chan CapacityEvent) error {
	if events == nil {
		return errors.Join(ErrCapacityUnavailable, errCapacityLeaseUnavailable)
	}
	select {
	case event, open := <-events:
		return capacityEventError(event, open)
	default:
		return nil
	}
}

func capacityEventError(event CapacityEvent, open bool) error {
	if !open {
		return errors.Join(ErrCapacityUnavailable, errCapacityLeaseUnavailable, errors.New("capacity lease event stream closed"))
	}
	switch event.Kind {
	case CapacityEventLost:
		return errors.Join(ErrCapacityUnavailable, errCapacityLeaseLost, event.Err)
	case CapacityEventUnavailable:
		return errors.Join(ErrCapacityUnavailable, errCapacityLeaseUnavailable, event.Err)
	default:
		return errors.Join(ErrCapacityUnavailable, errCapacityLeaseUnavailable, errors.New("capacity lease event kind is invalid"), event.Err)
	}
}

func capacityAuditType(err error) AuditEventType {
	if errors.Is(err, errCapacityLeaseLost) {
		return AuditCapacityLost
	}
	if errors.Is(err, ErrCapacityUnavailable) {
		return AuditCapacityUnavailable
	}
	return ""
}

func isTypedNil(value any) bool {
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

var _ ConnectionCapacity = (*LocalConnectionCapacity)(nil)
var _ ConnectionLease = (*localConnectionLease)(nil)
