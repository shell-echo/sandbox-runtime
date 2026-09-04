package gateway

import "sync"

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
