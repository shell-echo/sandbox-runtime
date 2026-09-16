package qualificationharness

import (
	"context"
	"errors"
	"os"
	"sync"
)

const (
	ProviderLocalState          = "provider_local_state"
	CallerOwnedCorrelationState = "caller_owned_correlation_state"
	RuntimeResourceState        = "runtime_resource_state"
)

var errPersistentState = errors.New("qualification persistent state preflight failed")

type stateDirectoryPin struct {
	file      *os.File
	info      os.FileInfo
	path      string
	name      string
	ancestors []os.FileInfo
}

type persistentState struct {
	mu     sync.Mutex
	closed bool
	parent *stateDirectoryPin
	root   *stateDirectoryPin
	stores map[string]*stateDirectoryPin
}

func persistentStoreIDs() []string {
	return []string{ProviderLocalState, CallerOwnedCorrelationState, RuntimeResourceState}
}

func (s *persistentState) path(storeID string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", false
	}
	store, ok := s.stores[storeID]
	if !ok || store == nil {
		return "", false
	}
	return store.path, true
}

func (s *persistentState) recheck(ctx context.Context) error {
	if ctx == nil || s == nil {
		return errPersistentState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errPersistentState
	}
	return recheckPersistentState(ctx, s)
}

func (s *persistentState) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var result error
	for _, storeID := range persistentStoreIDs() {
		if store := s.stores[storeID]; store != nil && store.file != nil {
			result = errors.Join(result, store.file.Close())
		}
	}
	if s.root != nil && s.root.file != nil {
		result = errors.Join(result, s.root.file.Close())
	}
	if s.parent != nil && s.parent.file != nil {
		result = errors.Join(result, s.parent.file.Close())
	}
	return result
}
