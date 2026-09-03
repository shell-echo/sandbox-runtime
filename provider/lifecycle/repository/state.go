package repository

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

const maxEventPageSize = 1000

// State is the adapter-independent mutable snapshot. Callers must hold their
// adapter lock before invoking its methods.
type State struct {
	Sandboxes   map[string]lifecycle.Sandbox
	Operations  map[string]lifecycle.Operation
	Leases      map[string]lifecycle.Lease
	Events      map[string][]lifecycle.Event
	Idempotency map[string]IdempotencyRecord
	Fencing     map[string]uint64
}

type IdempotencyRecord struct {
	Scope         string
	Key           string
	RequestDigest string
	Operation     lifecycle.Operation
}

func NewState() State {
	return State{
		Sandboxes:   make(map[string]lifecycle.Sandbox),
		Operations:  make(map[string]lifecycle.Operation),
		Leases:      make(map[string]lifecycle.Lease),
		Events:      make(map[string][]lifecycle.Event),
		Idempotency: make(map[string]IdempotencyRecord),
		Fencing:     make(map[string]uint64),
	}
}

func (s *State) ensureMaps() {
	if s.Sandboxes == nil {
		s.Sandboxes = make(map[string]lifecycle.Sandbox)
	}
	if s.Operations == nil {
		s.Operations = make(map[string]lifecycle.Operation)
	}
	if s.Leases == nil {
		s.Leases = make(map[string]lifecycle.Lease)
	}
	if s.Events == nil {
		s.Events = make(map[string][]lifecycle.Event)
	}
	if s.Idempotency == nil {
		s.Idempotency = make(map[string]IdempotencyRecord)
	}
	if s.Fencing == nil {
		s.Fencing = make(map[string]uint64)
	}
}

func (s *State) ReserveCreate(idempotencyKey, requestDigest string, sandbox lifecycle.Sandbox, operation lifecycle.Operation) (CreateResult, error) {
	s.ensureMaps()
	if err := sandbox.Validate(); err != nil {
		return CreateResult{}, fmt.Errorf("validate sandbox: %w", err)
	}
	if err := operation.Validate(); err != nil {
		return CreateResult{}, fmt.Errorf("validate operation: %w", err)
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return CreateResult{}, ErrConflict
	}
	if err := lifecycle.ValidateDigest(requestDigest); err != nil {
		return CreateResult{}, fmt.Errorf("validate request digest: %w", err)
	}
	if operation.Type != lifecycle.OperationCreate || operation.State != lifecycle.OperationAccepted || operation.SandboxID != sandbox.ID {
		return CreateResult{}, ErrConflict
	}
	scope := fencingScope(sandbox.ProviderRevisionID, sandbox.ID)
	idempotencyScope := idempotencyScope(sandbox.ProviderRevisionID, idempotencyKey)
	if existing, ok := s.Idempotency[idempotencyScope]; ok {
		if existing.RequestDigest != requestDigest || existing.Operation.ID != operation.ID {
			return CreateResult{}, ErrIdempotencyConflict
		}
		return CreateResult{Operation: cloneOperation(existing.Operation), Replayed: true}, nil
	}
	if _, exists := s.Sandboxes[sandbox.ID]; exists {
		return CreateResult{}, fmt.Errorf("%w: sandbox %s", ErrAlreadyExists, sandbox.ID)
	}
	if _, exists := s.Operations[operation.ID]; exists {
		return CreateResult{}, fmt.Errorf("%w: operation %s", ErrAlreadyExists, operation.ID)
	}
	if current := s.Fencing[scope]; operation.FencingToken <= current {
		return CreateResult{}, fmt.Errorf("%w: incoming %d, current %d", lifecycle.ErrStaleFencingToken, operation.FencingToken, current)
	}
	s.Sandboxes[sandbox.ID] = sandbox
	s.Operations[operation.ID] = cloneOperation(operation)
	s.Leases[sandbox.ID] = lifecycle.Lease{SandboxID: sandbox.ID, ExpiresAt: sandbox.LeaseExpiresAt, Generation: sandbox.Generation, FencingToken: operation.FencingToken}
	s.Fencing[scope] = operation.FencingToken
	s.Idempotency[idempotencyScope] = IdempotencyRecord{Scope: idempotencyScope, Key: idempotencyKey, RequestDigest: requestDigest, Operation: cloneOperation(operation)}
	return CreateResult{Operation: cloneOperation(operation)}, nil
}

func (s *State) GetSandbox(id string) (lifecycle.Sandbox, error) {
	s.ensureMaps()
	sandbox, ok := s.Sandboxes[id]
	if !ok {
		return lifecycle.Sandbox{}, fmt.Errorf("%w: sandbox %s", ErrNotFound, id)
	}
	return sandbox, nil
}

func (s *State) ListSandboxes() []lifecycle.Sandbox {
	s.ensureMaps()
	result := make([]lifecycle.Sandbox, 0, len(s.Sandboxes))
	for _, sandbox := range s.Sandboxes {
		result = append(result, sandbox)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (s *State) UpdateSandbox(sandbox lifecycle.Sandbox, expectedGeneration, fencingToken uint64) error {
	s.ensureMaps()
	if err := sandbox.Validate(); err != nil {
		return fmt.Errorf("validate sandbox: %w", err)
	}
	current, ok := s.Sandboxes[sandbox.ID]
	if !ok {
		return fmt.Errorf("%w: sandbox %s", ErrNotFound, sandbox.ID)
	}
	if current.Generation != expectedGeneration || sandbox.Generation < current.Generation || sandbox.Generation > current.Generation+1 {
		return fmt.Errorf("%w: expected %d, current %d", lifecycle.ErrGenerationConflict, expectedGeneration, current.Generation)
	}
	if err := checkCurrentFencing(s.Fencing, current.ProviderRevisionID, current.ID, fencingToken); err != nil {
		return err
	}
	if sandbox.LeaseExpiresAt != current.LeaseExpiresAt {
		return ErrConflict
	}
	if sandbox.Network != current.Network {
		return ErrConflict
	}
	if sandbox.Generation != current.Generation {
		lease, ok := s.Leases[sandbox.ID]
		if !ok {
			return fmt.Errorf("%w: lease %s", ErrNotFound, sandbox.ID)
		}
		lease.Generation = sandbox.Generation
		s.Leases[sandbox.ID] = lease
	}
	s.Sandboxes[sandbox.ID] = sandbox
	return nil
}

func (s *State) GetOperation(id string) (lifecycle.Operation, error) {
	s.ensureMaps()
	operation, ok := s.Operations[id]
	if !ok {
		return lifecycle.Operation{}, fmt.Errorf("%w: operation %s", ErrNotFound, id)
	}
	return cloneOperation(operation), nil
}

func (s *State) ListOperations() []lifecycle.Operation {
	s.ensureMaps()
	result := make([]lifecycle.Operation, 0, len(s.Operations))
	for _, operation := range s.Operations {
		result = append(result, cloneOperation(operation))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (s *State) UpdateOperation(operation lifecycle.Operation) error {
	s.ensureMaps()
	if err := operation.Validate(); err != nil {
		return fmt.Errorf("validate operation: %w", err)
	}
	current, ok := s.Operations[operation.ID]
	if !ok {
		return fmt.Errorf("%w: operation %s", ErrNotFound, operation.ID)
	}
	if current.SandboxID != operation.SandboxID || current.AttemptID != operation.AttemptID {
		return ErrConflict
	}
	if err := checkCurrentFencing(s.Fencing, operationProviderRevision(s, operation.SandboxID), operation.SandboxID, operation.FencingToken); err != nil {
		return err
	}
	s.Operations[operation.ID] = cloneOperation(operation)
	if record, ok := s.IdempotencyForOperation(operation.ID); ok {
		record.Operation = cloneOperation(operation)
		s.Idempotency[record.Scope] = record
	}
	return nil
}

func (s *State) GetLease(id string) (lifecycle.Lease, error) {
	s.ensureMaps()
	lease, ok := s.Leases[id]
	if !ok {
		return lifecycle.Lease{}, fmt.Errorf("%w: lease %s", ErrNotFound, id)
	}
	return lease, nil
}

func (s *State) ReplaceLease(lease lifecycle.Lease, fencingToken uint64) error {
	s.ensureMaps()
	if err := lease.Validate(); err != nil {
		return err
	}
	current, ok := s.Leases[lease.SandboxID]
	if !ok {
		return fmt.Errorf("%w: lease %s", ErrNotFound, lease.SandboxID)
	}
	if lease.Generation != current.Generation {
		return fmt.Errorf("%w: lease generation %d, current %d", lifecycle.ErrGenerationConflict, lease.Generation, current.Generation)
	}
	sandbox, ok := s.Sandboxes[lease.SandboxID]
	if !ok {
		return fmt.Errorf("%w: sandbox %s", ErrNotFound, lease.SandboxID)
	}
	if err := checkCurrentFencing(s.Fencing, sandbox.ProviderRevisionID, sandbox.ID, fencingToken); err != nil {
		return err
	}
	updatedSandbox := sandbox
	updatedSandbox.LeaseExpiresAt = lease.ExpiresAt
	s.Sandboxes[lease.SandboxID] = updatedSandbox
	s.Leases[lease.SandboxID] = lease
	return nil
}

func (s *State) AppendEvent(event lifecycle.Event) (lifecycle.Event, error) {
	s.ensureMaps()
	if err := event.Validate(); err != nil {
		return lifecycle.Event{}, err
	}
	sandbox, ok := s.Sandboxes[event.SandboxID]
	if !ok {
		return lifecycle.Event{}, fmt.Errorf("%w: sandbox %s", ErrNotFound, event.SandboxID)
	}
	if event.Generation > sandbox.Generation {
		return lifecycle.Event{}, fmt.Errorf("%w: event generation %d, current %d", lifecycle.ErrGenerationConflict, event.Generation, sandbox.Generation)
	}
	if err := checkCurrentFencing(s.Fencing, sandbox.ProviderRevisionID, sandbox.ID, event.FencingToken); err != nil {
		return lifecycle.Event{}, err
	}
	for _, existing := range s.Events[event.SandboxID] {
		if existing.ID != event.ID {
			continue
		}
		if existing.OperationID != event.OperationID || existing.Generation != event.Generation || existing.FencingToken != event.FencingToken || existing.Kind != event.Kind || existing.DataDigest != event.DataDigest {
			return lifecycle.Event{}, ErrConflict
		}
		return existing, nil
	}
	event.Sequence = uint64(len(s.Events[event.SandboxID])) + 1
	s.Events[event.SandboxID] = append(s.Events[event.SandboxID], event)
	return event, nil
}

func (s *State) ListEvents(sandboxID string, after uint64, limit int) ([]lifecycle.Event, error) {
	s.ensureMaps()
	if limit <= 0 || limit > maxEventPageSize {
		return nil, ErrInvalidCursor
	}
	if _, ok := s.Sandboxes[sandboxID]; !ok {
		return nil, fmt.Errorf("%w: sandbox %s", ErrNotFound, sandboxID)
	}
	all := s.Events[sandboxID]
	if after > uint64(len(all)) {
		return nil, ErrInvalidCursor
	}
	start := int(after)
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	result := append([]lifecycle.Event(nil), all[start:end]...)
	return result, nil
}

func (s *State) IdempotencyForOperation(operationID string) (IdempotencyRecord, bool) {
	for _, record := range s.Idempotency {
		if record.Operation.ID == operationID {
			return record, true
		}
	}
	return IdempotencyRecord{}, false
}

func checkCurrentFencing(fencing map[string]uint64, revisionID, sandboxID string, token uint64) error {
	if token == 0 {
		return lifecycle.ErrStaleFencingToken
	}
	current := fencing[fencingScope(revisionID, sandboxID)]
	if current != token {
		return fmt.Errorf("%w: incoming %d, current %d", lifecycle.ErrStaleFencingToken, token, current)
	}
	return nil
}

func operationProviderRevision(s *State, sandboxID string) string {
	return s.Sandboxes[sandboxID].ProviderRevisionID
}

func fencingScope(revisionID, sandboxID string) string {
	return revisionID + "\x00" + sandboxID
}

func idempotencyScope(revisionID, key string) string {
	return revisionID + "\x00" + key
}

func cloneOperation(operation lifecycle.Operation) lifecycle.Operation {
	if operation.Failure != nil {
		failure := *operation.Failure
		operation.Failure = &failure
	}
	return operation
}

type PersistedState struct {
	Version     int                   `json:"version"`
	Sandboxes   []lifecycle.Sandbox   `json:"sandboxes"`
	Operations  []lifecycle.Operation `json:"operations"`
	Leases      []lifecycle.Lease     `json:"leases"`
	Events      []lifecycle.Event     `json:"events"`
	Idempotency []IdempotencyRecord   `json:"idempotency"`
	Fencing     []FencingRecord       `json:"fencing"`
}

type FencingRecord struct {
	Scope string `json:"scope"`
	Token uint64 `json:"token"`
}

func (s State) Export() PersistedState {
	result := PersistedState{Version: 1}
	for _, sandbox := range s.Sandboxes {
		result.Sandboxes = append(result.Sandboxes, sandbox)
	}
	for _, operation := range s.Operations {
		result.Operations = append(result.Operations, cloneOperation(operation))
	}
	for _, lease := range s.Leases {
		result.Leases = append(result.Leases, lease)
	}
	for _, events := range s.Events {
		result.Events = append(result.Events, events...)
	}
	for _, record := range s.Idempotency {
		record.Operation = cloneOperation(record.Operation)
		result.Idempotency = append(result.Idempotency, record)
	}
	for scope, token := range s.Fencing {
		result.Fencing = append(result.Fencing, FencingRecord{Scope: scope, Token: token})
	}
	sort.Slice(result.Sandboxes, func(i, j int) bool { return result.Sandboxes[i].ID < result.Sandboxes[j].ID })
	sort.Slice(result.Operations, func(i, j int) bool { return result.Operations[i].ID < result.Operations[j].ID })
	sort.Slice(result.Leases, func(i, j int) bool { return result.Leases[i].SandboxID < result.Leases[j].SandboxID })
	sort.Slice(result.Events, func(i, j int) bool {
		if result.Events[i].SandboxID != result.Events[j].SandboxID {
			return result.Events[i].SandboxID < result.Events[j].SandboxID
		}
		return result.Events[i].Sequence < result.Events[j].Sequence
	})
	sort.Slice(result.Idempotency, func(i, j int) bool { return result.Idempotency[i].Scope < result.Idempotency[j].Scope })
	sort.Slice(result.Fencing, func(i, j int) bool { return result.Fencing[i].Scope < result.Fencing[j].Scope })
	return result
}

func (s *State) Import(snapshot PersistedState) error {
	if snapshot.Version != 1 {
		return fmt.Errorf("%w: unsupported state version %d", ErrCorrupt, snapshot.Version)
	}
	loaded := NewState()
	for _, sandbox := range snapshot.Sandboxes {
		if err := sandbox.Validate(); err != nil {
			return fmt.Errorf("%w: sandbox: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Sandboxes[sandbox.ID]; exists {
			return fmt.Errorf("%w: duplicate sandbox %q", ErrCorrupt, sandbox.ID)
		}
		loaded.Sandboxes[sandbox.ID] = sandbox
	}
	for _, operation := range snapshot.Operations {
		if err := operation.Validate(); err != nil {
			return fmt.Errorf("%w: operation: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Operations[operation.ID]; exists {
			return fmt.Errorf("%w: duplicate operation %q", ErrCorrupt, operation.ID)
		}
		if _, exists := loaded.Sandboxes[operation.SandboxID]; !exists {
			return fmt.Errorf("%w: operation %q references missing sandbox", ErrCorrupt, operation.ID)
		}
		loaded.Operations[operation.ID] = cloneOperation(operation)
	}
	for _, lease := range snapshot.Leases {
		if err := lease.Validate(); err != nil {
			return fmt.Errorf("%w: lease: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Sandboxes[lease.SandboxID]; !exists {
			return fmt.Errorf("%w: lease references missing sandbox %q", ErrCorrupt, lease.SandboxID)
		}
		if _, exists := loaded.Leases[lease.SandboxID]; exists {
			return fmt.Errorf("%w: duplicate lease %q", ErrCorrupt, lease.SandboxID)
		}
		loaded.Leases[lease.SandboxID] = lease
	}
	for _, event := range snapshot.Events {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("%w: event: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Sandboxes[event.SandboxID]; !exists {
			return fmt.Errorf("%w: event references missing sandbox %q", ErrCorrupt, event.SandboxID)
		}
		if _, exists := loaded.Operations[event.OperationID]; !exists {
			return fmt.Errorf("%w: event references missing operation %q", ErrCorrupt, event.OperationID)
		}
		list := loaded.Events[event.SandboxID]
		if event.Sequence != uint64(len(list))+1 {
			return fmt.Errorf("%w: event sequence for sandbox %q", ErrCorrupt, event.SandboxID)
		}
		loaded.Events[event.SandboxID] = append(list, event)
	}
	for _, record := range snapshot.Idempotency {
		if record.Scope == "" || record.Key == "" || record.RequestDigest == "" {
			return fmt.Errorf("%w: invalid idempotency record", ErrCorrupt)
		}
		if err := record.Operation.Validate(); err != nil {
			return fmt.Errorf("%w: idempotency operation: %v", ErrCorrupt, err)
		}
		if _, exists := loaded.Operations[record.Operation.ID]; !exists {
			return fmt.Errorf("%w: idempotency references missing operation %q", ErrCorrupt, record.Operation.ID)
		}
		if _, exists := loaded.Idempotency[record.Scope]; exists {
			return fmt.Errorf("%w: duplicate idempotency scope %q", ErrCorrupt, record.Scope)
		}
		loaded.Idempotency[record.Scope] = record
	}
	for _, record := range snapshot.Fencing {
		if record.Scope == "" || record.Token == 0 {
			return fmt.Errorf("%w: invalid fencing record", ErrCorrupt)
		}
		if _, exists := loaded.Fencing[record.Scope]; exists {
			return fmt.Errorf("%w: duplicate fencing scope %q", ErrCorrupt, record.Scope)
		}
		loaded.Fencing[record.Scope] = record.Token
	}
	for sandboxID, sandbox := range loaded.Sandboxes {
		lease, ok := loaded.Leases[sandboxID]
		if !ok {
			return fmt.Errorf("%w: sandbox %q has no lease", ErrCorrupt, sandboxID)
		}
		if !lease.ExpiresAt.Equal(sandbox.LeaseExpiresAt) || lease.Generation != sandbox.Generation {
			return fmt.Errorf("%w: lease does not match sandbox %q", ErrCorrupt, sandboxID)
		}
		token, ok := loaded.Fencing[fencingScope(sandbox.ProviderRevisionID, sandbox.ID)]
		if !ok || token < lease.FencingToken {
			return fmt.Errorf("%w: sandbox %q has no valid fencing high-water mark", ErrCorrupt, sandboxID)
		}
	}
	*s = loaded
	return nil
}
