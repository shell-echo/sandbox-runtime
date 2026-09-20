package providerpostgres

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

type UsageClock interface{ Now() time.Time }

type usageSnapshot struct {
	Version  int              `json:"version"`
	Evidence []usage.Evidence `json:"evidence"`
}

type usageState struct {
	values         map[string]usage.Evidence
	operationIndex map[string]string
}

func newUsageState() usageState {
	return usageState{values: make(map[string]usage.Evidence), operationIndex: make(map[string]string)}
}
func importUsageState(state *usageState, document json.RawMessage) error {
	var snapshot usageSnapshot
	if err := decodePersisted(&snapshot, document); err != nil || snapshot.Version != 1 || snapshot.Evidence == nil {
		return ErrCorrupt
	}
	for _, evidence := range snapshot.Evidence {
		if err := evidence.Validate(evidence.ObservedAt); err != nil {
			return ErrCorrupt
		}
		if _, exists := state.values[evidence.EvidenceID]; exists {
			return ErrCorrupt
		}
		if _, exists := state.operationIndex[evidence.OperationID]; exists {
			return ErrCorrupt
		}
		state.values[evidence.EvidenceID] = evidence.Clone()
		state.operationIndex[evidence.OperationID] = evidence.EvidenceID
	}
	return nil
}
func exportUsageState(state usageState) any {
	snapshot := usageSnapshot{Version: 1, Evidence: make([]usage.Evidence, 0, len(state.values))}
	for _, evidence := range state.values {
		snapshot.Evidence = append(snapshot.Evidence, evidence.Clone())
	}
	sort.Slice(snapshot.Evidence, func(i, j int) bool { return snapshot.Evidence[i].OperationID < snapshot.Evidence[j].OperationID })
	return snapshot
}

type UsageRepository struct {
	store *Store
	clock UsageClock
}

func NewUsageRepository(store *Store, clock UsageClock) (*UsageRepository, error) {
	if store == nil || clock == nil || clock.Now().IsZero() {
		return nil, ErrUnavailable
	}
	return &UsageRepository{store: store, clock: clock}, nil
}
func (r *UsageRepository) Put(ctx context.Context, evidence usage.Evidence) error {
	return mutateState(ctx, r.store, "usage", newUsageState, importUsageState, exportUsageState, func(state *usageState) error {
		if err := evidence.Validate(r.clock.Now().UTC()); err != nil {
			return err
		}
		if previous, exists := state.values[evidence.EvidenceID]; exists {
			if reflect.DeepEqual(previous, evidence) {
				return nil
			}
			return usage.ErrEvidenceUnavailable
		}
		if evidenceID, exists := state.operationIndex[evidence.OperationID]; exists {
			if previous, ok := state.values[evidenceID]; ok && reflect.DeepEqual(previous, evidence) {
				return nil
			}
			return usage.ErrEvidenceUnavailable
		}
		state.values[evidence.EvidenceID] = evidence.Clone()
		state.operationIndex[evidence.OperationID] = evidence.EvidenceID
		return nil
	})
}
func (r *UsageRepository) GetEvidence(ctx context.Context, operationID string, now time.Time) (usage.Evidence, error) {
	state, err := readState(ctx, r.store, "usage", newUsageState, importUsageState)
	if err != nil {
		return usage.Evidence{}, err
	}
	evidenceID, exists := state.operationIndex[operationID]
	if !exists {
		return usage.Evidence{}, usage.ErrEvidenceNotFound
	}
	evidence, exists := state.values[evidenceID]
	if !exists || evidence.OperationID != operationID {
		return usage.Evidence{}, ErrCorrupt
	}
	if now.IsZero() || !now.UTC().Before(evidence.RetainedUntil) {
		return usage.Evidence{}, usage.ErrEvidenceExpired
	}
	return evidence.Clone(), nil
}
func (r *UsageRepository) Close() error { return nil }

var _ usage.Store = (*UsageRepository)(nil)
