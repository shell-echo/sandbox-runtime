package product

import (
	"context"
	"errors"
	"testing"
	"time"
)

type dispatchStore struct {
	work     []ReconcileWork
	recorded []ProviderOperationEvidence
	retries  int
	err      error
}

func (s *dispatchStore) LeaseReconcileWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error) {
	return s.work, s.err
}
func (s *dispatchStore) RecordDispatchEvidence(_ context.Context, _ ReconcileWork, e ProviderOperationEvidence) error {
	s.recorded = append(s.recorded, e)
	return s.err
}
func (s *dispatchStore) RetryReconcileWork(context.Context, ReconcileWork, string, time.Duration, int) error {
	s.retries++
	return s.err
}

type dispatchProvider struct {
	evidence ProviderOperationEvidence
	err      error
}

type browserDispatchStore struct{ dispatchStore }

func (s *browserDispatchStore) LeaseBrowserSlotWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error) {
	return s.work, s.err
}

type browserDispatchProvider struct {
	evidence ProviderOperationEvidence
	err      error
}

func (p browserDispatchProvider) ProvisionBrowserSlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error) {
	return p.evidence, p.err
}

func (p dispatchProvider) ProvisionPrimarySlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error) {
	return p.evidence, p.err
}

func TestDispatcherSeparatesKnownRetryableAndAmbiguousOutcomes(t *testing.T) {
	work := []ReconcileWork{{OutboxID: "out-1"}}
	tests := []struct {
		name              string
		evidence          ProviderOperationEvidence
		err               error
		recorded, retries int
		state             string
	}{
		{name: "accepted", evidence: ProviderOperationEvidence{State: "accepted"}, recorded: 1, state: "accepted"},
		{name: "ambiguous", evidence: ProviderOperationEvidence{}, err: ErrDispatchOutcomeUnknown, recorded: 1, state: "outcome_unknown"},
		{name: "retryable", evidence: ProviderOperationEvidence{Retryable: true}, err: ErrDispatchRejected, retries: 1},
		{name: "known failure", evidence: ProviderOperationEvidence{State: "failed"}, err: ErrDispatchRejected, recorded: 1, state: "failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &dispatchStore{work: work}
			dispatcher, err := NewDispatcher(store, dispatchProvider{test.evidence, test.err}, "worker-1", 5*time.Second, time.Second, 3, 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := dispatcher.DispatchOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(store.recorded) != test.recorded || store.retries != test.retries {
				t.Fatalf("recorded=%d retries=%d", len(store.recorded), store.retries)
			}
			if test.recorded == 1 && store.recorded[0].State != test.state {
				t.Fatalf("state=%q", store.recorded[0].State)
			}
		})
	}
}

func TestDispatcherRejectsInvalidConfigurationAndPropagatesLeaseFailure(t *testing.T) {
	if _, err := NewDispatcher(nil, dispatchProvider{}, "worker", time.Second, time.Second, 1, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
	store := &dispatchStore{err: ErrStoreUnavailable}
	dispatcher, _ := NewDispatcher(store, dispatchProvider{}, "worker", time.Second, time.Second, 1, 1)
	if _, err := dispatcher.DispatchOnce(context.Background()); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestBrowserDispatcherUsesIsolatedLeaseAndOutcomeRules(t *testing.T) {
	store := &browserDispatchStore{dispatchStore: dispatchStore{work: []ReconcileWork{{OutboxID: "browser-out-1"}}}}
	dispatcher, err := NewBrowserDispatcher(store, browserDispatchProvider{evidence: ProviderOperationEvidence{}, err: ErrDispatchOutcomeUnknown}, "browser-worker-1", time.Second, time.Millisecond, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := dispatcher.DispatchOnce(context.Background()); err != nil || count != 1 || len(store.recorded) != 1 || store.recorded[0].State != "outcome_unknown" {
		t.Fatalf("count=%d store=%#v err=%v", count, store, err)
	}
	if _, err := NewBrowserDispatcher(nil, browserDispatchProvider{}, "browser-worker-1", time.Second, time.Millisecond, 3, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil store err=%v", err)
	}
}

type observationStore struct {
	work              []ProviderObservationWork
	recorded, retried int
	state             string
}

func (s *observationStore) LeaseProviderObservations(context.Context, string, time.Duration, int) ([]ProviderObservationWork, error) {
	return s.work, nil
}
func (s *observationStore) RecordProviderObservation(_ context.Context, _ ProviderObservationWork, evidence ProviderOperationEvidence, eventID string) error {
	s.recorded++
	s.state = evidence.State
	if eventID == "" {
		return ErrInvalid
	}
	return nil
}
func (s *observationStore) RetryProviderObservation(context.Context, ProviderObservationWork, time.Duration) error {
	s.retried++
	return nil
}

type observationProvider struct {
	evidence ProviderOperationEvidence
	err      error
}

func (p observationProvider) ObserveOperation(context.Context, ProviderObservationWork) (ProviderOperationEvidence, error) {
	return p.evidence, p.err
}

func TestReconcilerRecordsEvidenceAndRetriesReadFailures(t *testing.T) {
	work := []ProviderObservationWork{{OperationID: "op-1"}}
	store := &observationStore{work: work}
	reconciler, err := NewReconciler(store, observationProvider{evidence: ProviderOperationEvidence{State: "succeeded"}}, &sequenceIDs{}, "worker-1", time.Second, time.Millisecond, 1)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := reconciler.ReconcileOnce(context.Background()); err != nil || count != 1 || store.recorded != 1 || store.state != "succeeded" {
		t.Fatalf("count=%d store=%#v err=%v", count, store, err)
	}
	store = &observationStore{work: work}
	reconciler, _ = NewReconciler(store, observationProvider{err: ErrStoreUnavailable}, &sequenceIDs{}, "worker-1", time.Second, time.Millisecond, 1)
	if count, err := reconciler.ReconcileOnce(context.Background()); err != nil || count != 0 || store.retried != 1 {
		t.Fatalf("count=%d retries=%d err=%v", count, store.retried, err)
	}
}
