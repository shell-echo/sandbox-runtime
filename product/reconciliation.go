package product

import (
	"context"
	"errors"
	"time"
)

var (
	ErrDispatchRejected       = errors.New("provider dispatch rejected")
	ErrDispatchOutcomeUnknown = errors.New("provider dispatch outcome is unknown")
	ErrLeaseLost              = errors.New("worker lease lost")
)

type ReconcileWork struct {
	TenantID        string
	OutboxID        string
	LeaseOwner      string
	WorkspaceID     string
	OperationID     string
	AttemptID       string
	SlotKey         string
	SlotGeneration  int64
	WorkspaceExpiry time.Time
	Slot            SlotSpec
}

type ProviderOperationEvidence struct {
	ProviderRevisionID  string
	SandboxID           string
	ProviderOperationID string
	RequestDigest       string
	State               string
	ErrorCode           string
	Retryable           bool
	OutcomeUnknown      bool
	ObservedAt          time.Time
}

type ReconcileStore interface {
	LeaseReconcileWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error)
	RecordDispatchEvidence(context.Context, ReconcileWork, ProviderOperationEvidence) error
	RetryReconcileWork(context.Context, ReconcileWork, string, time.Duration, int) error
}

type ProviderProvisioner interface {
	ProvisionPrimarySlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error)
}

type ProviderObservationWork struct {
	TenantID            string
	WorkspaceID         string
	OperationID         string
	AttemptID           string
	SlotKey             string
	SlotGeneration      int64
	RuntimeProfileID    string
	SandboxID           string
	ProviderOperationID string
	ProviderRevisionID  string
	SessionID           string
	OperationType       string
	LeaseOwner          string
}

type ProviderObserver interface {
	ObserveOperation(context.Context, ProviderObservationWork) (ProviderOperationEvidence, error)
}

type ObservationStore interface {
	LeaseProviderObservations(context.Context, string, time.Duration, int) ([]ProviderObservationWork, error)
	RecordProviderObservation(context.Context, ProviderObservationWork, ProviderOperationEvidence, string) error
	RetryProviderObservation(context.Context, ProviderObservationWork, time.Duration) error
}

type Reconciler struct {
	store     ObservationStore
	provider  ProviderObserver
	ids       IDGenerator
	workerID  string
	lease     time.Duration
	retry     time.Duration
	batchSize int
}

func NewReconciler(store ObservationStore, provider ProviderObserver, ids IDGenerator, workerID string, lease, retry time.Duration, batchSize int) (*Reconciler, error) {
	if nilInterface(store) || nilInterface(provider) || nilInterface(ids) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute ||
		retry < time.Millisecond || retry > time.Minute || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &Reconciler{store: store, provider: provider, ids: ids, workerID: workerID, lease: lease, retry: retry, batchSize: batchSize}, nil
}

func (r *Reconciler) ReconcileOnce(ctx context.Context) (int, error) {
	if r == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := r.store.LeaseProviderObservations(ctx, r.workerID, r.lease, r.batchSize)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, item := range work {
		evidence, observeErr := r.provider.ObserveOperation(ctx, item)
		if observeErr != nil {
			if err := r.store.RetryProviderObservation(ctx, item, r.retry); err != nil {
				return completed, err
			}
			continue
		}
		eventID, err := r.ids.NewID("evt")
		if err != nil {
			return completed, ErrStoreUnavailable
		}
		if err := r.store.RecordProviderObservation(ctx, item, evidence, eventID); err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}

type Dispatcher struct {
	store       ReconcileStore
	provider    ProviderProvisioner
	workerID    string
	lease       time.Duration
	retryBase   time.Duration
	maxAttempts int
	batchSize   int
}

func NewDispatcher(store ReconcileStore, provider ProviderProvisioner, workerID string, lease, retryBase time.Duration, maxAttempts, batchSize int) (*Dispatcher, error) {
	if nilInterface(store) || nilInterface(provider) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute ||
		retryBase < time.Millisecond || retryBase > time.Minute || maxAttempts < 1 || maxAttempts > 100 || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &Dispatcher{store: store, provider: provider, workerID: workerID, lease: lease, retryBase: retryBase, maxAttempts: maxAttempts, batchSize: batchSize}, nil
}

func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || d.store == nil || d.provider == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := d.store.LeaseReconcileWork(ctx, d.workerID, d.lease, d.batchSize)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, item := range work {
		evidence, dispatchErr := d.provider.ProvisionPrimarySlot(ctx, item)
		if dispatchErr == nil || errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) {
			if dispatchErr != nil {
				evidence.OutcomeUnknown = true
				evidence.State = "outcome_unknown"
			}
			if err := d.store.RecordDispatchEvidence(ctx, item, evidence); err != nil {
				return completed, err
			}
			completed++
			continue
		}
		if errors.Is(dispatchErr, ErrDispatchRejected) && !evidence.Retryable {
			if err := d.store.RecordDispatchEvidence(ctx, item, evidence); err != nil {
				return completed, err
			}
			completed++
			continue
		}
		if err := d.store.RetryReconcileWork(ctx, item, safeDispatchCode(evidence.ErrorCode), d.retryBase, d.maxAttempts); err != nil {
			return completed, err
		}
	}
	return completed, nil
}

func safeDispatchCode(value string) string {
	if value == "" || !validIdentifier(value) {
		return "provider_unavailable"
	}
	return value
}
