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
	TenantID           string
	OutboxID           string
	LeaseOwner         string
	WorkspaceID        string
	OperationID        string
	AttemptID          string
	SlotKey            string
	SlotGeneration     int64
	PreviousGeneration int64
	FencingToken       int64
	Action             string
	ProviderRevisionID string
	SandboxID          string
	ProviderGeneration int64
	WorkspaceExpiry    time.Time
	Slot               SlotSpec
}

type ProviderOperationEvidence struct {
	ProviderRevisionID   string
	SandboxID            string
	ProviderOperationID  string
	RequestDigest        string
	State                string
	ErrorCode            string
	Retryable            bool
	OutcomeUnknown       bool
	ObservedAt           time.Time
	HandoffReference     string
	ConnectionGeneration int64
	HandoffExpiresAt     time.Time
}

type ReconcileStore interface {
	LeaseReconcileWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error)
	RecordDispatchEvidence(context.Context, ReconcileWork, ProviderOperationEvidence) error
	RetryReconcileWork(context.Context, ReconcileWork, string, time.Duration, int) error
}

type ProviderProvisioner interface {
	ProvisionPrimarySlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error)
}

type BrowserReconcileStore interface {
	LeaseBrowserSlotWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error)
	RecordDispatchEvidence(context.Context, ReconcileWork, ProviderOperationEvidence) error
	RetryReconcileWork(context.Context, ReconcileWork, string, time.Duration, int) error
}

type BrowserSlotProvisioner interface {
	ProvisionBrowserSlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error)
}

type DesktopReconcileStore interface {
	LeaseDesktopSlotWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error)
	RecordDispatchEvidence(context.Context, ReconcileWork, ProviderOperationEvidence) error
	RetryReconcileWork(context.Context, ReconcileWork, string, time.Duration, int) error
}

type DesktopSlotProvisioner interface {
	ProvisionDesktopSlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error)
}

type BrowserLifecycleStore interface {
	LeaseBrowserLifecycleWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error)
	RecordDispatchEvidence(context.Context, ReconcileWork, ProviderOperationEvidence) error
	RetryReconcileWork(context.Context, ReconcileWork, string, time.Duration, int) error
}

type BrowserLifecycleController interface {
	ControlBrowserSlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error)
}

type DesktopLifecycleStore interface {
	LeaseDesktopLifecycleWork(context.Context, string, time.Duration, int) ([]ReconcileWork, error)
	RecordDispatchEvidence(context.Context, ReconcileWork, ProviderOperationEvidence) error
	RetryReconcileWork(context.Context, ReconcileWork, string, time.Duration, int) error
}

type DesktopLifecycleController interface {
	ControlDesktopSlot(context.Context, ReconcileWork) (ProviderOperationEvidence, error)
}

type ProviderObservationWork struct {
	TenantID            string
	WorkspaceID         string
	OperationID         string
	AttemptID           string
	SlotKey             string
	SlotGeneration      int64
	FencingToken        int64
	ProviderAction      string
	RuntimeProfileID    string
	SandboxID           string
	ProviderOperationID string
	ProviderRevisionID  string
	ProviderGeneration  int64
	SessionID           string
	OperationType       string
	LeaseOwner          string
	SessionKind         string
	ProtocolProfile     string
	SessionExpiresAt    time.Time
	SessionFinalState   string
}

type BrowserLifecycleDispatcher struct {
	store       BrowserLifecycleStore
	provider    BrowserLifecycleController
	workerID    string
	lease       time.Duration
	retryBase   time.Duration
	maxAttempts int
	batchSize   int
}

func NewBrowserLifecycleDispatcher(store BrowserLifecycleStore, provider BrowserLifecycleController, workerID string, lease, retryBase time.Duration, maxAttempts, batchSize int) (*BrowserLifecycleDispatcher, error) {
	if nilInterface(store) || nilInterface(provider) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute ||
		retryBase < time.Millisecond || retryBase > time.Minute || maxAttempts < 1 || maxAttempts > 100 || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &BrowserLifecycleDispatcher{store: store, provider: provider, workerID: workerID, lease: lease, retryBase: retryBase, maxAttempts: maxAttempts, batchSize: batchSize}, nil
}

func (d *BrowserLifecycleDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := d.store.LeaseBrowserLifecycleWork(ctx, d.workerID, d.lease, d.batchSize)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, item := range work {
		evidence, dispatchErr := d.provider.ControlBrowserSlot(ctx, item)
		if dispatchErr == nil || errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) || (errors.Is(dispatchErr, ErrDispatchRejected) && !evidence.Retryable) {
			if errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) {
				evidence.OutcomeUnknown = true
				evidence.State = "outcome_unknown"
			}
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

type ProviderObserver interface {
	ObserveOperation(context.Context, ProviderObservationWork) (ProviderOperationEvidence, error)
}

type ObservationStore interface {
	LeaseProviderObservations(context.Context, string, time.Duration, int) ([]ProviderObservationWork, error)
	RecordProviderObservation(context.Context, ProviderObservationWork, ProviderOperationEvidence, string) error
	RetryProviderObservation(context.Context, ProviderObservationWork, time.Duration) error
}

type DesktopObservationStore interface {
	LeaseDesktopProviderObservations(context.Context, string, time.Duration, int) ([]ProviderObservationWork, error)
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

type DesktopReconciler struct {
	store     DesktopObservationStore
	provider  ProviderObserver
	ids       IDGenerator
	workerID  string
	lease     time.Duration
	retry     time.Duration
	batchSize int
}

func NewDesktopReconciler(store DesktopObservationStore, provider ProviderObserver, ids IDGenerator, workerID string, lease, retry time.Duration, batchSize int) (*DesktopReconciler, error) {
	if nilInterface(store) || nilInterface(provider) || nilInterface(ids) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute ||
		retry < time.Millisecond || retry > time.Minute || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &DesktopReconciler{store: store, provider: provider, ids: ids, workerID: workerID, lease: lease, retry: retry, batchSize: batchSize}, nil
}

func (r *DesktopReconciler) ReconcileOnce(ctx context.Context) (int, error) {
	if r == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := r.store.LeaseDesktopProviderObservations(ctx, r.workerID, r.lease, r.batchSize)
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

type BrowserDispatcher struct {
	store       BrowserReconcileStore
	provider    BrowserSlotProvisioner
	workerID    string
	lease       time.Duration
	retryBase   time.Duration
	maxAttempts int
	batchSize   int
}

type DesktopDispatcher struct {
	store       DesktopReconcileStore
	provider    DesktopSlotProvisioner
	workerID    string
	lease       time.Duration
	retryBase   time.Duration
	maxAttempts int
	batchSize   int
}

func NewDesktopDispatcher(store DesktopReconcileStore, provider DesktopSlotProvisioner, workerID string, lease, retryBase time.Duration, maxAttempts, batchSize int) (*DesktopDispatcher, error) {
	if nilInterface(store) || nilInterface(provider) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute ||
		retryBase < time.Millisecond || retryBase > time.Minute || maxAttempts < 1 || maxAttempts > 100 || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &DesktopDispatcher{store: store, provider: provider, workerID: workerID, lease: lease, retryBase: retryBase, maxAttempts: maxAttempts, batchSize: batchSize}, nil
}

func (d *DesktopDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := d.store.LeaseDesktopSlotWork(ctx, d.workerID, d.lease, d.batchSize)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, item := range work {
		evidence, dispatchErr := d.provider.ProvisionDesktopSlot(ctx, item)
		if dispatchErr == nil || errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) || (errors.Is(dispatchErr, ErrDispatchRejected) && !evidence.Retryable) {
			if errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) {
				evidence.OutcomeUnknown = true
				evidence.State = "outcome_unknown"
			}
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

type DesktopLifecycleDispatcher struct {
	store       DesktopLifecycleStore
	provider    DesktopLifecycleController
	workerID    string
	lease       time.Duration
	retryBase   time.Duration
	maxAttempts int
	batchSize   int
}

func NewDesktopLifecycleDispatcher(store DesktopLifecycleStore, provider DesktopLifecycleController, workerID string, lease, retryBase time.Duration, maxAttempts, batchSize int) (*DesktopLifecycleDispatcher, error) {
	if nilInterface(store) || nilInterface(provider) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute ||
		retryBase < time.Millisecond || retryBase > time.Minute || maxAttempts < 1 || maxAttempts > 100 || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &DesktopLifecycleDispatcher{store: store, provider: provider, workerID: workerID, lease: lease, retryBase: retryBase, maxAttempts: maxAttempts, batchSize: batchSize}, nil
}

func (d *DesktopLifecycleDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := d.store.LeaseDesktopLifecycleWork(ctx, d.workerID, d.lease, d.batchSize)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, item := range work {
		evidence, dispatchErr := d.provider.ControlDesktopSlot(ctx, item)
		if dispatchErr == nil || errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) || (errors.Is(dispatchErr, ErrDispatchRejected) && !evidence.Retryable) {
			if errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) {
				evidence.OutcomeUnknown = true
				evidence.State = "outcome_unknown"
			}
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

func NewBrowserDispatcher(store BrowserReconcileStore, provider BrowserSlotProvisioner, workerID string, lease, retryBase time.Duration, maxAttempts, batchSize int) (*BrowserDispatcher, error) {
	if nilInterface(store) || nilInterface(provider) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute ||
		retryBase < time.Millisecond || retryBase > time.Minute || maxAttempts < 1 || maxAttempts > 100 || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &BrowserDispatcher{store: store, provider: provider, workerID: workerID, lease: lease, retryBase: retryBase, maxAttempts: maxAttempts, batchSize: batchSize}, nil
}

func (d *BrowserDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := d.store.LeaseBrowserSlotWork(ctx, d.workerID, d.lease, d.batchSize)
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, item := range work {
		evidence, dispatchErr := d.provider.ProvisionBrowserSlot(ctx, item)
		if dispatchErr == nil || errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) || (errors.Is(dispatchErr, ErrDispatchRejected) && !evidence.Retryable) {
			if errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) {
				evidence.OutcomeUnknown = true
				evidence.State = "outcome_unknown"
			}
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
