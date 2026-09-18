package product

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"
)

type SessionPolicy interface {
	AuthorizeSession(context.Context, string, string) error
}

type SessionCommand struct {
	TenantID                                                        string
	Actor                                                           ActorRef
	WorkspaceID, SlotKey, SessionID, OperationID, EventID, OutboxID string
	IdempotencyKey                                                  string
	RequestDigest                                                   [32]byte
	Path                                                            string
	ExpectedVersion                                                 int64
	Kind, ProtocolProfile, RecordingPolicy, Reason                  string
	Lifetime                                                        time.Duration
}

type SessionStore interface {
	CreateSession(context.Context, SessionCommand) (Operation, bool, error)
	CloseSession(context.Context, SessionCommand) (Operation, bool, error)
	GetSession(context.Context, string, string) (RuntimeSession, error)
	ListSessions(context.Context, string, string, ActorRef, int) ([]RuntimeSession, error)
}

type SessionControlWork struct {
	TenantID, OutboxID, LeaseOwner, WorkspaceID, SlotKey, SessionID, OperationID, AttemptID string
	SlotGeneration                                                                          int64
	RuntimeProfileID, SandboxID, ProviderRevisionID                                         string
	Kind, ProtocolProfile                                                                   string
	ConnectionGeneration                                                                    int64
	ExpiresAt                                                                               time.Time
	Action, Reason                                                                          string
}
type ProviderSessionController interface {
	ExecuteSessionControl(context.Context, SessionControlWork) (ProviderOperationEvidence, error)
}
type BrowserSessionController interface {
	ExecuteBrowserSessionControl(context.Context, SessionControlWork) (ProviderOperationEvidence, error)
}
type SessionDispatchStore interface {
	LeaseSessionWork(context.Context, string, time.Duration, int) ([]SessionControlWork, error)
	RecordSessionDispatch(context.Context, SessionControlWork, ProviderOperationEvidence) error
	RetrySessionWork(context.Context, SessionControlWork, string, time.Duration, int) error
}
type BrowserSessionDispatchStore interface {
	LeaseBrowserSessionWork(context.Context, string, time.Duration, int) ([]SessionControlWork, error)
	RecordSessionDispatch(context.Context, SessionControlWork, ProviderOperationEvidence) error
	RetrySessionWork(context.Context, SessionControlWork, string, time.Duration, int) error
}
type SessionDispatcher struct {
	store                  SessionDispatchStore
	provider               ProviderSessionController
	workerID               string
	lease, retry           time.Duration
	maxAttempts, batchSize int
}

func NewSessionDispatcher(store SessionDispatchStore, provider ProviderSessionController, workerID string, lease, retry time.Duration, maxAttempts, batchSize int) (*SessionDispatcher, error) {
	if nilInterface(store) || nilInterface(provider) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute || retry < time.Millisecond || retry > time.Minute || maxAttempts < 1 || maxAttempts > 100 || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &SessionDispatcher{store: store, provider: provider, workerID: workerID, lease: lease, retry: retry, maxAttempts: maxAttempts, batchSize: batchSize}, nil
}
func (d *SessionDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := d.store.LeaseSessionWork(ctx, d.workerID, d.lease, d.batchSize)
	if err != nil {
		return 0, err
	}
	complete := 0
	for _, item := range work {
		evidence, dispatchErr := d.provider.ExecuteSessionControl(ctx, item)
		if dispatchErr == nil || errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) || (errors.Is(dispatchErr, ErrDispatchRejected) && !evidence.Retryable) {
			if dispatchErr != nil && errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) {
				evidence.State = "outcome_unknown"
				evidence.OutcomeUnknown = true
			}
			if err := d.store.RecordSessionDispatch(ctx, item, evidence); err != nil {
				return complete, err
			}
			complete++
			continue
		}
		if err := d.store.RetrySessionWork(ctx, item, safeDispatchCode(evidence.ErrorCode), d.retry, d.maxAttempts); err != nil {
			return complete, err
		}
	}
	return complete, nil
}

type BrowserSessionDispatcher struct {
	store                  BrowserSessionDispatchStore
	provider               BrowserSessionController
	workerID               string
	lease, retry           time.Duration
	maxAttempts, batchSize int
}

func NewBrowserSessionDispatcher(store BrowserSessionDispatchStore, provider BrowserSessionController, workerID string, lease, retry time.Duration, maxAttempts, batchSize int) (*BrowserSessionDispatcher, error) {
	if nilInterface(store) || nilInterface(provider) || !validIdentifier(workerID) || lease < time.Second || lease > time.Minute || retry < time.Millisecond || retry > time.Minute || maxAttempts < 1 || maxAttempts > 100 || batchSize < 1 || batchSize > 100 {
		return nil, ErrInvalid
	}
	return &BrowserSessionDispatcher{store: store, provider: provider, workerID: workerID, lease: lease, retry: retry, maxAttempts: maxAttempts, batchSize: batchSize}, nil
}

func (d *BrowserSessionDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if d == nil || ctx == nil {
		return 0, ErrInvalid
	}
	work, err := d.store.LeaseBrowserSessionWork(ctx, d.workerID, d.lease, d.batchSize)
	if err != nil {
		return 0, err
	}
	complete := 0
	for _, item := range work {
		evidence, dispatchErr := d.provider.ExecuteBrowserSessionControl(ctx, item)
		if dispatchErr == nil || errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) || (errors.Is(dispatchErr, ErrDispatchRejected) && !evidence.Retryable) {
			if errors.Is(dispatchErr, ErrDispatchOutcomeUnknown) {
				evidence.State = "outcome_unknown"
				evidence.OutcomeUnknown = true
			}
			if err := d.store.RecordSessionDispatch(ctx, item, evidence); err != nil {
				return complete, err
			}
			complete++
			continue
		}
		if err := d.store.RetrySessionWork(ctx, item, safeDispatchCode(evidence.ErrorCode), d.retry, d.maxAttempts); err != nil {
			return complete, err
		}
	}
	return complete, nil
}

type SessionService struct {
	store  SessionStore
	policy SessionPolicy
	ids    IDGenerator
}

func NewSessionService(store SessionStore, policy SessionPolicy, ids IDGenerator) (*SessionService, error) {
	if nilInterface(store) || nilInterface(policy) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &SessionService{store: store, policy: policy, ids: ids}, nil
}

func (s *SessionService) Create(ctx context.Context, tenantID string, actor ActorRef, workspaceID, key string, request CreateSessionRequest) (Operation, bool, error) {
	if err := validateSessionInput(ctx, s, tenantID, actor, workspaceID, key); err != nil {
		return Operation{}, false, err
	}
	if request.ExpectedWorkspaceVersion < 1 || !validIdentifier(request.SlotKey) || !validIdentifier(request.Kind) || !validIdentifier(request.ProtocolProfile) || request.ExpiresInSeconds < 30 || request.ExpiresInSeconds > 86400 || (request.RecordingPolicy != "disabled" && request.RecordingPolicy != "metadata_only" && request.RecordingPolicy != "required") {
		return Operation{}, false, ErrInvalid
	}
	if !supportedSessionProfile(request.Kind, request.ProtocolProfile) {
		return Operation{}, false, ErrCapabilityUnsupported
	}
	if err := s.policy.AuthorizeSession(ctx, request.Kind, request.ProtocolProfile); err != nil {
		return Operation{}, false, err
	}
	sessionID, err := s.ids.NewID("ses")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	operationID, err := s.ids.NewID("op")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	outboxID, err := s.ids.NewID("out")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	digest, err := sessionDigest(request)
	if err != nil {
		return Operation{}, false, ErrInvalid
	}
	return s.store.CreateSession(ctx, SessionCommand{TenantID: tenantID, Actor: actor, WorkspaceID: workspaceID, SlotKey: request.SlotKey, SessionID: sessionID, OperationID: operationID, EventID: eventID, OutboxID: outboxID, IdempotencyKey: key, RequestDigest: digest, Path: "/api/v1/workspaces/" + workspaceID + "/sessions", ExpectedVersion: request.ExpectedWorkspaceVersion, Kind: request.Kind, ProtocolProfile: request.ProtocolProfile, RecordingPolicy: request.RecordingPolicy, Lifetime: time.Duration(request.ExpiresInSeconds) * time.Second})
}

func supportedSessionProfile(kind, profile string) bool {
	switch kind {
	case SessionKindTerminal:
		return profile == SessionProfileTerminal
	case SessionKindBrowserAutomation:
		return profile == SessionProfileBrowserAutomation
	case SessionKindBrowserLive:
		return profile == SessionProfileBrowserLive
	default:
		return false
	}
}

// CanTransitionSession is the Product-owned durable session state machine.
// External observations may request a transition, but they never redefine it.
func CanTransitionSession(from, to string) bool {
	switch from {
	case SessionStateRequested:
		return to == SessionStateProvisioning || to == SessionStateDraining || to == SessionStateExpired || to == SessionStateFailed
	case SessionStateProvisioning:
		return to == SessionStateReady || to == SessionStateDraining || to == SessionStateExpired || to == SessionStateFailed
	case SessionStateReady:
		return to == SessionStateActive || to == SessionStateDraining || to == SessionStateExpired || to == SessionStateFailed
	case SessionStateActive:
		return to == SessionStateReady || to == SessionStateDraining || to == SessionStateExpired || to == SessionStateFailed
	case SessionStateDraining:
		return to == SessionStateClosed || to == SessionStateFailed
	default:
		return false
	}
}
func (s *SessionService) Close(ctx context.Context, tenantID string, actor ActorRef, sessionID, key string, request CloseSessionRequest) (Operation, bool, error) {
	if err := validateSessionInput(ctx, s, tenantID, actor, sessionID, key); err != nil {
		return Operation{}, false, err
	}
	if request.ExpectedVersion < 1 || len(request.Reason) < 1 || len(request.Reason) > 256 {
		return Operation{}, false, ErrInvalid
	}
	operationID, err := s.ids.NewID("op")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	outboxID, err := s.ids.NewID("out")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	digest, err := sessionDigest(request)
	if err != nil {
		return Operation{}, false, ErrInvalid
	}
	return s.store.CloseSession(ctx, SessionCommand{TenantID: tenantID, Actor: actor, SessionID: sessionID, OperationID: operationID, EventID: eventID, OutboxID: outboxID, IdempotencyKey: key, RequestDigest: digest, Path: "/api/v1/sessions/" + sessionID + ":close", ExpectedVersion: request.ExpectedVersion, Reason: request.Reason})
}
func (s *SessionService) Resize(context.Context, string, ActorRef, string, string, int64, int, int, string, int64) (Operation, bool, error) {
	return Operation{}, false, ErrCapabilityUnsupported
}
func (s *SessionService) Get(ctx context.Context, tenantID string, actor ActorRef, sessionID string) (RuntimeSession, error) {
	if err := validateSessionRead(ctx, s, tenantID, actor, sessionID); err != nil {
		return RuntimeSession{}, err
	}
	session, err := s.store.GetSession(ctx, tenantID, sessionID)
	if err != nil {
		return RuntimeSession{}, err
	}
	workspace, err := s.storeWorkspaceOwner(ctx, tenantID, session.WorkspaceID)
	if err != nil || workspace != actor {
		return RuntimeSession{}, ErrNotFound
	}
	return session, nil
}
func (s *SessionService) List(ctx context.Context, tenantID string, actor ActorRef, workspaceID string, limit int) ([]RuntimeSession, error) {
	if err := validateSessionRead(ctx, s, tenantID, actor, workspaceID); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 200 {
		return nil, ErrInvalid
	}
	return s.store.ListSessions(ctx, tenantID, workspaceID, actor, limit)
}

type workspaceOwnerStore interface {
	GetWorkspace(context.Context, string, string) (Workspace, error)
}

func (s *SessionService) storeWorkspaceOwner(ctx context.Context, tenantID, workspaceID string) (ActorRef, error) {
	store, ok := s.store.(workspaceOwnerStore)
	if !ok {
		return ActorRef{}, ErrStoreUnavailable
	}
	workspace, err := store.GetWorkspace(ctx, tenantID, workspaceID)
	return workspace.Owner, err
}
func validateSessionInput(ctx context.Context, s *SessionService, tenantID string, actor ActorRef, resourceID, key string) error {
	if s == nil || s.store == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(resourceID) || !validIdempotencyKey(key) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
func validateSessionRead(ctx context.Context, s *SessionService, tenantID string, actor ActorRef, resourceID string) error {
	if s == nil || s.store == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(resourceID) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
func sessionDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
