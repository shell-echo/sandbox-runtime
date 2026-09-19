package product

import (
	"context"
	"errors"
	"testing"
	"time"
)

type browserSessionDispatchStoreStub struct {
	work     []SessionControlWork
	recorded []ProviderOperationEvidence
	retries  int
}

func (s *browserSessionDispatchStoreStub) LeaseBrowserSessionWork(context.Context, string, time.Duration, int) ([]SessionControlWork, error) {
	return s.work, nil
}
func (s *browserSessionDispatchStoreStub) RecordSessionDispatch(_ context.Context, _ SessionControlWork, evidence ProviderOperationEvidence) error {
	s.recorded = append(s.recorded, evidence)
	return nil
}
func (s *browserSessionDispatchStoreStub) RetrySessionWork(context.Context, SessionControlWork, string, time.Duration, int) error {
	s.retries++
	return nil
}

type browserSessionControllerStub struct {
	evidence ProviderOperationEvidence
	err      error
}

func (s browserSessionControllerStub) ExecuteBrowserSessionControl(context.Context, SessionControlWork) (ProviderOperationEvidence, error) {
	return s.evidence, s.err
}

func TestBrowserSessionDispatcherIsolatedOutcomeHandling(t *testing.T) {
	store := &browserSessionDispatchStoreStub{work: []SessionControlWork{{SessionID: "browser-session-1"}}}
	dispatcher, err := NewBrowserSessionDispatcher(store, browserSessionControllerStub{err: ErrDispatchOutcomeUnknown}, "browser-session-worker", time.Second, time.Millisecond, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := dispatcher.DispatchOnce(context.Background()); err != nil || count != 1 || len(store.recorded) != 1 || store.recorded[0].State != "outcome_unknown" {
		t.Fatalf("count=%d store=%#v err=%v", count, store, err)
	}
	store = &browserSessionDispatchStoreStub{work: []SessionControlWork{{SessionID: "browser-session-2"}}}
	dispatcher, _ = NewBrowserSessionDispatcher(store, browserSessionControllerStub{evidence: ProviderOperationEvidence{Retryable: true}, err: ErrDispatchRejected}, "browser-session-worker", time.Second, time.Millisecond, 3, 1)
	if count, err := dispatcher.DispatchOnce(context.Background()); err != nil || count != 0 || store.retries != 1 {
		t.Fatalf("count=%d retries=%d err=%v", count, store.retries, err)
	}
}

type sessionStoreStub struct {
	command   SessionCommand
	operation Operation
	err       error
}

func (s *sessionStoreStub) CreateSession(_ context.Context, c SessionCommand) (Operation, bool, error) {
	s.command = c
	return s.operation, false, s.err
}
func (s *sessionStoreStub) CloseSession(_ context.Context, c SessionCommand) (Operation, bool, error) {
	s.command = c
	return s.operation, false, s.err
}
func (s *sessionStoreStub) GetSession(context.Context, string, string) (RuntimeSession, error) {
	return RuntimeSession{}, s.err
}
func (s *sessionStoreStub) ListSessions(context.Context, string, string, ActorRef, int) ([]RuntimeSession, error) {
	return nil, s.err
}

type sessionPolicyStub struct{ err error }

func (p sessionPolicyStub) AuthorizeSession(context.Context, string, string) error { return p.err }

func TestSessionServicePersistsIntentBeforeProviderWork(t *testing.T) {
	store := &sessionStoreStub{operation: Operation{ID: "op_2"}}
	service, err := NewSessionService(store, sessionPolicyStub{}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := CreateSessionRequest{ExpectedWorkspaceVersion: 2, SlotKey: PrimarySlotKey, Kind: "terminal", ProtocolProfile: "product-terminal.v1", ExpiresInSeconds: 3600, RecordingPolicy: "metadata_only"}
	operation, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "key-1", request)
	if err != nil || operation.ID != "op_2" {
		t.Fatalf("operation=%#v err=%v", operation, err)
	}
	if store.command.SessionID != "ses_1" || store.command.OperationID != "op_2" || store.command.EventID != "evt_3" || store.command.OutboxID != "out_4" || store.command.RequestDigest == [32]byte{} {
		t.Fatalf("command=%#v", store.command)
	}
}
func TestSessionServiceFailsClosedOnCapabilityAndResize(t *testing.T) {
	service, _ := NewSessionService(&sessionStoreStub{}, sessionPolicyStub{err: ErrCapabilityUnsupported}, &sequenceIDs{})
	request := CreateSessionRequest{ExpectedWorkspaceVersion: 1, SlotKey: PrimarySlotKey, Kind: "terminal", ProtocolProfile: "product-terminal.v1", ExpiresInSeconds: 30, RecordingPolicy: "disabled"}
	if _, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "key", request); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("err=%v", err)
	}
	if _, _, err := service.Resize(context.Background(), "tenant-1", ActorRef{}, "ses-1", "key", 1, 80, 24, "ctl-1", 1); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("resize err=%v", err)
	}
}

func TestSessionServiceAcceptsOnlyExactBrowserProfiles(t *testing.T) {
	tests := []struct {
		kind    string
		profile string
	}{
		{kind: SessionKindBrowserAutomation, profile: SessionProfileBrowserAutomation},
		{kind: SessionKindBrowserLive, profile: SessionProfileBrowserLive},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			store := &sessionStoreStub{operation: Operation{ID: "op_browser"}}
			service, err := NewSessionService(store, sessionPolicyStub{}, &sequenceIDs{})
			if err != nil {
				t.Fatal(err)
			}
			request := CreateSessionRequest{ExpectedWorkspaceVersion: 2, SlotKey: "browser-main", Kind: test.kind, ProtocolProfile: test.profile, ExpiresInSeconds: 900, RecordingPolicy: "required"}
			operation, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "browser-key", request)
			if err != nil || operation.ID != "op_browser" || store.command.Kind != test.kind || store.command.ProtocolProfile != test.profile {
				t.Fatalf("operation=%#v command=%#v err=%v", operation, store.command, err)
			}
		})
	}

	service, _ := NewSessionService(&sessionStoreStub{}, sessionPolicyStub{}, &sequenceIDs{})
	request := CreateSessionRequest{ExpectedWorkspaceVersion: 1, SlotKey: "browser-main", Kind: SessionKindBrowserLive, ProtocolProfile: SessionProfileBrowserAutomation, ExpiresInSeconds: 900, RecordingPolicy: "metadata_only"}
	if _, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "browser-key", request); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("mismatched browser profile err=%v", err)
	}
}

func TestSessionServiceAcceptsOnlyExactDesktopProfile(t *testing.T) {
	store := &sessionStoreStub{operation: Operation{ID: "op_desktop"}}
	service, err := NewSessionService(store, sessionPolicyStub{}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := CreateSessionRequest{ExpectedWorkspaceVersion: 2, SlotKey: "desktop-main", Kind: SessionKindDesktop, ProtocolProfile: SessionProfileDesktop, ExpiresInSeconds: 900, RecordingPolicy: "required"}
	operation, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "desktop-key", request)
	if err != nil || operation.ID != "op_desktop" || store.command.Kind != SessionKindDesktop || store.command.ProtocolProfile != SessionProfileDesktop {
		t.Fatalf("operation=%#v command=%#v err=%v", operation, store.command, err)
	}
	request.ProtocolProfile = SessionProfileBrowserLive
	if _, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "desktop-key-2", request); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("mismatched Desktop profile err=%v", err)
	}
}

func TestBrowserSessionStateMachineRejectsResurrection(t *testing.T) {
	allowed := [][2]string{
		{SessionStateRequested, SessionStateProvisioning},
		{SessionStateProvisioning, SessionStateReady},
		{SessionStateReady, SessionStateActive},
		{SessionStateActive, SessionStateReady},
		{SessionStateActive, SessionStateDraining},
		{SessionStateDraining, SessionStateClosed},
	}
	for _, transition := range allowed {
		if !CanTransitionSession(transition[0], transition[1]) {
			t.Fatalf("transition %q -> %q rejected", transition[0], transition[1])
		}
	}
	for _, terminal := range []string{SessionStateClosed, SessionStateExpired, SessionStateFailed} {
		for _, next := range []string{SessionStateRequested, SessionStateProvisioning, SessionStateReady, SessionStateActive, SessionStateDraining} {
			if CanTransitionSession(terminal, next) {
				t.Fatalf("terminal transition %q -> %q accepted", terminal, next)
			}
		}
	}
}

func TestDesktopSessionTerminalStatesAreAbsorbing(t *testing.T) {
	for _, terminal := range []string{SessionStateClosed, SessionStateExpired, SessionStateFailed} {
		for _, next := range []string{SessionStateRequested, SessionStateProvisioning, SessionStateReady, SessionStateActive, SessionStateDraining} {
			if CanTransitionSession(terminal, next) {
				t.Fatalf("Desktop terminal transition %q -> %q accepted", terminal, next)
			}
		}
	}
}

type browserExpiryStoreStub struct {
	candidates []BrowserExpiryCandidate
	commands   []BrowserExpiryCommand
	changed    bool
}

func (s *browserExpiryStoreStub) ListExpiredBrowserSessions(context.Context, int) ([]BrowserExpiryCandidate, error) {
	return s.candidates, nil
}
func (s *browserExpiryStoreStub) ExpireBrowserSession(_ context.Context, c BrowserExpiryCommand) (bool, error) {
	s.commands = append(s.commands, c)
	return s.changed, nil
}

func TestBrowserExpiryWorkerAllocatesDurableCleanupIntent(t *testing.T) {
	store := &browserExpiryStoreStub{candidates: []BrowserExpiryCandidate{{TenantID: "tenant-1", SessionID: "ses-1", Version: 4}}, changed: true}
	worker, err := NewBrowserExpiryWorker(store, &sequenceIDs{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	count, err := worker.ExpireOnce(context.Background())
	if err != nil || count != 1 || len(store.commands) != 1 || store.commands[0].OperationID != "op_1" || store.commands[0].EventID != "evt_2" || store.commands[0].OutboxID != "out_3" {
		t.Fatalf("count=%d commands=%#v err=%v", count, store.commands, err)
	}
}
