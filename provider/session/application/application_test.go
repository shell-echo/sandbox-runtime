package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
)

var applicationTestTime = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

type authoritySpy struct {
	record session.Record
	err    error
	calls  int
}

func (a *authoritySpy) ReserveOpen(_ context.Context, request session.OpenRequest, acceptedAt time.Time) (session.Reservation, error) {
	a.calls++
	if a.err != nil {
		return session.Reservation{}, a.err
	}
	record, err := session.NewRecord(request, acceptedAt)
	if err != nil {
		return session.Reservation{}, err
	}
	a.record = record
	return session.Reservation{Record: record}, nil
}

func (a *authoritySpy) GetOpen(_ context.Context, _ string) (session.Record, error) {
	if a.err != nil {
		return session.Record{}, a.err
	}
	return a.record.Clone(), nil
}

func (a *authoritySpy) GetOpenAt(_ context.Context, _ string, _ time.Time) (session.Record, error) {
	return a.GetOpen(context.Background(), "")
}

func (a *authoritySpy) UpdateOpen(context.Context, session.Record, session.Status) error { return nil }

var _ session.Authority = (*authoritySpy)(nil)

func validApplicationRequest() session.OpenRequest {
	return session.OpenRequest{
		SandboxID:           "sandbox-1",
		ProviderRevisionID:  "provider-revision-1",
		OperationID:         "operation-1",
		AttemptID:           "attempt-1",
		FencingToken:        1,
		IdempotencyKey:      "session-key-1",
		RequestDigest:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:            applicationTestTime.Add(30 * time.Minute),
		ExpectedGeneration:  1,
		RuntimeSessionID:    "session-1",
		RuntimeType:         session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1",
		ExpiresAt:           applicationTestTime.Add(10 * time.Minute),
	}
}

func newTestApplication(t *testing.T, authority session.Authority) *Application {
	t.Helper()
	app, err := New(authority, ClockFunc(func() time.Time { return applicationTestTime }))
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	clock := ClockFunc(func() time.Time { return applicationTestTime })
	if _, err := New(nil, clock); !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("New(nil, clock) = %v", err)
	}
	spy := &authoritySpy{}
	if _, err := New(spy, nil); !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("New(spy, nil) = %v", err)
	}
}

func TestOpenReturnsAcceptedProjectionAndDoesNotDispatch(t *testing.T) {
	spy := &authoritySpy{}
	operation, err := newTestApplication(t, spy).Open(context.Background(), validApplicationRequest())
	if err != nil {
		t.Fatal(err)
	}
	if spy.calls != 1 || operation.OperationID != "operation-1" || operation.Status != session.StatusAccepted || operation.SandboxID != "sandbox-1" {
		t.Fatalf("operation=%#v calls=%d", operation, spy.calls)
	}
}

func TestGetHandoffOnlyProjectsSuccessfulOpaqueRecord(t *testing.T) {
	spy := &authoritySpy{}
	request := validApplicationRequest()
	record, err := session.NewRecord(request, applicationTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, err := session.Transition(record, session.StatusRunning, applicationTestTime.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	succeeded, err := session.Transition(running, session.StatusSucceeded, applicationTestTime.Add(2*time.Second), &session.EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	spy.record = succeeded
	handoff, err := newTestApplication(t, spy).GetHandoff(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if handoff.InternalEndpointReference != "ref:session:opaque-1" || handoff.Protocol != session.ProtocolWebSocket || handoff.RuntimeType != session.RuntimeTerminal {
		t.Fatalf("handoff=%#v", handoff)
	}
}

func TestGetHandoffRejectsPendingUnknownAndExpired(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(session.Record) session.Record
		want error
	}{
		{name: "pending", make: func(record session.Record) session.Record { return record }, want: ErrHandoffPending},
		{name: "outcome unknown", make: func(record session.Record) session.Record {
			updated, _ := session.Transition(record, session.StatusOutcomeUnknown, applicationTestTime.Add(time.Second), nil)
			return updated
		}, want: session.ErrHandoffUnavailable},
		{name: "expired", make: func(record session.Record) session.Record {
			running, _ := session.Transition(record, session.StatusRunning, applicationTestTime.Add(time.Second), nil)
			succeeded, _ := session.Transition(running, session.StatusSucceeded, applicationTestTime.Add(2*time.Second), &session.EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1})
			succeeded.Handoff.ExpiresAt = applicationTestTime
			succeeded.Request.ExpiresAt = applicationTestTime
			return succeeded
		}, want: session.ErrHandoffExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validApplicationRequest()
			record, err := session.NewRecord(request, applicationTestTime)
			if err != nil {
				t.Fatal(err)
			}
			spy := &authoritySpy{record: test.make(record)}
			_, err = newTestApplication(t, spy).GetHandoff(context.Background(), request.OperationID)
			if !errors.Is(err, test.want) {
				t.Fatalf("GetHandoff() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOpenPropagatesAuthorityErrors(t *testing.T) {
	known := session.ErrStaleFencingToken
	spy := &authoritySpy{err: known}
	_, err := newTestApplication(t, spy).Open(context.Background(), validApplicationRequest())
	if !errors.Is(err, known) {
		t.Fatalf("Open() = %v, want %v", err, known)
	}
}
