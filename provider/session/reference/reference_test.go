package reference

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

var referenceTestTime = time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type testSessionReader struct {
	mu     sync.RWMutex
	record session.Record
	err    error
}

type testStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

func newTestStore() *testStore { return &testStore{records: make(map[string]Record)} }

func (s *testStore) Create(_ context.Context, record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.Reference]; exists {
		return ErrAlreadyExists
	}
	s.records[record.Reference] = record.Clone()
	return nil
}

func (s *testStore) Get(_ context.Context, value string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[value]
	if !ok {
		return Record{}, ErrNotFound
	}
	return record.Clone(), nil
}

func (s *testStore) FindRunning(_ context.Context, source session.Record) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.records {
		if record.OperationID != source.Request.OperationID {
			continue
		}
		if source.Allocation == nil || record.AttemptID != source.Request.AttemptID || record.FencingToken != source.Request.FencingToken ||
			record.Receipt.Reference != source.Allocation.Receipt.Reference {
			return Record{}, ErrConflict
		}
		return record.Clone(), nil
	}
	return Record{}, ErrNotFound
}

func (s *testStore) Revoke(_ context.Context, value string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[value]
	if !ok {
		return ErrNotFound
	}
	if record.RevokedAt == nil {
		revokedAt = revokedAt.UTC()
		record.RevokedAt = &revokedAt
		s.records[value] = record
	}
	return nil
}

func (r *testSessionReader) GetOpen(context.Context, string) (session.Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.err != nil {
		return session.Record{}, r.err
	}
	return r.record.Clone(), nil
}

func (r *testSessionReader) GetOpenAt(ctx context.Context, operationID string, _ time.Time) (session.Record, error) {
	return r.GetOpen(ctx, operationID)
}

func (r *testSessionReader) Set(record session.Record) {
	r.mu.Lock()
	r.record = record.Clone()
	r.mu.Unlock()
}

type testAttacher struct {
	mu       sync.Mutex
	receipts []terminal.Receipt
	err      error
}

func (a *testAttacher) Attach(ctx context.Context, receipt terminal.Receipt) (terminal.Stream, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.receipts = append(a.receipts, receipt)
	err := a.err
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return testTerminalStream{}, nil
}

func (a *testAttacher) Receipts() []terminal.Receipt {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]terminal.Receipt(nil), a.receipts...)
}

type testTerminalStream struct{}

func (testTerminalStream) Read(ctx context.Context, _ []byte) (int, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	return 0, io.EOF
}

func (testTerminalStream) Write(ctx context.Context, value []byte) (int, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (testTerminalStream) Close() error { return nil }

func testRequest() session.OpenRequest {
	return session.OpenRequest{
		SandboxID: "sandbox-reference", ProviderRevisionID: "provider-revision-reference",
		OperationID: "operation-reference", AttemptID: "attempt-reference", FencingToken: 1,
		IdempotencyKey: "reference-key", RequestDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline: referenceTestTime.Add(30 * time.Minute), ExpectedGeneration: 1,
		RuntimeSessionID: "session-reference", RuntimeType: session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1", ExpiresAt: referenceTestTime.Add(10 * time.Minute),
	}
}

func runningSession(t *testing.T) session.Record {
	t.Helper()
	return runningSessionForRequest(t, testRequest())
}

func runningSessionForRequest(t *testing.T, request session.OpenRequest) session.Record {
	t.Helper()
	record, err := session.NewRecord(request, referenceTestTime)
	if err != nil {
		t.Fatal(err)
	}
	receipt := session.AllocationReceipt{
		Reference: "ref:terminal/11111111111111111111111111111111", SandboxID: request.SandboxID,
		RuntimeSessionID: request.RuntimeSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: referenceTestTime, ExpiresAt: request.ExpiresAt,
	}
	running, err := session.AttachAllocation(record, receipt)
	if err != nil {
		t.Fatal(err)
	}
	return running
}

func succeededSession(t *testing.T, running session.Record, evidence session.EndpointEvidence) session.Record {
	t.Helper()
	succeeded, err := session.Transition(running, session.StatusSucceeded, referenceTestTime.Add(time.Second), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	return succeeded
}

func newRegisteredResolver(t *testing.T) (*Resolver, *testStore, *testClock, *testSessionReader, *testAttacher, Registration) {
	t.Helper()
	clock := &testClock{now: referenceTestTime}
	store := newTestStore()
	registrar, err := NewRegistrar(store, clock, func() (string, error) { return "ref:session:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil })
	if err != nil {
		t.Fatal(err)
	}
	running := runningSession(t)
	registration, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	reader := &testSessionReader{record: succeededSession(t, running, registration.Evidence)}
	attacher := &testAttacher{}
	resolver, err := NewResolver(store, reader, attacher, clock)
	if err != nil {
		t.Fatal(err)
	}
	return resolver, store, clock, reader, attacher, registration
}

func TestRegistrarRetriesOpaqueReferenceCollision(t *testing.T) {
	clock := &testClock{now: referenceTestTime}
	store := newTestStore()
	running := runningSession(t)
	otherRequest := testRequest()
	otherRequest.OperationID = "operation-reference-other"
	otherRequest.AttemptID = "attempt-reference-other"
	otherRequest.RuntimeSessionID = "session-reference-other"
	otherRequest.IdempotencyKey = "reference-key-other"
	other := runningSessionForRequest(t, otherRequest)
	existing, err := NewRecord("ref:session:11111111111111111111111111111111", other, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	values := []string{existing.Reference, "ref:session:22222222222222222222222222222222"}
	registrar, err := NewRegistrar(store, clock, func() (string, error) {
		value := values[0]
		values = values[1:]
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := registrar.Register(context.Background(), running)
	if err != nil || registration.Record.Reference != "ref:session:22222222222222222222222222222222" {
		t.Fatalf("Register() = %#v, %v", registration, err)
	}
	if registration.Evidence.InternalEndpointReference != registration.Record.Reference || registration.Evidence.ConnectionGeneration != 1 {
		t.Fatalf("evidence = %#v", registration.Evidence)
	}
}

func TestRegistrarReusesExactRunningSessionReference(t *testing.T) {
	clock := &testClock{now: referenceTestTime}
	store := newTestStore()
	generated := 0
	registrar, err := NewRegistrar(store, clock, func() (string, error) {
		generated++
		return "ref:session:33333333333333333333333333333333", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	running := runningSession(t)
	first, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	if generated != 1 || second.Record.Reference != first.Record.Reference || second.Evidence != first.Evidence {
		t.Fatalf("registrations first=%#v second=%#v generated=%d", first, second, generated)
	}
}

func TestRegistrarRejectsTerminalSessionThatCannotMintReference(t *testing.T) {
	clock := &testClock{now: referenceTestTime}
	store := newTestStore()
	registrar, err := NewRegistrar(store, clock, func() (string, error) { return "ref:session:33333333333333333333333333333333", nil })
	if err != nil {
		t.Fatal(err)
	}
	running := runningSession(t)
	failed, err := session.Transition(running, session.StatusFailed, referenceTestTime.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registrar.Register(context.Background(), failed); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Register(terminal) error = %v", err)
	}
}

func TestResolverReturnsFreshTerminalDialWithoutBackendProjection(t *testing.T) {
	resolver, _, _, _, attacher, registration := newRegisteredResolver(t)
	endpoint, err := resolver.Resolve(context.Background(), registration.Record.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Reference != registration.Record.Reference || endpoint.SandboxID != registration.Record.SandboxID ||
		endpoint.RuntimeSessionID != registration.Record.RuntimeSessionID || endpoint.ConnectionGeneration != registration.Record.ConnectionGeneration || endpoint.Dial == nil {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	if _, err := endpoint.Dial(context.Background()); err != nil {
		t.Fatalf("Dial() = %v", err)
	}
	receipts := attacher.Receipts()
	if len(receipts) != 1 || string(receipts[0].Reference) != registration.Record.Receipt.Reference || receipts[0].OperationID != registration.Record.OperationID {
		t.Fatalf("attached receipts = %#v", receipts)
	}
}

func TestResolverRejectsExpiryRevocationAndStaleBindings(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		resolver, _, clock, _, _, registration := newRegisteredResolver(t)
		clock.Set(registration.Record.ExpiresAt)
		if _, err := resolver.Resolve(context.Background(), registration.Record.Reference); !errors.Is(err, ErrExpired) {
			t.Fatalf("Resolve(expired) error = %v", err)
		}
	})
	t.Run("revocation", func(t *testing.T) {
		resolver, store, clock, _, _, registration := newRegisteredResolver(t)
		if err := store.Revoke(context.Background(), registration.Record.Reference, clock.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := resolver.Resolve(context.Background(), registration.Record.Reference); !errors.Is(err, ErrRevoked) {
			t.Fatalf("Resolve(revoked) error = %v", err)
		}
	})
	t.Run("wrong generation", func(t *testing.T) {
		resolver, _, _, reader, _, registration := newRegisteredResolver(t)
		running := runningSession(t)
		reader.Set(succeededSession(t, running, session.EndpointEvidence{
			InternalEndpointReference: registration.Record.Reference, ConnectionGeneration: registration.Record.ConnectionGeneration + 1,
		}))
		if _, err := resolver.Resolve(context.Background(), registration.Record.Reference); !errors.Is(err, ErrStale) {
			t.Fatalf("Resolve(wrong generation) error = %v", err)
		}
	})
	t.Run("mismatched reference", func(t *testing.T) {
		resolver, _, _, reader, _, registration := newRegisteredResolver(t)
		running := runningSession(t)
		reader.Set(succeededSession(t, running, session.EndpointEvidence{
			InternalEndpointReference: "ref:session:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ConnectionGeneration: registration.Record.ConnectionGeneration,
		}))
		if _, err := resolver.Resolve(context.Background(), registration.Record.Reference); !errors.Is(err, ErrStale) {
			t.Fatalf("Resolve(mismatched reference) error = %v", err)
		}
	})
}

func TestResolverRechecksReferenceAtDialDuringConcurrentCleanup(t *testing.T) {
	resolver, store, clock, _, _, registration := newRegisteredResolver(t)
	endpoint, err := resolver.Resolve(context.Background(), registration.Record.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(context.Background(), registration.Record.Reference, clock.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Dial(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Dial() after cleanup = %v", err)
	}

	resolver, store, clock, _, _, registration = newRegisteredResolver(t)
	start := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		<-start
		for i := 0; i < 100; i++ {
			_, err := resolver.Resolve(context.Background(), registration.Record.Reference)
			if err != nil && !errors.Is(err, ErrRevoked) {
				result <- fmt.Errorf("resolve during cleanup: %w", err)
				return
			}
		}
		result <- nil
	}()
	close(start)
	if err := store.Revoke(context.Background(), registration.Record.Reference, clock.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
