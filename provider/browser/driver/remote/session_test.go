package remote

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

type attemptStore struct {
	mu       sync.Mutex
	reserved []executorprotocol.Open
	closed   bool
}

func (s *attemptStore) ReserveExecutor(_ context.Context, open executorprotocol.Open, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reserved) != 0 {
		return reference.ErrConflict
	}
	s.reserved = append(s.reserved, open)
	return nil
}

func (s *attemptStore) matches(open executorprotocol.Open) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reserved) == 1 && s.reserved[0] == open
}

func (s *attemptStore) CloseConnection(_ context.Context, ref, epoch, authorityDigest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reserved) == 1 && s.reserved[0].HandoffReference == ref &&
		s.reserved[0].ConnectionEpoch == epoch {
		s.closed = true
	}
	return nil
}

func remoteConnectionFixture(t *testing.T) (reference.Record, string) {
	t.Helper()
	now := time.Now().UTC()
	expires := now.Add(30 * time.Minute)
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1",
		AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64),
		Deadline: now.Add(time.Hour), ExpectedGeneration: 1, BrowserSessionID: "browser-1",
		CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: expires}
	running, err := browser.NewRecord(request, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	receipt := browser.AllocationReceipt{Reference: "ref:browser/11111111111111111111111111111111", SandboxID: request.SandboxID,
		BrowserSessionID: request.BrowserSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now, ExpiresAt: expires}
	running, err = browser.AttachAllocation(running, receipt)
	if err != nil {
		t.Fatal(err)
	}
	referenceID := "ref:browser-session:" + strings.Repeat("1", 32)
	digest := browserbinding.Prefix + strings.Repeat("b", 64)
	record, err := reference.NewRecordWithTenantBinding(referenceID, running, digest, now.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	private := browserhandoffv2.OpenRequest{BindingVersion: browserhandoffv2.BindingVersion,
		BindingIssuer: browserhandoffv2.BindingIssuer, Protocol: browserhandoffv2.ProtocolID,
		RequestID: "private-request-1", Resource: browserhandoffv2.ResourceBrowser, TenantBindingDigest: digest,
		ProviderRevisionID: request.ProviderRevisionID, SandboxID: request.SandboxID,
		BrowserSessionID: request.BrowserSessionID, CapabilityProfileID: browser.CapabilityProfileID,
		MediaProfileID: browserhandoffv2.MediaProfileID, ControlProfileID: browserhandoffv2.ControlProfileID,
		HandoffReference: referenceID, HandoffDigest: browserhandoffv2.ReferenceDigest(referenceID),
		ConnectionGeneration: 1, ConnectionEpoch: "epoch-1", ControlLeaseDigest: "sha256:" + strings.Repeat("c", 64),
		ControlFence: 1, AuthorityExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt: expires.Format(time.RFC3339Nano)}
	private.AuthorityDigest = browserhandoffv2.AuthorityDigest(private)
	private.RequestDigest = browserhandoffv2.RequestDigest(private)
	claim, err := reference.ConnectionFromOpen(private, now)
	if err != nil {
		t.Fatal(err)
	}
	record.ConnectionClaims = map[string]reference.ConnectionClaim{private.ConnectionEpoch: claim}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	return record, private.ConnectionEpoch
}

func TestAttachConnectionReservesExactAuthorityBeforeSend(t *testing.T) {
	record, epoch := remoteConnectionFixture(t)
	store := &attemptStore{}
	seen := make(chan executorprotocol.Open, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{executorprotocol.ProtocolID}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		kind, document, err := connection.Read(request.Context())
		var open executorprotocol.Open
		if err != nil || kind != websocket.MessageText || executorprotocol.Decode(document, &open) != nil ||
			open.Validate(time.Now().UTC()) != nil || !store.matches(open) {
			return
		}
		seen <- open
		response, _ := executorprotocol.Encode(executorprotocol.Accepted(open.RequestID))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
	}))
	defer server.Close()
	attacher, err := New(Options{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/session",
		HTTPClient: server.Client(), OperationTimeout: 5 * time.Second, ConnectionStore: store})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := attacher.AttachConnection(context.Background(), record, epoch)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	select {
	case open := <-seen:
		claim := record.ConnectionClaims[epoch]
		fence, _ := browserhandoffv2.ExecutorFence(claim.AuthorityDigest)
		if open.ConnectionEpoch != epoch || open.Fence != fence ||
			open.AuthorityExpiresAt != claim.AuthorityExpiresAt.Format(time.RFC3339Nano) ||
			open.HandoffExpiresAt != record.ExpiresAt.Format(time.RFC3339Nano) ||
			open.RequestDigest == claim.PrivateRequestDigest {
			t.Fatalf("executor lost exact private binding: %#v", open)
		}
	default:
		t.Fatal("server did not receive reserved authority")
	}
	if _, err := attacher.AttachConnection(context.Background(), record, epoch); err == nil {
		t.Fatal("uncertain prior attempt could be retried with a fresh request ID")
	}
}

func TestAttachConnectionClosesReservedEpochAfterAmbiguousSendFailure(t *testing.T) {
	record, epoch := remoteConnectionFixture(t)
	store := &attemptStore{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	attacher, err := New(Options{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/session",
		HTTPClient: server.Client(), OperationTimeout: time.Second, ConnectionStore: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attacher.AttachConnection(context.Background(), record, epoch); err == nil {
		t.Fatal("failed WebSocket handshake accepted")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.reserved) != 1 || !store.closed {
		t.Fatal("ambiguous send failure lost one-use reservation or left epoch active")
	}
}
