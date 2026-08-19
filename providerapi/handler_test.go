package providerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func TestNewCapabilitiesHandlerReadsSourceOnceAndFreezesResponse(t *testing.T) {
	snapshot := validSnapshot(t, int64Pointer(4096), int64Pointer(0))
	source := &capabilityReaderSpy{snapshot: snapshot}
	handler, err := newCapabilitiesHandler(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if source.callCount() != 1 {
		t.Fatalf("source calls = %d, want 1", source.callCount())
	}

	*snapshot.Limits.MaxWorkspaceBytes = 1
	snapshot.SnapshotRestoreProfiles[0].ProfileID = "mutated-after-construction"

	first := serve(handler, http.MethodGet, capabilitiesPath, "")
	second := serve(handler, http.MethodGet, capabilitiesPath, "Bearer arbitrary-value")
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("GET statuses = %d, %d", first.Code, second.Code)
	}
	if contentType := first.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("response changed with Authorization header:\n%s\n%s", first.Body.Bytes(), second.Body.Bytes())
	}
	if source.callCount() != 1 {
		t.Fatalf("source calls after requests = %d, want 1", source.callCount())
	}

	var document providerv1.Capabilities
	if err := json.Unmarshal(first.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	if document.ProviderRevisionID != "revision-1" || document.SnapshotRestoreProfile[0].ProfileID != "sandbox-snapshot-workspace-v1" ||
		document.Limits.MaxWorkspaceBytes == nil || *document.Limits.MaxWorkspaceBytes != 4096 {
		t.Fatalf("frozen document = %#v", document)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(first.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	for _, localField := range []string{"code", "message", "success", "data", "time", "latency"} {
		if _, exists := envelope[localField]; exists {
			t.Fatalf("raw Provider response contains local envelope field %q", localField)
		}
	}
}

func TestCapabilitiesHandlerRejectsMethodsAndAbsentRoutesWithoutSourceReads(t *testing.T) {
	source := &capabilityReaderSpy{snapshot: validSnapshot(t, nil, nil)}
	handler, err := newCapabilitiesHandler(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}

	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		t.Run(method+" exact path", func(t *testing.T) {
			response := serve(handler, method, capabilitiesPath, "")
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", response.Code)
			}
			if allow := response.Header().Get("Allow"); allow != http.MethodGet {
				t.Fatalf("Allow = %q, want GET", allow)
			}
		})
	}

	absentPaths := []string{
		"/", "/v1/capabilities/", "/v1/unknown", "/v1/sandboxes", "/v1/sandboxes:restore",
		"/v1/sandboxes/sandbox-1", "/v1/sandboxes/sandbox-1/desired-state",
		"/v1/sandboxes/sandbox-1/lease", "/v1/sandboxes/sandbox-1/exec",
		"/v1/sandboxes/sandbox-1/exec:cancel", "/v1/sandboxes/sandbox-1/runtime-sessions",
		"/v1/sandboxes/sandbox-1/snapshots", "/v1/sandboxes/sandbox-1:terminate",
		"/v1/operations/op-1", "/v1/operations/op-1/exec-result",
		"/v1/operations/op-1/snapshot-manifest", "/v1/sandboxes/sandbox-1/events",
	}
	for _, path := range absentPaths {
		t.Run(path, func(t *testing.T) {
			if response := serve(handler, http.MethodGet, path, ""); response.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", response.Code)
			}
		})
	}
	if source.callCount() != 1 {
		t.Fatalf("source calls after rejected requests = %d, want construction read only", source.callCount())
	}
}

func TestCapabilitiesHandlerRejectsRequestsWithoutADocumentBeforeDispatch(t *testing.T) {
	source := &capabilityReaderSpy{snapshot: validSnapshot(t, nil, nil)}
	handler, err := newCapabilitiesHandler(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		path       string
		contentLen int64
		transfer   []string
		body       io.ReadCloser
		forceQuery bool
	}{
		{name: "unknown query", path: capabilitiesPath + "?unexpected=value", contentLen: 0, body: http.NoBody},
		{name: "bare trailing question mark", path: capabilitiesPath + "?", contentLen: 0, body: blockingReadCloser{}, forceQuery: true},
		{name: "one byte content length", path: capabilitiesPath, contentLen: 1, body: http.NoBody},
		{name: "maximum content length", path: capabilitiesPath, contentLen: math.MaxInt64, body: http.NoBody},
		{name: "chunked body", path: capabilitiesPath, contentLen: -1, transfer: []string{"chunked"}, body: blockingReadCloser{}},
		{name: "unknown length body", path: capabilitiesPath, contentLen: -1, body: blockingReadCloser{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.ContentLength = test.contentLen
			request.TransferEncoding = test.transfer
			request.Body = test.body
			if request.URL.ForceQuery != test.forceQuery {
				t.Fatalf("ForceQuery = %t, want %t", request.URL.ForceQuery, test.forceQuery)
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", response.Code)
			}
			if response.Body.Len() != 0 {
				t.Fatalf("rejection body = %q, want empty", response.Body.String())
			}
			if contentType := response.Header().Get("Content-Type"); contentType != "" {
				t.Fatalf("rejection Content-Type = %q, want empty", contentType)
			}
		})
	}

	response := serve(handler, http.MethodGet, capabilitiesPath, "")
	if response.Code != http.StatusOK {
		t.Fatalf("empty request status = %d, want 200", response.Code)
	}
	if source.callCount() != 1 {
		t.Fatalf("source calls after rejected requests = %d, want construction read only", source.callCount())
	}
}

func TestNewCapabilitiesHandlerFailsBeforeServing(t *testing.T) {
	sourceError := errors.New("source unavailable")
	tests := []struct {
		name   string
		ctx    context.Context
		source provider.CapabilityReader
	}{
		{name: "nil context", source: &capabilityReaderSpy{}},
		{name: "nil source", ctx: context.Background()},
		{name: "source error", ctx: context.Background(), source: &capabilityReaderSpy{err: sourceError}},
		{name: "invalid mapped response", ctx: context.Background(), source: &capabilityReaderSpy{snapshot: provider.CapabilitySnapshot{}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := newCapabilitiesHandler(test.ctx, test.source)
			if err == nil || handler != nil {
				t.Fatalf("NewCapabilitiesHandler() = (%v, %v), want nil handler and error", handler, err)
			}
		})
	}
}

func serve(handler http.Handler, method, path, authorization string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type capabilityReaderSpy struct {
	mu       sync.Mutex
	calls    int
	snapshot provider.CapabilitySnapshot
	err      error
}

type blockingReadCloser struct{}

func (blockingReadCloser) Read([]byte) (int, error) {
	panic("request body must not be read")
}

func (blockingReadCloser) Close() error { return nil }

func (s *capabilityReaderSpy) CapabilitySnapshot(context.Context) (provider.CapabilitySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.snapshot, s.err
}

func (s *capabilityReaderSpy) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestCapabilitiesHandlerResponsesAreByteStableConcurrently(t *testing.T) {
	source := &capabilityReaderSpy{snapshot: validSnapshot(t, nil, nil)}
	handler, err := newCapabilitiesHandler(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	want := serve(handler, http.MethodGet, capabilitiesPath, "").Body.Bytes()

	const readers = 32
	responses := make(chan []byte, readers)
	var waitGroup sync.WaitGroup
	for range readers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			responses <- append([]byte(nil), serve(handler, http.MethodGet, capabilitiesPath, "").Body.Bytes()...)
		}()
	}
	waitGroup.Wait()
	close(responses)
	for response := range responses {
		if !reflect.DeepEqual(response, want) {
			t.Fatalf("concurrent response = %q, want %q", response, want)
		}
	}
	if source.callCount() != 1 {
		t.Fatalf("source calls = %d, want 1", source.callCount())
	}
}
