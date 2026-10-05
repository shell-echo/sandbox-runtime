package dockercontrol

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

func testCodingDeleteRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method,
		"http://placeholder"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = client.DummyHost
	request.URL.Host = "/run/docker.sock"
	return request
}

func TestCodingDeletionTransportClosedAllowlistAndResponse(t *testing.T) {
	runtimeID := strings.Repeat("a", 64)
	transport := &codingDeletionTransport{endpointHost: "/run/docker.sock",
		runtimeID: runtimeID, volumes: [3]string{"volume-inputs", "volume-workspace", "volume-outputs"},
		base: codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return codingSDKResponse(http.StatusNoContent, "", ""), nil
		})}
	for _, path := range []string{"/v1.55/containers/" + runtimeID + "?force=1",
		"/v1.55/volumes/volume-inputs", "/v1.55/volumes/volume-workspace",
		"/v1.55/volumes/volume-outputs"} {
		request := testCodingDeleteRequest(t, http.MethodDelete, path)
		response, err := transport.RoundTrip(request)
		if err != nil || response.StatusCode != http.StatusNoContent {
			t.Fatalf("exact DELETE rejected: %s: %v", path, err)
		}
		_ = response.Body.Close()
	}
	for _, candidate := range []struct{ method, path string }{
		{http.MethodGet, "/v1.55/containers/" + runtimeID + "?force=1"},
		{http.MethodPost, "/v1.55/containers/" + runtimeID + "?force=1"},
		{http.MethodDelete, "/v1.55/containers/" + strings.Repeat("b", 64) + "?force=1"},
		{http.MethodDelete, "/v1.55/containers/" + runtimeID},
		{http.MethodDelete, "/v1.55/containers/" + runtimeID + "?force=1&v=1"},
		{http.MethodDelete, "/v1.55/volumes/volume-inputs?force=1"},
		{http.MethodDelete, "/v1.55/volumes/other"},
		{http.MethodDelete, "/v1.54/volumes/volume-inputs"},
		{http.MethodDelete, "/v1.55/volumes/volume-inputs/extra"},
	} {
		request := testCodingDeleteRequest(t, candidate.method, candidate.path)
		if _, err := transport.RoundTrip(request); !errors.Is(err, ErrInvalidCodingDeletion) {
			t.Fatalf("unreviewed Docker request admitted: %s %s: %v", candidate.method, candidate.path, err)
		}
	}
	for name, response := range map[string]*http.Response{
		"404":               codingSDKResponse(http.StatusNotFound, `{"message":"not found"}`, "application/json"),
		"fake-visible-body": codingSDKResponse(http.StatusNoContent, "unexpected", ""),
		"empty":             {StatusCode: http.StatusNoContent, Body: nil},
		"encoding": {StatusCode: http.StatusNoContent, Body: http.NoBody,
			Header: http.Header{"Content-Encoding": {"gzip"}}},
		"transfer": {StatusCode: http.StatusNoContent, Body: http.NoBody,
			Header: http.Header{"Transfer-Encoding": {"chunked"}}},
		"transfer-field": {StatusCode: http.StatusNoContent, Body: http.NoBody,
			TransferEncoding: []string{"chunked"}},
		"unknown-length": {StatusCode: http.StatusNoContent, Body: http.NoBody,
			ContentLength: -1},
		"nonzero-length-header": {StatusCode: http.StatusNoContent, Body: http.NoBody,
			Header: http.Header{"Content-Length": {"1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			transport.base = codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return response, nil
			})
			request := testCodingDeleteRequest(t, http.MethodDelete, "/v1.55/volumes/volume-inputs")
			if _, err := transport.RoundTrip(request); !errors.Is(err, ErrInvalidCodingDeletion) {
				t.Fatalf("uncertain deletion response admitted: %v", err)
			}
		})
	}
}

func TestCodingUnixDeletionUsesOneShotTypedExactTargets(t *testing.T) {
	runtimeID := strings.Repeat("a", 64)
	volumes := [3]string{"volume-inputs", "volume-workspace", "volume-outputs"}
	var observed []string
	bounded := &codingDeletionTransport{endpointHost: "/run/docker.sock",
		runtimeID: runtimeID, volumes: volumes,
		base: codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			observed = append(observed, request.Method+" "+request.URL.RequestURI())
			return &http.Response{StatusCode: http.StatusNoContent,
				Body: io.NopCloser(strings.NewReader("")), ContentLength: 0,
				Header: make(http.Header)}, nil
		})}
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: bounded}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	deletion := &codingUnixDeletion{api: api, scope: testControlDigest("a"),
		runtimeID: runtimeID, volumes: volumes, attempted: make(map[string]bool),
		confirmed: make(map[string]bool)}
	deletion.gate = make(chan struct{}, 1)
	deletion.gate <- struct{}{}
	defer api.Close()
	if deletion.ScopeDigest() != testControlDigest("a") {
		t.Fatal("frozen scope digest changed")
	}
	if deletion.RemoveVolume(t.Context(), volumes[0]) == nil ||
		deletion.RemoveRuntime(t.Context(), strings.Repeat("b", 64)) == nil {
		t.Fatal("wrong order or runtime ID reached Docker")
	}
	if err := deletion.RemoveRuntime(t.Context(), runtimeID); err != nil {
		t.Fatal(err)
	}
	if deletion.RemoveRuntime(t.Context(), runtimeID) == nil ||
		deletion.RemoveVolume(t.Context(), volumes[2]) == nil {
		t.Fatal("replay or skipped volume reached Docker")
	}
	for _, name := range volumes {
		if err := deletion.RemoveVolume(t.Context(), name); err != nil {
			t.Fatalf("exact whole volume %s: %v", name, err)
		}
	}
	want := []string{"DELETE /v1.55/containers/" + runtimeID + "?force=1",
		"DELETE /v1.55/volumes/volume-inputs",
		"DELETE /v1.55/volumes/volume-workspace",
		"DELETE /v1.55/volumes/volume-outputs"}
	if !reflect.DeepEqual(observed, want) {
		t.Fatalf("Docker mutation allowlist drift: %#v", observed)
	}
	if err := deletion.RemoveVolume(context.Background(), volumes[0]); !errors.Is(err, ErrInvalidCodingDeletion) {
		t.Fatalf("volume replayed: %v", err)
	}
}

func TestCodingUnixDeletionAdmissionAndCloseRespectShortCallerDeadline(t *testing.T) {
	runtimeID := strings.Repeat("a", 64)
	entered := make(chan struct{})
	release := make(chan struct{})
	requests := 0
	bounded := &codingDeletionTransport{endpointHost: "/run/docker.sock", runtimeID: runtimeID,
		volumes: [3]string{"volume-inputs", "volume-workspace", "volume-outputs"},
		base: codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			close(entered)
			select {
			case <-release:
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
			return codingSDKResponse(http.StatusNoContent, "", ""), nil
		})}
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: bounded}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	deletion := &codingUnixDeletion{gate: gate, api: api, transport: &http.Transport{},
		runtimeID: runtimeID, volumes: bounded.volumes,
		attempted: make(map[string]bool), confirmed: make(map[string]bool)}
	finished := make(chan error, 1)
	go func() { finished <- deletion.RemoveRuntime(t.Context(), runtimeID) }()
	<-entered
	begin := time.Now()
	short, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	if err := deletion.RemoveVolume(short, "volume-inputs"); !errors.Is(err, ErrInvalidCodingDeletion) {
		t.Fatalf("queued mutation ignored caller cancellation: %v", err)
	}
	cancel()
	if time.Since(begin) > 250*time.Millisecond {
		t.Fatal("queued mutation waited for network request instead of caller deadline")
	}
	closeCtx, stop := context.WithTimeout(t.Context(), 30*time.Millisecond)
	if err := deletion.CloseContext(closeCtx); !errors.Is(err, ErrInvalidCodingDeletion) {
		t.Fatalf("CloseContext ignored bounded gate wait: %v", err)
	}
	stop()
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("queued/canceled requests reached Docker: %d", requests)
	}
	if err := deletion.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
}
