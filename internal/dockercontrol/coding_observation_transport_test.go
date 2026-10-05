package dockercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type codingRoundTripFunc func(*http.Request) (*http.Response, error)

func (f codingRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func codingTransportFixture(t *testing.T, base http.RoundTripper) *codingObservationTransport {
	t.Helper()
	a, plan, _ := testReceiptAuthority(t)
	set, err := NewCodingResourceSet(testReceiptBinding(a, plan), a)
	if err != nil {
		t.Fatal(err)
	}
	return &codingObservationTransport{base: base, set: set,
		endpointHost: "docker.localhost", requestHost: "docker.localhost"}
}

func codingTransportRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	parsed, err := url.Parse("http://docker.localhost" + path)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{Method: method, URL: parsed, Host: parsed.Host, Header: make(http.Header)}
}

func codingTransportResponse(status int, body string, length int64) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)),
		ContentLength: length, Header: make(http.Header)}
}

func TestCodingObservationActualHTTPParserRejectsOversizedHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Oversized-Daemon-Header", strings.Repeat("x", 17<<10))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	defer server.Close()
	base := newCodingObservationHTTPTransport((&net.Dialer{}).DialContext)
	defer base.CloseIdleConnections()
	bounded := codingTransportFixture(t, base)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1.55/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	bounded.endpointHost, bounded.requestHost = request.URL.Host, request.Host
	if _, err := bounded.RoundTrip(request); !errors.Is(err, ErrInvalidCodingObservationTransport) || cerrdefs.IsNotFound(err) {
		t.Fatalf("oversized HTTP response headers became evidence/absence: %v", err)
	}
}

func TestCodingObservationTransportPreflightsExactReadOnlyPaths(t *testing.T) {
	calls := 0
	transport := codingTransportFixture(t, codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body := `{}`
		if request.URL.Path == "/v1.55/containers/json" {
			body = `[]`
		} else if request.URL.Path == "/v1.55/volumes" {
			body = `{"Volumes":[],"Warnings":null}`
		}
		return codingTransportResponse(http.StatusOK, body, int64(len(body))), nil
	}))
	prep, _ := transport.set.ContainerName(CodingPreparationRole)
	runtime, _ := transport.set.ContainerName(CodingRuntimeRole)
	inputs, _ := transport.set.VolumeName(CodingInputsRole)
	for _, path := range []string{"/v1.55/info", "/v1.55/containers/" + prep + "/json",
		"/v1.55/containers/" + runtime + "/json", "/v1.55/volumes/" + inputs} {
		response, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet, path))
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("reviewed path %s rejected: %v", path, err)
		}
	}
	filters := make(client.Filters).Add("label", codingEffectLabel+"="+transport.set.effectID)
	encoded, err := json.Marshal(filters)
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range []struct {
		path string
		all  bool
	}{{"/v1.55/containers/json", true}, {"/v1.55/volumes", false}} {
		query := url.Values{"filters": {string(encoded)}}
		if options.all {
			query.Set("all", "1")
		}
		response, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet, options.path+"?"+query.Encode()))
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("reviewed list %s rejected: %v", options.path, err)
		}
	}
	allowedCalls := calls
	for _, request := range []struct{ method, path string }{
		{http.MethodPost, "/v1.55/containers/create"},
		{http.MethodDelete, "/v1.55/containers/" + prep},
		{http.MethodGet, "/v1.55/images/json"},
		{http.MethodGet, "/v1.55/containers/unrelated/json"},
		{http.MethodGet, "/v1.55/volumes/unrelated"},
		{http.MethodGet, "/v1.55/info?debug=1"},
		{http.MethodGet, "/v1.55/containers/json?all=1"},
		{http.MethodGet, "/v1.54/info"},
		{http.MethodGet, "/v1.55/containers/../json"},
		{http.MethodGet, "/v1.55/containers/a%2Fb/json"},
	} {
		if _, err := transport.RoundTrip(codingTransportRequest(t, request.method, request.path)); !errors.Is(err, ErrInvalidCodingObservationTransport) || calls != allowedCalls {
			t.Fatalf("unreviewed request reached daemon: %s %s, error=%v calls=%d", request.method, request.path, err, calls)
		}
	}
	for name, mutate := range map[string]func(*http.Request){
		"foreign endpoint":    func(request *http.Request) { request.URL.Host = "other.localhost" },
		"foreign host header": func(request *http.Request) { request.Host = "other.localhost" },
		"https scheme":        func(request *http.Request) { request.URL.Scheme = "https" },
		"userinfo":            func(request *http.Request) { request.URL.User = url.User("operator") },
		"force query":         func(request *http.Request) { request.URL.ForceQuery = true },
	} {
		t.Run(name, func(t *testing.T) {
			request := codingTransportRequest(t, http.MethodGet, "/v1.55/info")
			mutate(request)
			if _, err := transport.RoundTrip(request); !errors.Is(err, ErrInvalidCodingObservationTransport) || calls != allowedCalls {
				t.Fatalf("foreign endpoint request reached daemon: %v, calls=%d", err, calls)
			}
		})
	}
}

func TestCodingObservationTransportBounds404BeforeSDK(t *testing.T) {
	transport := codingTransportFixture(t, codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return codingTransportResponse(http.StatusNotFound,
			strings.Repeat("x", MaxCodingObservationResponseBytes+1), -1), nil
	}))
	prep, _ := transport.set.ContainerName(CodingPreparationRole)
	request := codingTransportRequest(t, http.MethodGet, "/v1.55/containers/"+prep+"/json")
	if _, err := transport.RoundTrip(request); !errors.Is(err, ErrInvalidCodingObservationTransport) || cerrdefs.IsNotFound(err) {
		t.Fatalf("oversized 404 became absence: %v", err)
	}
	// The actual SDK must also see a non-NotFound error; the transport returns
	// no synthetic 404/empty response for its error classifier to misread.
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: transport}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	transport.endpointHost, transport.requestHost = "/run/docker.sock", client.DummyHost
	if _, err := api.ContainerInspect(context.Background(), prep, client.ContainerInspectOptions{}); err == nil || cerrdefs.IsNotFound(err) {
		t.Fatalf("SDK interpreted oversized 404 as absence: %v", err)
	}
}

func TestCodingObservationTransportAllowsActualSDKInventoryRequests(t *testing.T) {
	calls := 0
	transport := codingTransportFixture(t, codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body := `{}`
		if request.URL.Path == "/v1.55/containers/json" {
			body = `[]`
		} else if request.URL.Path == "/v1.55/volumes" {
			body = `{"Volumes":[],"Warnings":null}`
		}
		return codingTransportResponse(http.StatusOK, body, int64(len(body))), nil
	}))
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: transport}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	transport.endpointHost, transport.requestHost = "/run/docker.sock", client.DummyHost
	ctx := context.Background()
	if _, err := api.Info(ctx, client.InfoOptions{}); err != nil {
		t.Fatalf("SDK Info request rejected: %v", err)
	}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		name, _ := transport.set.ContainerName(role)
		if _, err := api.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); err != nil {
			t.Fatalf("SDK container inspect rejected: %v", err)
		}
	}
	for _, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := transport.set.VolumeName(role)
		if _, err := api.VolumeInspect(ctx, name, client.VolumeInspectOptions{}); err != nil {
			t.Fatalf("SDK volume inspect rejected: %v", err)
		}
	}
	filters := make(client.Filters).Add("label", codingEffectLabel+"="+transport.set.effectID)
	if _, err := api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters}); err != nil {
		t.Fatalf("SDK container list rejected: %v", err)
	}
	if _, err := api.VolumeList(ctx, client.VolumeListOptions{Filters: filters}); err != nil {
		t.Fatalf("SDK volume list rejected: %v", err)
	}
	if calls != 8 {
		t.Fatalf("expected exactly eight bounded SDK reads, got %d", calls)
	}
}

func TestCodingObservationImageInspectSDKRequestScope(t *testing.T) {
	template := testVolumeTemplate(t)
	requests := 0
	base := codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return codingTransportResponse(http.StatusOK, `{}`, 2), nil
	})
	transport := codingTransportFixture(t, base)
	transport.endpointHost, transport.requestHost = "/run/docker.sock", client.DummyHost
	transport.imageRef, transport.platform = template.Image.Reference, template.Image.Platform
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: transport}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if _, err := api.ImageInspect(t.Context(), template.Image.Reference); err != nil {
		t.Fatal(err)
	}
	if _, err := api.ImageInspect(t.Context(), template.Image.Reference,
		client.ImageInspectWithPlatform(&ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"})); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("image inspect SDK requests = %d", requests)
	}
	for _, path := range []string{
		"/v1.55/images/other:tag/json",
		"/v1.55/images/" + template.Image.Reference + "/json?platform=other",
		"/v1.55/images/" + template.Image.Reference + "/json?manifests=1",
	} {
		request := codingTransportRequest(t, http.MethodGet, path)
		request.URL.Host, request.Host = "/run/docker.sock", client.DummyHost
		if _, err := transport.RoundTrip(request); !errors.Is(err, ErrInvalidCodingObservationTransport) || requests != 2 {
			t.Fatalf("unapproved image read reached daemon: %v, requests=%d", err, requests)
		}
	}
}

func TestCodingObservationTransportRejectsTruncationMalformedAndReadError(t *testing.T) {
	for name, result := range map[string]func() *http.Response{
		"declared oversized": func() *http.Response { return codingTransportResponse(404, `{}`, MaxCodingObservationResponseBytes+1) },
		"truncated":          func() *http.Response { return codingTransportResponse(200, `{}`, 3) },
		"malformed success":  func() *http.Response { return codingTransportResponse(200, `{`, -1) },
		"chunked oversized": func() *http.Response {
			return codingTransportResponse(404, strings.Repeat("x", MaxCodingObservationResponseBytes+1), -1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			transport := codingTransportFixture(t, codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return result(), nil
			}))
			if _, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet, "/v1.55/info")); !errors.Is(err, ErrInvalidCodingObservationTransport) {
				t.Fatalf("unsafe response accepted: %v", err)
			}
		})
	}
	transport := codingTransportFixture(t, codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		response := codingTransportResponse(404, `{"message":"not found"}`, -1)
		response.Header.Set("Content-Type", "application/json")
		return response, nil
	}))
	containerName, _ := transport.set.ContainerName(CodingPreparationRole)
	response, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet,
		"/v1.55/containers/"+containerName+"/json"))
	if err != nil || response.StatusCode != 404 {
		t.Fatalf("bounded genuine 404 rejected: %v", err)
	}
}

type codingErrorBody struct{ err error }

func (b codingErrorBody) Read([]byte) (int, error) { return 0, b.err }
func (b codingErrorBody) Close() error             { return nil }

type codingCloseErrorBody struct{ io.Reader }

func (codingCloseErrorBody) Close() error { return errors.New("broken close") }

func TestCodingObservationTransportReadErrorAndCancellationNeverAbsence(t *testing.T) {
	transport := codingTransportFixture(t, codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		response := codingTransportResponse(404, "", -1)
		response.Body = codingErrorBody{err: errors.New("broken daemon stream")}
		return response, nil
	}))
	if _, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet, "/v1.55/info")); !errors.Is(err, ErrInvalidCodingObservationTransport) {
		t.Fatalf("read error became absence: %v", err)
	}
	transport = codingTransportFixture(t, codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		response := codingTransportResponse(404, "", -1)
		response.Body = codingCloseErrorBody{Reader: strings.NewReader(`{"message":"not found"}`)}
		return response, nil
	}))
	if _, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet, "/v1.55/info")); !errors.Is(err, ErrInvalidCodingObservationTransport) {
		t.Fatalf("close error became absence: %v", err)
	}
	calls := 0
	transport = codingTransportFixture(t, codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return codingTransportResponse(200, `{}`, -1), nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet, "/v1.55/info").WithContext(ctx)); !errors.Is(err, ErrInvalidCodingObservationTransport) || calls != 0 {
		t.Fatalf("cancelled request reached transport: %v, calls=%d", err, calls)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if _, err := transport.RoundTrip(codingTransportRequest(t, http.MethodGet, "/v1.55/info").WithContext(ctx)); !errors.Is(err, ErrInvalidCodingObservationTransport) || calls != 0 {
		t.Fatalf("expired request reached transport: %v, calls=%d", err, calls)
	}
}

func TestCodingObservationTransportSlow404CancellationNeverAbsence(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.(http.Flusher).Flush()
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()
	transport := codingTransportFixture(t, http.DefaultTransport)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1.55/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport.endpointHost, transport.requestHost = request.URL.Host, request.Host
	result := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(request)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not start the slow response")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrInvalidCodingObservationTransport) || cerrdefs.IsNotFound(err) {
			t.Fatalf("cancelled slow 404 became absence: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled response read did not return")
	}
}
