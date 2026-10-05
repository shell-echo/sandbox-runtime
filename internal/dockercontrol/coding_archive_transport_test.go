package dockercontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func codingArchiveFixture(t *testing.T, target string, mutate func(*tar.Header)) []byte {
	t.Helper()
	uid, gid := 57000, 58000
	mode := int64(0o770)
	if target == "/inputs" {
		uid, gid, mode = 0, 0, 0o555
	}
	var document bytes.Buffer
	writer := tar.NewWriter(&document)
	header := &tar.Header{Name: strings.TrimPrefix(target, "/"), Typeflag: tar.TypeDir,
		Mode: mode, Uid: uid, Gid: gid}
	if mutate != nil {
		mutate(header)
	}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return document.Bytes()
}

func codingArchiveResponse(t *testing.T, target string, document []byte) *http.Response {
	t.Helper()
	response := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(document)),
		ContentLength: int64(len(document)), Header: make(http.Header)}
	response.Header.Set("Content-Type", "application/x-tar")
	mode := os.FileMode(0o770)
	if target == "/inputs" {
		mode = 0o555
	}
	stat, err := json.Marshal(container.PathStat{Name: strings.TrimPrefix(target, "/"),
		Mode: os.ModeDir | mode, Size: 4096})
	if err != nil {
		t.Fatal(err)
	}
	response.Header.Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(stat))
	return response
}

func codingArchiveTransportFixture(t *testing.T, base http.RoundTripper) (*codingObservationTransport, string) {
	t.Helper()
	transport := codingTransportFixture(t, base)
	template := testVolumeTemplate(t)
	transport.endpointHost, transport.requestHost = "/run/docker.sock", client.DummyHost
	transport.archiveID = strings.Repeat("a", 64)
	transport.archiveUID = int(template.Slots[0].WorkloadUID)
	transport.archiveGID = int(template.Slots[0].WorkloadGID)
	transport.archiveMode = int64(template.VolumePrepMode)
	return transport, transport.archiveID
}

func TestCodingArchiveTransportOnlyThreeRootsThroughSDK(t *testing.T) {
	requests := 0
	base := codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		target := request.URL.Query().Get("path")
		return codingArchiveResponse(t, target, codingArchiveFixture(t, target, nil)), nil
	})
	transport, runtimeID := codingArchiveTransportFixture(t, base)
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: transport}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	for _, target := range []string{"/inputs", "/workspace", "/outputs"} {
		result, err := api.CopyFromContainer(context.Background(), runtimeID,
			client.CopyFromContainerOptions{SourcePath: target})
		if err != nil {
			t.Fatalf("fixed archive root rejected: %v", err)
		}
		if _, err := io.ReadAll(result.Content); err != nil {
			t.Fatal(err)
		}
		if err := result.Content.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if requests != 3 {
		t.Fatalf("exact archive reads = %d", requests)
	}
	for _, item := range []struct{ method, path string }{
		{http.MethodGet, "/v1.55/containers/" + runtimeID + "/archive?path=%2F"},
		{http.MethodGet, "/v1.55/containers/" + runtimeID + "/archive?path=%2Ftmp"},
		{http.MethodGet, "/v1.55/containers/" + runtimeID + "/archive?path=%2Fworkspace%2Fchild"},
		{http.MethodGet, "/v1.55/containers/" + strings.Repeat("b", 64) + "/archive?path=%2Fworkspace"},
		{http.MethodPut, "/v1.55/containers/" + runtimeID + "/archive?path=%2Fworkspace"},
	} {
		request := codingTransportRequest(t, item.method, item.path)
		request.URL.Host, request.Host = "/run/docker.sock", client.DummyHost
		if _, err := transport.RoundTrip(request); !errors.Is(err, ErrInvalidCodingObservationTransport) || requests != 3 {
			t.Fatalf("unreviewed archive route reached daemon: %v, requests=%d", err, requests)
		}
	}
}

func TestCodingArchiveTransportRejectsIncompleteOrForeignProof(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *http.Response){
		"wrong owner": func(t *testing.T, response *http.Response) {
			response.Body = io.NopCloser(bytes.NewReader(codingArchiveFixture(t, "/workspace", func(h *tar.Header) { h.Uid++ })))
		},
		"nonzero tail": func(t *testing.T, response *http.Response) {
			document := codingArchiveFixture(t, "/workspace", nil)
			document[len(document)-1] = 1
			response.Body = io.NopCloser(bytes.NewReader(document))
		},
		"extra entry": func(t *testing.T, response *http.Response) {
			var document bytes.Buffer
			writer := tar.NewWriter(&document)
			_ = writer.WriteHeader(&tar.Header{Name: "workspace", Typeflag: tar.TypeDir,
				Mode: 0o770, Uid: 57000, Gid: 58000})
			_ = writer.WriteHeader(&tar.Header{Name: "workspace/child", Typeflag: tar.TypeReg, Size: 0})
			_ = writer.Close()
			response.Body = io.NopCloser(bytes.NewReader(document.Bytes()))
			response.ContentLength = int64(document.Len())
		},
		"wrong stat": func(_ *testing.T, response *http.Response) {
			response.Header.Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(
				[]byte(`{"name":"other","size":4096,"mode":2147484144,"linkTarget":""}`)))
		},
		"duplicate path stat": func(_ *testing.T, response *http.Response) {
			response.Header.Add("X-Docker-Container-Path-Stat", response.Header.Get("X-Docker-Container-Path-Stat"))
		},
		"special mode bit": func(t *testing.T, response *http.Response) {
			stat, err := json.Marshal(container.PathStat{Name: "workspace", Mode: os.ModeDir | os.ModeSetuid | 0o770, Size: 4096})
			if err != nil {
				t.Fatal(err)
			}
			response.Header.Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(stat))
		},
		"oversized": func(_ *testing.T, response *http.Response) {
			response.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", maxCodingArchiveResponseBytes+1)))
			response.ContentLength = -1
		},
		"truncated": func(_ *testing.T, response *http.Response) {
			response.ContentLength++
		},
		"bad media": func(_ *testing.T, response *http.Response) {
			response.Header.Set("Content-Type", "application/json")
		},
		"bad status": func(_ *testing.T, response *http.Response) {
			response.StatusCode = http.StatusNotFound
		},
	} {
		t.Run(name, func(t *testing.T) {
			transport, runtimeID := codingArchiveTransportFixture(t, codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				response := codingArchiveResponse(t, "/workspace", codingArchiveFixture(t, "/workspace", nil))
				mutate(t, response)
				return response, nil
			}))
			api, err := client.New(client.WithHost("unix:///run/docker.sock"),
				client.WithHTTPClient(&http.Client{Transport: transport}), client.WithAPIVersion("1.55"))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			_, err = api.CopyFromContainer(t.Context(), runtimeID,
				client.CopyFromContainerOptions{SourcePath: "/workspace"})
			if err == nil || cerrdefs.IsNotFound(err) {
				t.Fatalf("unsafe archive became accepted/absence: %v", err)
			}
		})
	}
}

func TestCodingArchiveTransportCancellationNeverBecomesProof(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/x-tar")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()
	transport, runtimeID := codingArchiveTransportFixture(t, http.DefaultTransport)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		server.URL+"/v1.55/containers/"+runtimeID+"/archive?path=%2Fworkspace", nil)
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
		t.Fatal("archive stream did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrInvalidCodingObservationTransport) || cerrdefs.IsNotFound(err) {
			t.Fatalf("cancelled archive became completion/absence: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled archive read did not return")
	}
}
