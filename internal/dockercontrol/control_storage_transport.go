package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

// Separate from the execution-scoped observer: this read surface intentionally
// sees ALL daemon consumers. It never exposes arbitrary endpoints or mutations.
type controlStorageTransport struct {
	base        http.RoundTripper
	host        string
	binding     controlStorageBinding
	ids         map[string]bool
	checkSocket func() bool
}

func (t *controlStorageTransport) allowed(r *http.Request) bool {
	if t == nil || r == nil || r.URL == nil || r.Method != "GET" || r.URL.Scheme != "http" || r.URL.Host != t.host || t.host == "" || r.Host != client.DummyHost ||
		r.URL.User != nil || r.URL.Opaque != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.URL.Fragment != "" ||
		r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) {
		return false
	}
	if r.URL.Path == "/v1.55/containers/json" {
		return r.URL.RawQuery == "all=1"
	}
	if r.URL.RawQuery != "" {
		return false
	}
	switch r.URL.Path {
	case "/v1.55/info", "/v1.55/volumes", "/v1.55/volumes/" + t.binding.Storage.StorageID, "/v1.55/volumes/" + t.binding.backingVolume():
		return true
	}
	if t.binding.profileSource != nil {
		for _, m := range t.binding.profileSource.Control.Mounts {
			if m.Kind != "daemon_socket" && r.URL.Path == "/v1.55/volumes/"+t.binding.profileVolume(m) {
				return true
			}
		}
		for _, n := range t.binding.profileSource.Networks {
			if r.URL.Path == "/v1.55/networks/"+t.binding.profileNetwork(n.Network.Name) {
				return true
			}
		}
	}
	for id := range t.ids {
		if r.URL.Path == "/v1.55/containers/"+id+"/json" {
			return true
		}
	}
	return false
}

func (t *controlStorageTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.allowed(r) || t.base == nil || r.Context().Err() != nil || (t.checkSocket != nil && !t.checkSocket()) {
		return nil, ErrInvalidCodingObservationTransport
	}
	if r.URL.Path == "/v1.55/info" {
		t.ids = nil
	}
	response, err := t.base.RoundTrip(r)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrInvalidCodingObservationTransport
	}
	closed := false
	defer func() {
		if !closed {
			_ = response.Body.Close()
		}
	}()
	if response.StatusCode != 200 || response.ContentLength > MaxCodingObservationResponseBytes {
		return nil, ErrInvalidCodingObservationTransport
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxCodingObservationResponseBytes+1))
	closeErr := response.Body.Close()
	closed = true
	if err != nil || closeErr != nil || (t.checkSocket != nil && !t.checkSocket()) || r.Context().Err() != nil || len(data) > MaxCodingObservationResponseBytes ||
		(response.ContentLength >= 0 && response.ContentLength != int64(len(data))) || !json.Valid(data) || !executionJSONUnambiguous(data) {
		return nil, ErrInvalidCodingObservationTransport
	}
	if r.URL.Path == "/v1.55/containers/json" {
		var list []struct {
			ID string `json:"Id"`
		}
		if len(data) == 0 || bytes.TrimSpace(data)[0] != '[' || json.Unmarshal(data, &list) != nil || len(list) > maxControlStorageContainers {
			return nil, ErrInvalidCodingObservationTransport
		}
		ids := map[string]bool{}
		for _, c := range list {
			if !codingArchiveRuntimeID.MatchString(c.ID) || ids[c.ID] {
				return nil, ErrInvalidCodingObservationTransport
			}
			ids[c.ID] = true
		}
		t.ids = ids
	} else {
		fields, ok := codingJSONObjectFields(data)
		if !ok {
			return nil, ErrInvalidCodingObservationTransport
		}
		if r.URL.Path == "/v1.55/volumes" {
			var v struct {
				Volumes  []json.RawMessage
				Warnings []string
			}
			if !validCodingVolumeList(data) || json.Unmarshal(data, &v) != nil || len(v.Volumes) > maxControlStorageVolumes || len(v.Warnings) != 0 {
				return nil, ErrInvalidCodingObservationTransport
			}
		} else if strings.HasPrefix(r.URL.Path, "/v1.55/containers/") {
			for _, name := range []string{"Id", "Name", "Config", "HostConfig", "State", "Mounts", "Image"} {
				if _, ok := fields[name]; !ok {
					return nil, ErrInvalidCodingObservationTransport
				}
			}
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	response.Header.Set("Content-Length", strconv.Itoa(len(data)))
	return response, nil
}

type controlStorageUnixObserver struct {
	gate      chan struct{}
	api       *client.Client
	transport *http.Transport
	binding   controlStorageBinding
	store     *controlstorage.Store // caller owns lifetime; closing it fails observation
}

func newControlStorageUnixObserver(endpoint codingBoundUnixEndpoint, b controlStorageBinding, store *controlstorage.Store) (*controlStorageUnixObserver, error) {
	if store == nil {
		return nil, ErrInvalidCodingUnixObserver
	}
	return openControlStorageUnixObserver(endpoint, b, store)
}
func openControlStorageUnixObserver(endpoint codingBoundUnixEndpoint, b controlStorageBinding, store *controlstorage.Store) (*controlStorageUnixObserver, error) {
	if b.validate() != nil {
		return nil, ErrInvalidCodingUnixObserver
	}
	return openControlStorageReadAPI(endpoint, b, store)
}

// Also used for the source session's bounded daemon/volume bootstrap. It
// exposes only the existing GET allowlist; the caller derives b from source.
func openControlStorageReadAPI(endpoint codingBoundUnixEndpoint, b controlStorageBinding, store *controlstorage.Store) (*controlStorageUnixObserver, error) {
	if endpoint.scopeDigest != b.EndpointScopeDigest || verifyCodingUnixSocket(endpoint.path) != nil {
		return nil, ErrInvalidCodingUnixObserver
	}
	identity, err := os.Lstat(endpoint.path)
	if err != nil {
		return nil, ErrInvalidCodingUnixObserver
	}
	check := func() bool {
		current, err := os.Lstat(endpoint.path)
		return err == nil && os.SameFile(identity, current) && verifyCodingUnixSocket(endpoint.path) == nil
	}
	base := newCodingObservationHTTPTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !check() {
			return nil, ErrInvalidCodingUnixObserver
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", endpoint.path)
		if err != nil {
			return nil, err
		}
		if !check() {
			_ = conn.Close()
			return nil, ErrInvalidCodingUnixObserver
		}
		return conn, nil
	})
	bounded := &controlStorageTransport{base: executionSocketTransport{base: base, check: check}, host: endpoint.path, binding: b, checkSocket: check}
	api, err := client.New(client.WithHost("unix://"+endpoint.path), client.WithAPIVersion("1.55"), client.WithHTTPClient(&http.Client{Transport: bounded, Timeout: maxCodingObservationRequestDuration, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport }}))
	if err != nil {
		base.CloseIdleConnections()
		return nil, ErrInvalidCodingUnixObserver
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &controlStorageUnixObserver{gate: gate, api: api, transport: base, binding: b, store: store}, nil
}

func (o *controlStorageUnixObserver) acquire(ctx context.Context) bool {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-o.gate:
		if ctx.Err() == nil {
			return true
		}
		o.gate <- struct{}{}
		return false
	}
}
func (o *controlStorageUnixObserver) Observe(ctx context.Context) (controlStorageObservation, error) {
	if !o.acquire(ctx) {
		return controlStorageObservation{}, ErrInvalidCodingInventory
	}
	defer func() { o.gate <- struct{}{} }()
	return observeControlStorage(ctx, o.api, o.store, o.binding)
}
func (o *controlStorageUnixObserver) CloseContext(ctx context.Context) error {
	if !o.acquire(ctx) {
		return ErrInvalidCodingUnixObserver
	}
	defer func() { o.gate <- struct{}{} }()
	if o.api == nil {
		return nil
	}
	o.transport.CloseIdleConnections()
	err := o.api.Close()
	o.api = nil
	return err
}
