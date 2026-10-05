package dockercontrol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

var ErrInvalidCodingDeletion = errors.New("invalid private Coding exact Unix deletion")

// codingDeletionTransport is a separate, mutation-only capability. The
// completion/inventory observer remains GET-only. No Docker method other
// than one exact runtime DELETE and three whole-volume DELETEs can reach its
// frozen Unix dialer. A lost, malformed, non-204 or net/http-visible non-empty
// response is uncertain and cannot authorize a Released receipt. HTTP's 204
// normalization cannot prove absence of raw late wire bytes or daemon
// quiescence; the subsequent independent inventories are also required.
type codingDeletionTransport struct {
	base         http.RoundTripper
	endpointHost string
	runtimeID    string
	volumes      [3]string
}

func (t *codingDeletionTransport) allowed(request *http.Request) bool {
	if t == nil || request == nil || request.Context().Err() != nil ||
		request.Method != http.MethodDelete || request.URL == nil ||
		request.URL.Scheme != "http" || request.URL.Host != t.endpointHost ||
		request.Host != client.DummyHost || request.URL.User != nil ||
		request.URL.Opaque != "" || request.URL.ForceQuery || request.URL.RawPath != "" ||
		request.URL.EscapedPath() != request.URL.Path || request.URL.Fragment != "" ||
		request.ContentLength > 0 || (request.Body != nil && request.Body != http.NoBody) {
		return false
	}
	if request.URL.Path == "/v1.55/containers/"+t.runtimeID &&
		request.URL.RawQuery == "force=1" && codingArchiveRuntimeID.MatchString(t.runtimeID) {
		return true
	}
	for _, name := range t.volumes {
		if name != "" && request.URL.Path == "/v1.55/volumes/"+name &&
			request.URL.RawQuery == "" {
			return true
		}
	}
	return false
}

func (t *codingDeletionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil || !t.allowed(request) {
		return nil, ErrInvalidCodingDeletion
	}
	response, err := t.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrInvalidCodingDeletion
	}
	if response.StatusCode != http.StatusNoContent || response.ContentLength != 0 ||
		len(response.TransferEncoding) != 0 ||
		response.Header.Get("Content-Encoding") != "" ||
		response.Header.Get("Transfer-Encoding") != "" {
		_ = response.Body.Close()
		return nil, ErrInvalidCodingDeletion
	}
	for key, values := range response.Header {
		if strings.EqualFold(key, "Content-Length") {
			if len(values) != 1 || values[0] != "0" {
				_ = response.Body.Close()
				return nil, ErrInvalidCodingDeletion
			}
		}
	}
	// Require an empty body as exposed by net/http. For a real 204 response,
	// net/http may normalize the body to NoBody, so this is not a raw-wire or
	// daemon-quiescence assertion.
	document, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || request.Context().Err() != nil || len(document) != 0 {
		return nil, ErrInvalidCodingDeletion
	}
	response.Body = io.NopCloser(bytes.NewReader(nil))
	response.ContentLength = 0
	return response, nil
}

// codingUnixDeletion is not a general Docker client. Construction requires
// the same frozen endpoint scope and exact effect-derived volume names. The
// runtime ID is independently checked against the sealed completion proof
// and the pre-delete inventory by runCodingExactCleanup before first use.
type codingUnixDeletion struct {
	gate      chan struct{}
	api       *client.Client
	transport *http.Transport
	scope     string
	runtimeID string
	volumes   [3]string
	attempted map[string]bool
	confirmed map[string]bool
}

func newCodingUnixDeletion(endpoint codingBoundUnixEndpoint, binding CodingReceiptBinding,
	authority CodingCreateAuthority, runtimeID string) (*codingUnixDeletion, error) {
	if binding.Validate() != nil || endpoint.scopeDigest != binding.EndpointScopeDigest ||
		verifyCodingUnixSocket(endpoint.path) != nil || !codingArchiveRuntimeID.MatchString(runtimeID) {
		return nil, ErrInvalidCodingDeletion
	}
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		return nil, ErrInvalidCodingDeletion
	}
	var volumes [3]string
	for index, role := range [3]CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		volumes[index], err = set.VolumeName(role)
		if err != nil {
			return nil, ErrInvalidCodingDeletion
		}
	}
	base := newCodingObservationHTTPTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if verifyCodingUnixSocket(endpoint.path) != nil {
			return nil, ErrInvalidCodingDeletion
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", endpoint.path)
	})
	bounded := &codingDeletionTransport{base: base, endpointHost: endpoint.path,
		runtimeID: runtimeID, volumes: volumes}
	api, err := client.New(client.WithHost("unix://"+endpoint.path),
		client.WithHTTPClient(&http.Client{Transport: bounded,
			Timeout:       maxCodingObservationRequestDuration,
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingDeletion }}),
		client.WithAPIVersion("1.55"))
	if err != nil {
		base.CloseIdleConnections()
		return nil, ErrInvalidCodingDeletion
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &codingUnixDeletion{gate: gate, api: api, transport: base, scope: endpoint.scopeDigest,
		runtimeID: runtimeID, volumes: volumes, attempted: make(map[string]bool, 4),
		confirmed: make(map[string]bool, 4)}, nil
}

func (d *codingUnixDeletion) ScopeDigest() string {
	if d == nil {
		return ""
	}
	return d.scope
}

func (d *codingUnixDeletion) RemoveRuntime(ctx context.Context, id string) error {
	if d == nil || ctx == nil || ctx.Err() != nil || id != d.runtimeID {
		return ErrInvalidCodingDeletion
	}
	bounded, cancel := context.WithTimeout(ctx, maxCodingObservationRequestDuration)
	defer cancel()
	if !d.acquire(bounded) {
		return ErrInvalidCodingDeletion
	}
	defer d.release()
	if d.api == nil || d.attempted["runtime"] {
		return ErrInvalidCodingDeletion
	}
	d.attempted["runtime"] = true
	_, err := d.api.ContainerRemove(bounded, id, client.ContainerRemoveOptions{Force: true})
	if err != nil || bounded.Err() != nil {
		return ErrInvalidCodingDeletion
	}
	d.confirmed["runtime"] = true
	return nil
}

func (d *codingUnixDeletion) RemoveVolume(ctx context.Context, name string) error {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalidCodingDeletion
	}
	bounded, cancel := context.WithTimeout(ctx, maxCodingObservationRequestDuration)
	defer cancel()
	if !d.acquire(bounded) {
		return ErrInvalidCodingDeletion
	}
	defer d.release()
	if d.api == nil || !d.confirmed["runtime"] || d.attempted[name] {
		return ErrInvalidCodingDeletion
	}
	index := -1
	for current, want := range d.volumes {
		if want == name {
			index = current
		}
	}
	if index < 0 || index > 0 && !d.confirmed[d.volumes[index-1]] {
		return ErrInvalidCodingDeletion
	}
	d.attempted[name] = true
	_, err := d.api.VolumeRemove(bounded, name, client.VolumeRemoveOptions{})
	if err != nil || bounded.Err() != nil {
		return ErrInvalidCodingDeletion
	}
	d.confirmed[name] = true
	return nil
}

func (d *codingUnixDeletion) CloseContext(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrInvalidCodingDeletion
	}
	if !d.acquire(ctx) {
		return ErrInvalidCodingDeletion
	}
	defer d.release()
	if d.api == nil {
		return nil
	}
	d.transport.CloseIdleConnections()
	err := d.api.Close()
	d.api = nil
	if err != nil || ctx.Err() != nil {
		return ErrInvalidCodingDeletion
	}
	return nil
}

func (d *codingUnixDeletion) acquire(ctx context.Context) bool {
	if d == nil || d.gate == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-d.gate:
		if ctx.Err() != nil {
			d.release()
			return false
		}
		return true
	}
}

func (d *codingUnixDeletion) release() { d.gate <- struct{}{} }

func (d *codingUnixDeletion) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.CloseContext(ctx)
}

var _ codingExactDeletion = (*codingUnixDeletion)(nil)
