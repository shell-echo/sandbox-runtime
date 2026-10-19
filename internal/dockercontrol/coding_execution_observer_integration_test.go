//go:build integration && (darwin || linux)

package dockercontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

// An explicitly selected local fixture, not the production root-owned socket
// constructor. Only GETs are reachable. An absent fresh four-volume namespace
// must not produce completion. This does not run the Coding image.
func TestExecutionObserverEmptyNamespaceRealDaemon(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_EXECUTION_EMPTY_OBSERVATION") != "1" {
		t.Skip("explicit local read-only fixture required")
	}
	host := os.Getenv("SANDBOX_RUNTIME_CODING_EMPTY_UNIX_ENDPOINT")
	path := strings.TrimPrefix(host, "unix://")
	if !strings.HasPrefix(host, "unix://") || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		t.Fatal("invalid explicit fixture endpoint")
	}
	identity, err := os.Lstat(path)
	if err != nil || identity.Mode()&os.ModeSocket == 0 {
		t.Fatal("fixture socket unavailable")
	}
	check := func() bool {
		current, err := os.Lstat(path)
		return err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(identity, current)
	}
	f, b, a := executionFixture(t)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	a.AttemptID = "readonly-" + hex.EncodeToString(nonce[:])
	base := newCodingObservationHTTPTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !check() {
			return nil, ErrInvalidCodingUnixObserver
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if !check() {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, ErrInvalidCodingUnixObserver
		}
		return conn, err
	})
	defer base.CloseIdleConnections()
	calls, successes, missing := 0, 0, 0
	counting := codingRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls >= 11 {
			return nil, ErrInvalidCodingObservationTransport
		}
		calls++
		response, err := base.RoundTrip(r)
		if err == nil && response != nil {
			if response.StatusCode == 200 {
				successes++
			}
			if response.StatusCode == 404 {
				missing++
			}
		}
		return response, err
	})
	bounded := &executionObservationTransport{base: executionSocketTransport{base: counting, check: check}, endpointHost: path, binding: b, create: a, checkSocket: check}
	api, err := client.New(client.WithHost(host), client.WithAPIVersion("1.55"), client.WithHTTPClient(&http.Client{Transport: bounded, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport }}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	ctx, cancel := context.WithTimeout(t.Context(), maxCodingInventoryDuration)
	defer cancel()
	before, err := ObserveCodingDaemon(ctx, api, b.EndpointScopeDigest)
	if err != nil || before.Platform != b.Template.Image.Platform {
		t.Fatal("fixture platform/daemon rejected")
	}
	b.DaemonDigest, b.DaemonEnvironmentDigest = before.IdentityDigest, before.EnvironmentDigest
	a.BindingDigest = b.digest()
	bounded.binding, bounded.create = b, a
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	o := &executionUnixObserver{gate: gate, api: api, bounded: bounded, binding: b, create: a, documents: f.observer.documents, policy: []byte(executionFixturePolicy)}
	if proof, err := o.observeExecutionCreate(ctx, b, a, 2, executionTestDigest("f")); err == nil || proof.Protocol != "" {
		t.Fatal("empty namespace produced completion")
	}
	// The collector stops at the first missing volume. Exercise the remaining
	// three exact routes and both scoped lists without weakening that policy.
	resources := a.resources(b)
	for _, name := range resources.Volumes[1:] {
		if _, err := api.VolumeInspect(ctx, name, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("fresh volume was not absent")
		}
	}
	filters := make(client.Filters).Add("label", executionScopeLabel+"="+a.digest())
	containers, err := api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil || len(containers.Items) != 0 {
		t.Fatal("fresh container scope was not empty")
	}
	volumes, err := api.VolumeList(ctx, client.VolumeListOptions{Filters: filters})
	if err != nil || len(volumes.Items) != 0 || len(volumes.Warnings) != 0 {
		t.Fatal("fresh volume scope was not empty")
	}
	after, err := ObserveCodingDaemon(ctx, api, b.EndpointScopeDigest)
	if err != nil || after != before || ctx.Err() != nil || bounded.archiveID != "" || calls != 11 || successes != 5 || missing != 6 {
		t.Fatalf("incomplete read-only batch: requests=%d ok=%d missing=%d", calls, successes, missing)
	}
	t.Logf("fresh four-volume namespace rejected: %d bounded GETs, %d successful info/list reads, %d exact missing objects; no mutations or Coding execution", calls, successes, missing)
}

// Two bounded image reads through the same exact GET allowlist as the held
// observer. No container is created, and this cannot produce completion.
func TestExecutionObserverCandidateImageRealDaemon(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_EXECUTION_CANDIDATE_IMAGE_OBSERVATION") != "1" {
		t.Skip("explicit local candidate image read required")
	}
	host := os.Getenv("SANDBOX_RUNTIME_CODING_EMPTY_UNIX_ENDPOINT")
	path := strings.TrimPrefix(host, "unix://")
	if !strings.HasPrefix(host, "unix://") || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		t.Fatal("invalid fixture endpoint")
	}
	identity, err := os.Lstat(path)
	if err != nil || identity.Mode()&os.ModeSocket == 0 {
		t.Fatal("fixture socket unavailable")
	}
	check := func() bool {
		current, err := os.Lstat(path)
		return err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(identity, current)
	}
	f, b, a := executionFixture(t)
	if _, err := executionImageProof(b, f.observer.documents); err != nil {
		t.Fatal("original OCI platform/descriptor proof", err)
	}
	base := newCodingObservationHTTPTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !check() {
			return nil, ErrInvalidCodingUnixObserver
		}
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if !check() {
			if c != nil {
				_ = c.Close()
			}
			return nil, ErrInvalidCodingUnixObserver
		}
		return c, err
	})
	defer base.CloseIdleConnections()
	calls := 0
	counting := codingRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 2 || !strings.HasPrefix(r.URL.Path, "/v1.55/images/") {
			return nil, ErrInvalidCodingObservationTransport
		}
		return base.RoundTrip(r)
	})
	bounded := &executionObservationTransport{base: executionSocketTransport{base: counting, check: check}, endpointHost: path, binding: b, create: a, checkSocket: check}
	api, err := client.New(client.WithHost(host), client.WithAPIVersion("1.55"), client.WithHTTPClient(&http.Client{Transport: bounded, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport }}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	ctx, cancel := context.WithTimeout(t.Context(), maxCodingInventoryDuration)
	defer cancel()
	i := b.Template.Image
	plain, err := api.ImageInspect(ctx, i.Reference)
	if err != nil || !validExecutionSelectedImage(plain, b) {
		t.Fatal("local manifest/config selection rejected", err)
	}
	platform, ok := codingOCIPlatform(i.Platform)
	if !ok {
		t.Fatal("platform")
	}
	selected, err := api.ImageInspect(ctx, i.Reference, client.ImageInspectWithPlatform(&platform))
	if err != nil || !validExecutionSelectedImage(selected, b) || selected.ID != plain.ID || calls != 2 || !check() || ctx.Err() != nil {
		t.Fatal("platform selection rejected", err)
	}
	t.Logf("exact candidate manifest/config policy matches two read-only Docker queries; descriptor platform absent=%t; no four-volume/runtime acceptance", selected.Descriptor.Platform == nil)
}
