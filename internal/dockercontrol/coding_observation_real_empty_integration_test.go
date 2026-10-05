//go:build integration

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

	"github.com/moby/moby/client"
)

// This opt-in read-only component check is one bounded, no-retry batch. The
// endpoint is an explicit local test fixture, not an admitted production
// Profile/operator Docker scope. No create, delete, build or issuer call is
// reachable through the transport allowlist.
func TestCodingReadOnlyEmptyNamespaceRealDaemon(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CODING_EMPTY_OBSERVATION") != "1" {
		t.Skip("explicit read-only daemon observation not enabled")
	}
	host := os.Getenv("SANDBOX_RUNTIME_CODING_EMPTY_UNIX_ENDPOINT")
	if !strings.HasPrefix(host, "unix://") {
		t.Fatal("missing explicit local Unix test endpoint")
	}
	path := strings.TrimPrefix(host, "unix://")
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		t.Fatal("invalid local Unix test endpoint")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("local Unix test endpoint is not a live socket")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("cannot derive unique read-only effect")
	}
	_, plan, now := testReceiptAuthority(t)
	authority := otherReceiptAuthority(t, hex.EncodeToString(nonce[:]), 0, now)
	binding := testReceiptBinding(authority, plan)
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		t.Fatal("cannot derive private read-only resource set")
	}
	expected := map[CodingResourceRole]map[string]string{}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		labels, err := set.Labels(role)
		if err != nil {
			t.Fatal("cannot derive private read-only labels")
		}
		expected[role] = labels
	}
	ctx, cancel := context.WithTimeout(t.Context(), maxCodingInventoryDuration)
	defer cancel()
	base := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}
	defer base.CloseIdleConnections()
	total, okCount, missingCount, jsonMissing := 0, 0, 0, 0
	counting := codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if total >= 9 {
			return nil, ErrInvalidCodingObservationTransport
		}
		total++
		response, err := base.RoundTrip(request)
		if err != nil {
			return response, err
		}
		switch response.StatusCode {
		case http.StatusOK:
			okCount++
		case http.StatusNotFound:
			missingCount++
			if strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
				jsonMissing++
			}
		}
		return response, nil
	})
	bounded := &codingObservationTransport{base: counting, set: set,
		endpointHost: path, requestHost: client.DummyHost}
	api, err := client.New(client.WithHost(host), client.WithHTTPClient(&http.Client{
		Transport: bounded, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrInvalidCodingObservationTransport
		}}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal("cannot build frozen read-only SDK client")
	}
	defer api.Close()
	before, err := ObserveCodingDaemon(ctx, api, binding.EndpointScopeDigest)
	if err != nil || before.Platform != binding.RuntimePlatform {
		t.Logf("read-only GET summary: total=%d ok=%d missing=%d json_missing=%d", total, okCount, missingCount, jsonMissing)
		t.Fatal("initial daemon observation failed")
	}
	var inventory CodingResourceInventory
	if err := readCodingInventoryObjects(ctx, api, set, expected, &inventory); err != nil {
		t.Logf("read-only GET summary: total=%d ok=%d missing=%d json_missing=%d", total, okCount, missingCount, jsonMissing)
		t.Fatal("exact empty namespace or Docker response shape failed")
	}
	after, err := ObserveCodingDaemon(ctx, api, binding.EndpointScopeDigest)
	if err != nil || after != before || ctx.Err() != nil {
		t.Logf("read-only GET summary: total=%d ok=%d missing=%d json_missing=%d", total, okCount, missingCount, jsonMissing)
		t.Fatal("daemon identity/environment drifted during read-only batch")
	}
	for _, item := range inventory.Containers {
		if item.Present {
			t.Fatal("read-only effect namespace was not empty")
		}
	}
	for _, item := range inventory.Volumes {
		if item.Present {
			t.Fatal("read-only effect namespace was not empty")
		}
	}
	if total != 9 || okCount != 4 || missingCount != 5 || jsonMissing != 5 {
		t.Logf("read-only GET summary: total=%d ok=%d missing=%d json_missing=%d", total, okCount, missingCount, jsonMissing)
		t.Fatal("read-only batch was incomplete")
	}
	t.Logf("read-only GET summary: total=%d ok=%d missing=%d json_missing=%d platform=%s identity_digest=%s environment_digest=%s; no objects created or deleted",
		total, okCount, missingCount, jsonMissing, before.Platform, before.IdentityDigest, before.EnvironmentDigest)
}
