package phase6terminalcleanup

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func testVaultRemote(status int, response string) *VaultRemote {
	now := time.Now().UTC()
	return &VaultRemote{token: &memoryTokenSource{token: []byte("s.terminal-test-token"),
		expiresAt: now.Add(time.Minute), now: func() time.Time { return now }},
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Host != operatorVaultHost+":"+operatorVaultPort ||
				request.Header.Get("X-Vault-Token") != "s.terminal-test-token" {
				return nil, errors.New("wrong fixed endpoint or in-memory token")
			}
			headers := make(http.Header)
			if status != http.StatusNoContent {
				headers.Set("Content-Type", "application/json")
			}
			return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(response))}, nil
		})}}
}

func TestVaultAccessorAbsenceRequiresExact400Not403404OrMalformedJSON(t *testing.T) {
	for _, value := range []struct {
		name     string
		status   int
		response string
		absent   bool
	}{
		{"exact invalid accessor", 400, `{"errors":["invalid accessor"]}`, true},
		{"forbidden", 403, `{"errors":["invalid accessor"]}`, false},
		{"not found", 404, `{"errors":["invalid accessor"]}`, false},
		{"wrong error", 400, `{"errors":["permission denied"]}`, false},
		{"duplicate", 400, `{"errors":["invalid accessor"],"errors":["invalid accessor"]}`, false},
		{"unknown", 400, `{"errors":["invalid accessor"],"other":true}`, false},
	} {
		t.Run(value.name, func(t *testing.T) {
			remote := testVaultRemote(value.status, value.response)
			_, err := remote.LookupAccessor(context.Background(), "accessor-12345678")
			if errors.Is(err, ErrAccessorAbsent) != value.absent || err == nil {
				t.Fatalf("lookup error = %v", err)
			}
		})
	}
}

func TestVaultRevokeRequiresNoContentAndDoesNotAcceptDeniedOrTimeout(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusForbidden, http.StatusNotFound} {
		remote := testVaultRemote(status, `{"errors":["denied"]}`)
		if status == http.StatusNoContent {
			remote = testVaultRemote(status, "")
		}
		err := remote.RevokeAccessor(context.Background(), "accessor-12345678")
		if (err == nil) != (status == http.StatusNoContent) {
			t.Fatalf("status %d revoke error = %v", status, err)
		}
	}
	remote := testVaultRemote(http.StatusNoContent, "")
	if err := remote.RevokeSelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.LookupAccessor(context.Background(), "accessor-12345678"); err == nil {
		t.Fatal("self-revoked memory token remained usable")
	}
}
