package providerapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

func TestBrowserRoutesRemainUncomposed(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
	handler := newReleaseGateHandler(t, identity, publicKey, guard)

	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/sandboxes/browser-sandbox-1/browser-sessions"},
		{http.MethodGet, "/v1/operations/browser-session-operation-1/browser-session"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://provider.test"+test.path, nil)
			state := verifiedState(t, material.client)
			request.TLS = &state
			if route, values, ok := matchProtectedRoute(request); ok || values != nil || route.operation != "" {
				t.Fatalf("browser route unexpectedly matched: route=%#v values=%v ok=%t", route, values, ok)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
				t.Fatalf("browser route response=%d body=%q, want empty 404", response.Code, response.Body.String())
			}
		})
	}
	if guard.Calls() != 0 {
		t.Fatalf("uncomposed browser routes consumed mutation guard %d times", guard.Calls())
	}
	for _, route := range allProtectedReleaseRoutes() {
		if route.operation == admission.OperationOpenBrowserSession || route.operation == admission.OperationReadBrowserSession {
			t.Fatalf("browser route was added to composed release routes: %#v", route)
		}
	}
}
