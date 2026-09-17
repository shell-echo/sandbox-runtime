package qualificationoperator

import (
	"net/http"
	"testing"
)

func TestGatewayConnectReadFailureClassifiesOnlyMissingCredentialAsRejection(t *testing.T) {
	t.Parallel()
	status, transport := gatewayConnectReadFailure("")
	if status != http.StatusForbidden || transport != "gateway-upgrade-rejected" {
		t.Fatalf("missing credential classification = (%d, %q)", status, transport)
	}
	status, transport = gatewayConnectReadFailure("controller_a")
	if status != http.StatusBadGateway || transport != "transport-error" {
		t.Fatalf("authenticated transport failure classification = (%d, %q)", status, transport)
	}
}

func TestValidProviderPollingState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		event HTTPObservation
		final bool
		want  bool
	}{
		{name: "operation pending", event: HTTPObservation{Route: "/v1/operations/{operation_id}", StatusCode: 200, ResponseJSON: map[string]any{"status": "running"}}, want: true},
		{name: "operation terminal", event: HTTPObservation{Route: "/v1/operations/{operation_id}", StatusCode: 200, ResponseJSON: map[string]any{"status": "succeeded"}}, final: true, want: true},
		{name: "operation pending final", event: HTTPObservation{Route: "/v1/operations/{operation_id}", StatusCode: 200, ResponseJSON: map[string]any{"status": "accepted"}}, final: true},
		{name: "operation terminal intermediate", event: HTTPObservation{Route: "/v1/operations/{operation_id}", StatusCode: 200, ResponseJSON: map[string]any{"status": "cancelled"}}},
		{name: "sandbox provisioning", event: HTTPObservation{Route: "/v1/sandboxes/{sandbox_id}", StatusCode: 200, ResponseJSON: map[string]any{"observed_state": "provisioning"}}, want: true},
		{name: "sandbox ready", event: HTTPObservation{Route: "/v1/sandboxes/{sandbox_id}", StatusCode: 200, ResponseJSON: map[string]any{"observed_state": "ready"}}, final: true, want: true},
		{name: "sandbox failed final", event: HTTPObservation{Route: "/v1/sandboxes/{sandbox_id}", StatusCode: 200, ResponseJSON: map[string]any{"observed_state": "failed"}}, final: true},
		{name: "retry response", event: HTTPObservation{Route: "/v1/operations/{operation_id}", StatusCode: 503}, want: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validProviderPollingState(test.event, test.final); got != test.want {
				t.Fatalf("validProviderPollingState() = %t, want %t", got, test.want)
			}
		})
	}
}
