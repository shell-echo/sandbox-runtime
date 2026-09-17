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
