package secretref

import "testing"

func TestExternalPurposeDeploymentAllowlist(t *testing.T) {
	for _, test := range []struct {
		deployment string
		role       Role
		purpose    Purpose
		allowed    bool
	}{
		{"browser-action-ingress-runtime", RoleGateway, PurposeActionHistoryWitnessDSN, true},
		{"browser-action-ingress-agent", RoleGateway, PurposeActionHistoryWitnessDSN, true},
		{"browser-action-ingress-runtime", RoleGateway, PurposeCapacityValkeyCredentials, true},
		{"browser-action-ingress-agent", RoleGateway, PurposeCapacityValkeyCredentials, true},
		{"gateway-runtime", RoleGateway, PurposeCapacityValkeyCredentials, true},
		{"gateway-agent", RoleGateway, PurposeCapacityValkeyCredentials, true},
		{"gateway-runtime", RoleGateway, PurposeActionHistoryWitnessDSN, false},
		{"gateway-agent", RoleGateway, PurposeActionHistoryWitnessDSN, false},
		{"provider-runtime", RoleGateway, PurposeCapacityValkeyCredentials, false},
		{"browser-action-ingress-runtime", RoleProduct, PurposeCapacityValkeyCredentials, false},
		{"gateway-runtime", RoleGateway, PurposePostgresRuntimeDSN, true},
	} {
		if got := DeploymentPurposeAllowed(test.deployment, test.role, test.purpose); got != test.allowed {
			t.Errorf("deployment %s/%s/%s allowed=%t, want %t", test.deployment, test.role, test.purpose, got, test.allowed)
		}
	}
}
