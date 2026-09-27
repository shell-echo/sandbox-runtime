package secretref

// DeploymentPurposeAllowed narrows the two Gateway-family external database
// purposes to exact independent runtime/agent pairs. A shared logical Role
// never makes the other Gateway deployment's binding readable.
func DeploymentPurposeAllowed(deployment string, role Role, purpose Purpose) bool {
	if purpose != PurposeActionHistoryWitnessDSN && purpose != PurposeCapacityValkeyCredentials {
		return true
	}
	if role != RoleGateway {
		return false
	}
	switch deployment {
	case "browser-action-ingress-runtime", "browser-action-ingress-agent":
		return true
	case "gateway-runtime", "gateway-agent":
		return purpose == PurposeCapacityValkeyCredentials
	default:
		return false
	}
}
