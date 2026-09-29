package phase6security

import (
	"sort"
	"strings"
)

// Slice6DesiredDutyClass is a reviewed deployment-to-workload-duty mapping,
// independent of which binary happens to implement a role. A resource and
// seccomp supply must cover these exact classes; a common binary target does
// not grant permission to inherit another duty's limits or syscall policy.
func Slice6DesiredDutyClass(deployment string) (string, error) {
	kind, approved := slice6ApprovedDeploymentKinds[deployment]
	if !approved {
		return "", errSlice6DesiredInventory
	}
	switch kind {
	case "runtime":
		classes := map[string]string{
			"product-runtime": "product_runtime", "gateway-runtime": "gateway_runtime",
			"browser-action-ingress-runtime": "browser_action_ingress_runtime",
			"provider-runtime":               "provider_coding_runtime",
			"provider-browser-runtime":       "provider_browser_runtime",
			"provider-desktop-runtime":       "provider_desktop_runtime",
			"guest-runtime":                  "guest_runtime", "browser-runtime-role": "browser_role",
			"desktop-runtime-role": "desktop_role",
		}
		if duty := classes[deployment]; duty != "" {
			return duty, nil
		}
	case "executor":
		switch deployment {
		case "browser-executor-backend":
			return "browser_executor", nil
		case "desktop-executor-backend":
			return "desktop_executor", nil
		}
	case "tls_agent":
		return "tls_agent", nil
	case "material_agent":
		switch deployment {
		case "product-migration-agent", "provider-migration-agent",
			"provider-browser-migration-agent", "provider-desktop-migration-agent":
			return "migration_material_agent", nil
		default:
			return "runtime_material_agent", nil
		}
	case "migration_job":
		return "migration_job", nil
	case "controller":
		switch deployment {
		case "workload-credential-controller":
			return "credential_controller", nil
		case "certificate-controller":
			return "certificate_controller", nil
		case "break-glass-controller":
			return "break_glass_controller", nil
		default:
			if strings.HasPrefix(deployment, "egress-policy-authority-") {
				return "egress_policy_authority", nil
			}
		}
	case "egress_broker":
		return "egress_broker", nil
	case "ingress_relay":
		return "public_ingress_relay", nil
	case "sandbox":
		switch deployment {
		case "browser-sandbox-runtime":
			return "chromium_sandbox", nil
		case "desktop-sandbox-runtime":
			return "desktop_x11_sandbox", nil
		}
	}
	return "", errSlice6DesiredInventory
}

// Slice6DesiredDutyClasses returns the complete finite duty vocabulary in
// sorted order. It is desired configuration, not a measured resource policy.
func Slice6DesiredDutyClasses() ([]string, error) {
	seen := make(map[string]bool)
	for _, deployment := range Slice6DesiredDeploymentNames() {
		duty, err := Slice6DesiredDutyClass(deployment)
		if err != nil || duty == "" {
			return nil, errSlice6DesiredInventory
		}
		seen[duty] = true
	}
	classes := make([]string, 0, len(seen))
	for duty := range seen {
		classes = append(classes, duty)
	}
	sort.Strings(classes)
	return classes, nil
}
