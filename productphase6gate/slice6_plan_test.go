//go:build phase6slice6gate

package productphase6gate

import (
	"errors"
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This is the frozen routing/assertion plan for a distinct Slice 6 harness,
// not a release test or evidence. A future runner must bind each row to live
// observations from one runID; a passing plan test cannot close the slice.
type slice6EdgeRoute struct{ id, from, to string }
type slice6ScenarioRoute struct {
	name       string
	edges      []slice6EdgeRoute
	assertions []string
}

var slice6ScenarioRoutes = []slice6ScenarioRoute{
	{"browser_cdp_and_capacity_replay", []slice6EdgeRoute{
		{"provider-browser-attach", "provider-browser-runtime", "browser-runtime-role"},
		{"executor-browser", "browser-runtime-role", "browser-executor-backend"}},
		[]string{"real_cdp_version", "finite_capacity", "same_authority_replay_denied"}},
	{"browser_external_witness_isolation", []slice6EdgeRoute{
		{"gateway-browser-action-ingress", "gateway-runtime", "browser-action-ingress-runtime"},
		{"browser-action-history-postgres", "browser-action-ingress-runtime", "action-history-postgres"},
		{"browser-capacity-valkey", "browser-action-ingress-runtime", "capacity-valkey"}},
		[]string{"distinct_external_identities", "grant_isolation", "restore_domain_isolation"}},
	{"cross_role_and_tenant_denial", []slice6EdgeRoute{
		{"gateway-provider-private", "gateway-runtime", "provider-runtime"},
		{"browser-action-ingress-provider-private", "browser-action-ingress-runtime", "provider-browser-runtime"},
		{"gateway-provider-desktop-private", "gateway-runtime", "provider-desktop-runtime"}},
		[]string{"wrong_peer_denied", "wrong_route_denied", "cross_tenant_denied"}},
	{"desktop_media_input_and_cleanup", []slice6EdgeRoute{
		{"provider-desktop-attach", "provider-desktop-runtime", "desktop-runtime-role"},
		{"executor-desktop", "desktop-runtime-role", "desktop-executor-backend"}},
		[]string{"broker_in_parent_observed", "real_rtp_and_input", "exact_dynamic_cleanup"}},
	{"direct_egress_and_metadata_denial", []slice6EdgeRoute{
		{"egress-role-product", "product-runtime", "egress-broker-product"}},
		[]string{"role_direct_ip_denied", "metadata_denied", "alias_only_egress"}},
	{"dns_rebinding_and_alternate_path_denial", []slice6EdgeRoute{
		{"egress-dns", "egress-broker-product", "dns"}},
		[]string{"rebinding_denied", "alternate_path_denied", "dns_receipt_observed"}},
	{"external_dependency_loss", []slice6EdgeRoute{
		{"browser-action-history-postgres", "browser-action-ingress-runtime", "action-history-postgres"},
		{"browser-capacity-valkey", "browser-action-ingress-runtime", "capacity-valkey"}},
		[]string{"witness_loss_closes_admission", "capacity_loss_closes_admission", "bounded_recovery"}},
	{"guest_auth_and_reconnect", []slice6EdgeRoute{
		{"guest-product", "guest-runtime", "product-runtime"}},
		[]string{"signed_challenge_welcome", "binding_revoke_denied", "upgraded_socket_drain"}},
	{"least_privilege_active_probes", []slice6EdgeRoute{
		{"product-provider-contract", "product-runtime", "provider-runtime"}},
		[]string{"complete_container_inventory", "effective_uid_gid", "seccomp_capability_mount_limits"}},
	{"mtls_identity_and_downgrade_denial", []slice6EdgeRoute{
		{"gateway-provider-private", "gateway-runtime", "provider-runtime"}},
		[]string{"wrong_certificate_denied", "plaintext_denied", "legacy_downgrade_denied"}},
	{"policy_authority_loss_and_revocation", []slice6EdgeRoute{
		{"egress-role-product", "product-runtime", "egress-broker-product"},
		{"egress-authority-product", "egress-broker-product", "egress-policy-authority-product"}},
		[]string{"authority_loss_closes_egress", "revoked_policy_denied", "fresh_state_required"}},
	{"provider_and_executor_restart", []slice6EdgeRoute{
		{"product-provider-contract", "product-runtime", "provider-runtime"},
		{"provider-browser-attach", "provider-browser-runtime", "browser-runtime-role"},
		{"provider-desktop-attach", "provider-desktop-runtime", "desktop-runtime-role"}},
		[]string{"distinct_process_instances", "retained_authority", "stale_admission_denied"}},
	{"resource_exhaustion_denial", []slice6EdgeRoute{
		{"product-provider-contract", "product-runtime", "provider-runtime"}},
		[]string{"bounded_product_requests", "bounded_gateway_connections", "bounded_workers"}},
	{"revoked_leaf_and_crl_rollback_denial", []slice6EdgeRoute{
		{"gateway-provider-private", "gateway-runtime", "provider-runtime"}},
		[]string{"vault_revoked_leaf_denied", "active_socket_drain", "crl_rollback_denied"}},
	{"role_and_controller_drain", []slice6EdgeRoute{
		{"executor-browser", "browser-runtime-role", "browser-executor-backend"},
		{"executor-desktop", "desktop-runtime-role", "desktop-executor-backend"},
		{"certificate-vault", "certificate-controller", "vault"}},
		[]string{"bounded_sigterm", "active_socket_close", "exact_lease_socket_cleanup"}},
	{"vault_pki_rotation_and_loss", []slice6EdgeRoute{
		{"certificate-vault", "certificate-controller", "vault"}},
		[]string{"fresh_issue_and_overlap", "live_rotation", "loss_closes_admission"}},
}

func validateSlice6ScenarioRoutes(profile phase6security.Profile, routes []slice6ScenarioRoute) error {
	required := phase6security.RequiredSlice6Scenarios()
	if len(routes) != len(required) {
		return errors.New("Slice 6 scenario plan is incomplete")
	}
	participants := make(map[string]bool)
	for _, principal := range profile.Principals {
		participants[principal.Name] = true
	}
	for _, component := range profile.Components {
		participants[component.Name] = true
	}
	for _, external := range profile.External {
		participants[external.Name] = true
	}
	edges := make(map[string]phase6security.TrustEdge)
	for _, edge := range profile.TrustEdges {
		if _, duplicate := edges[edge.ID]; duplicate {
			return errors.New("Slice 6 profile has duplicate route edge")
		}
		edges[edge.ID] = edge
	}
	for index, route := range routes {
		if route.name != required[index].Name || len(route.edges) == 0 || len(route.assertions) == 0 {
			return errors.New("Slice 6 scenario plan drifted")
		}
		for _, name := range required[index].Participants {
			if !participants[name] {
				return errors.New("Slice 6 scenario participant is absent")
			}
		}
		seen := make(map[string]bool)
		for _, routeEdge := range route.edges {
			edge, ok := edges[routeEdge.id]
			if !ok || seen[routeEdge.id] || edge.From != routeEdge.from || edge.To != routeEdge.to {
				return errors.New("Slice 6 scenario route does not match profile")
			}
			seen[routeEdge.id] = true
		}
		assertions := append([]string(nil), route.assertions...)
		slices.Sort(assertions)
		if assertions[0] == "" || slices.ContainsFunc(assertions[1:], func(value string) bool { return value == "" }) {
			return errors.New("Slice 6 scenario assertion is absent")
		}
		for item := 1; item < len(assertions); item++ {
			if assertions[item] == assertions[item-1] {
				return errors.New("Slice 6 scenario assertion is duplicated")
			}
		}
	}
	return nil
}

func TestSlice6FrozenScenarioRoutingPlan(t *testing.T) {
	var profile phase6security.Profile
	for _, requirement := range phase6security.RequiredSlice6Scenarios() {
		for _, name := range requirement.Participants {
			switch name {
			case "desktop-broker":
				profile.Components = append(profile.Components, phase6security.Component{Name: name})
			case "dns", "vault", "action-history-postgres", "capacity-valkey":
				profile.External = append(profile.External, phase6security.ExternalService{Name: name})
			default:
				profile.Principals = append(profile.Principals, phase6security.Principal{Name: name})
			}
		}
	}
	for _, route := range slice6ScenarioRoutes {
		for _, edge := range route.edges {
			profile.TrustEdges = append(profile.TrustEdges, phase6security.TrustEdge{ID: edge.id, From: edge.from, To: edge.to})
		}
	}
	// A real gate verifies its complete signed profile before this mapping.
	// Deduplicate this small synthetic inventory only for negative map tests.
	profile.TrustEdges = uniqueSlice6TestEdges(profile.TrustEdges)
	if err := validateSlice6ScenarioRoutes(profile, slice6ScenarioRoutes); err != nil {
		t.Fatalf("frozen Slice 6 route plan: %v", err)
	}
	missing := profile
	missing.TrustEdges = append([]phase6security.TrustEdge(nil), profile.TrustEdges[1:]...)
	if validateSlice6ScenarioRoutes(missing, slice6ScenarioRoutes) == nil {
		t.Fatal("missing trust edge admitted")
	}
	wrong := profile
	wrong.TrustEdges = append([]phase6security.TrustEdge(nil), profile.TrustEdges...)
	wrong.TrustEdges[0].To = "wrong-provider"
	if validateSlice6ScenarioRoutes(wrong, slice6ScenarioRoutes) == nil {
		t.Fatal("wrong trust edge target admitted")
	}
	missing = profile
	missing.Components = nil
	if validateSlice6ScenarioRoutes(missing, slice6ScenarioRoutes) == nil {
		t.Fatal("missing in-container broker admitted")
	}
	dropped := append([]slice6ScenarioRoute(nil), slice6ScenarioRoutes[1:]...)
	if validateSlice6ScenarioRoutes(profile, dropped) == nil {
		t.Fatal("missing frozen scenario admitted")
	}
}

func uniqueSlice6TestEdges(values []phase6security.TrustEdge) []phase6security.TrustEdge {
	seen := make(map[string]bool)
	result := make([]phase6security.TrustEdge, 0, len(values))
	for _, edge := range values {
		if !seen[edge.ID] {
			seen[edge.ID] = true
			result = append(result, edge)
		}
	}
	return result
}
