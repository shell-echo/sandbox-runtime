package phase6security

import "slices"

type slice6EgressSpec struct {
	id, principal, broker, authority, authorizationName string
	keyID, socketDirectory, socketStorageID             string
	ledgerTarget, ledgerStorageID                       string
	targets                                             []EgressTarget
}

// This is the reviewed alias and authority inventory for the bounded local
// gate. A real run must still supply and verify each authority's actual key.
var slice6DesiredEgress = []slice6EgressSpec{
	{
		id: "browser-action-ingress-egress", principal: "browser-action-ingress-runtime",
		broker: "egress-broker-browser-action-ingress", authority: "egress-policy-authority-browser-action-ingress",
		authorizationName: "browser_action_ingress_policy_authority", keyID: "operator-browser-action-ingress-1",
		socketDirectory: "/run/egress-authority-browser-action-ingress", socketStorageID: "browser-action-ingress-authority-socket",
		ledgerTarget: "/var/lib/egress-authority-browser-action-ingress", ledgerStorageID: "browser-action-ingress-authority-ledger",
		targets: []EgressTarget{{Alias: "action-history", Host: "action-history.sandbox-runtime.test", Port: 5432, Protocol: "postgres"},
			{Alias: "capacity", Host: "capacity.sandbox-runtime.test", Port: 6379, Protocol: "tls"}},
	},
	{
		id: "gateway-egress", principal: "gateway-runtime", broker: "egress-broker-gateway",
		authority: "egress-policy-authority-gateway", authorizationName: "gateway_policy_authority", keyID: "operator-gateway-1",
		socketDirectory: "/run/egress-authority-gateway", socketStorageID: "gateway-authority-socket",
		ledgerTarget: "/var/lib/egress-authority-gateway", ledgerStorageID: "gateway-authority-ledger",
		targets: []EgressTarget{{Alias: "capacity", Host: "capacity.sandbox-runtime.test", Port: 6379, Protocol: "tls"}},
	},
	{
		id: "product-egress", principal: "product-runtime", broker: "egress-broker-product",
		authority: "egress-policy-authority-product", authorizationName: "product_policy_authority", keyID: "operator-product-1",
		socketDirectory: "/run/egress-authority", socketStorageID: "product-authority-socket",
		ledgerTarget: "/var/lib/egress-authority", ledgerStorageID: "product-authority-ledger",
		targets: []EgressTarget{{Alias: "registry-probe", Host: "registry-1.docker.io", Port: 443, Protocol: "https"}},
	},
	{
		id: "provider-browser-egress", principal: "provider-browser-runtime", broker: "egress-broker-provider-browser",
		authority: "egress-policy-authority-provider-browser", authorizationName: "provider_browser_policy_authority", keyID: "operator-provider-browser-1",
		socketDirectory: "/run/egress-authority-provider-browser", socketStorageID: "provider-browser-authority-socket",
		ledgerTarget: "/var/lib/egress-authority-provider-browser", ledgerStorageID: "provider-browser-authority-ledger",
		targets: []EgressTarget{{Alias: "postgres", Host: "postgres.sandbox-runtime.test", Port: 5432, Protocol: "postgres"}},
	},
	{
		id: "provider-desktop-egress", principal: "provider-desktop-runtime", broker: "egress-broker-provider-desktop",
		authority: "egress-policy-authority-provider-desktop", authorizationName: "provider_desktop_policy_authority", keyID: "operator-provider-desktop-1",
		socketDirectory: "/run/egress-authority-provider-desktop", socketStorageID: "provider-desktop-authority-socket",
		ledgerTarget: "/var/lib/egress-authority-provider-desktop", ledgerStorageID: "provider-desktop-authority-ledger",
		targets: []EgressTarget{{Alias: "postgres", Host: "postgres.sandbox-runtime.test", Port: 5432, Protocol: "postgres"}},
	},
}

// VerifySlice6DesiredEgressPolicies prevents a profile from granting a new
// destination or lengthening an authority lease by merely rehashing itself.
// Key digests remain run artifacts and are checked by the live authority gate.
func VerifySlice6DesiredEgressPolicies(profile Profile) error {
	if profile.Validate() != nil || len(profile.EgressPolicies) != len(slice6DesiredEgress) {
		return errSlice6DesiredInventory
	}
	for index, policy := range profile.EgressPolicies {
		expected := slice6DesiredEgress[index]
		authority := policy.Authority
		if policy.ID != expected.id || policy.Revision != "policy-1" ||
			policy.Principal != expected.principal || policy.Broker != expected.broker ||
			authority.DeploymentName != expected.authority || authority.AuthorizationName != expected.authorizationName ||
			authority.KeyID != expected.keyID || authority.SocketDirectory != expected.socketDirectory ||
			authority.SocketStorageID != expected.socketStorageID || authority.LedgerMountTarget != expected.ledgerTarget ||
			authority.LedgerStorageID != expected.ledgerStorageID || authority.PollMillis != 500 ||
			authority.CurrentTimeoutMS != 1000 || authority.StateMaxAgeSeconds != 5 ||
			policy.LeaseSeconds != 60 || policy.DNSMaxAnswers != 8 || !slices.Equal(policy.Targets, expected.targets) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
