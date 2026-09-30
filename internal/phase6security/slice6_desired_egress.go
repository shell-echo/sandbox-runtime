package phase6security

import (
	"crypto/ed25519"
	"slices"
)

type slice6EgressSpec struct {
	id, principal, broker, authority, authorizationName string
	keyID, socketDirectory, socketStorageID             string
	ledgerTarget, ledgerStorageID                       string
	dnsMaxAnswers                                       int
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
		dnsMaxAnswers: 8,
		targets: []EgressTarget{{Alias: "action-history", Host: "action-history.sandbox-runtime.test", Port: 5432, Protocol: "postgres"},
			{Alias: "capacity", Host: "capacity.sandbox-runtime.test", Port: 6379, Protocol: "tls"}},
	},
	{
		id: "gateway-egress", principal: "gateway-runtime", broker: "egress-broker-gateway",
		authority: "egress-policy-authority-gateway", authorizationName: "gateway_policy_authority", keyID: "operator-gateway-1",
		socketDirectory: "/run/egress-authority-gateway", socketStorageID: "gateway-authority-socket",
		ledgerTarget: "/var/lib/egress-authority-gateway", ledgerStorageID: "gateway-authority-ledger",
		dnsMaxAnswers: 8,
		targets:       []EgressTarget{{Alias: "capacity", Host: "capacity.sandbox-runtime.test", Port: 6379, Protocol: "tls"}},
	},
	{
		id: "product-egress", principal: "product-runtime", broker: "egress-broker-product",
		authority: "egress-policy-authority-product", authorizationName: "product_policy_authority", keyID: "operator-product-1",
		socketDirectory: "/run/egress-authority", socketStorageID: "product-authority-socket",
		ledgerTarget: "/var/lib/egress-authority", ledgerStorageID: "product-authority-ledger",
		dnsMaxAnswers: 16,
		targets:       []EgressTarget{{Alias: "registry-probe", Host: "registry-1.docker.io", Port: 443, Protocol: "https"}},
	},
	{
		id: "provider-browser-egress", principal: "provider-browser-runtime", broker: "egress-broker-provider-browser",
		authority: "egress-policy-authority-provider-browser", authorizationName: "provider_browser_policy_authority", keyID: "operator-provider-browser-1",
		socketDirectory: "/run/egress-authority-provider-browser", socketStorageID: "provider-browser-authority-socket",
		ledgerTarget: "/var/lib/egress-authority-provider-browser", ledgerStorageID: "provider-browser-authority-ledger",
		dnsMaxAnswers: 8,
		targets:       []EgressTarget{{Alias: "postgres", Host: "postgres.sandbox-runtime.test", Port: 5432, Protocol: "postgres"}},
	},
	{
		id: "provider-desktop-egress", principal: "provider-desktop-runtime", broker: "egress-broker-provider-desktop",
		authority: "egress-policy-authority-provider-desktop", authorizationName: "provider_desktop_policy_authority", keyID: "operator-provider-desktop-1",
		socketDirectory: "/run/egress-authority-provider-desktop", socketStorageID: "provider-desktop-authority-socket",
		ledgerTarget: "/var/lib/egress-authority-provider-desktop", ledgerStorageID: "provider-desktop-authority-ledger",
		dnsMaxAnswers: 8,
		targets:       []EgressTarget{{Alias: "postgres", Host: "postgres.sandbox-runtime.test", Port: 5432, Protocol: "postgres"}},
	},
}

// Slice6DesiredEgressAuthorityNames is the exact ordered private-key owner
// inventory. The corresponding private bytes remain outside the profile.
func Slice6DesiredEgressAuthorityNames() []string {
	result := make([]string, 0, len(slice6DesiredEgress))
	for _, spec := range slice6DesiredEgress {
		result = append(result, spec.authority)
	}
	return result
}

// BuildSlice6DesiredEgressPolicies binds the reviewed policy inventory to
// actual operator public keys and already-bound deployment identities. It
// does not attest possession of the private keys or a running authority.
func BuildSlice6DesiredEgressPolicies(principals []Principal, publicKeys map[string]ed25519.PublicKey) ([]EgressPolicy, error) {
	if len(publicKeys) != len(slice6DesiredEgress) {
		return nil, errSlice6DesiredInventory
	}
	byName := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		if _, duplicate := byName[principal.Name]; duplicate {
			return nil, errSlice6DesiredInventory
		}
		byName[principal.Name] = principal
	}
	result := make([]EgressPolicy, 0, len(slice6DesiredEgress))
	seenKeys := make(map[string]bool, len(slice6DesiredEgress))
	for _, spec := range slice6DesiredEgress {
		principal, principalOK := byName[spec.principal]
		broker, brokerOK := byName[spec.broker]
		authority, authorityOK := byName[spec.authority]
		key, keyOK := publicKeys[spec.authority]
		digest := OperatorPublicKeyDigest(key)
		if !principalOK || !brokerOK || !authorityOK || !keyOK || digest == "" || seenKeys[digest] ||
			principal.PrincipalDigest == "" || broker.PrincipalDigest == "" || authority.PrincipalDigest == "" ||
			principal.Kind == "egress_broker" || broker.Kind != "egress_broker" || authority.Kind != "controller" ||
			authority.AuthorizationPrincipal == nil || authority.AuthorizationPrincipal.Name != spec.authorizationName {
			return nil, errSlice6DesiredInventory
		}
		seenKeys[digest] = true
		result = append(result, EgressPolicy{
			ID: spec.id, Revision: "policy-1", Principal: spec.principal, Broker: spec.broker,
			PrincipalDigest: principal.PrincipalDigest, BrokerDigest: broker.PrincipalDigest,
			Authority: PolicyAuthority{DeploymentName: spec.authority, AuthorizationName: spec.authorizationName,
				PrincipalDigest: authority.PrincipalDigest, KeyID: spec.keyID, PublicKeyDigest: digest,
				SocketDirectory: spec.socketDirectory, SocketStorageID: spec.socketStorageID,
				LedgerMountTarget: spec.ledgerTarget, LedgerStorageID: spec.ledgerStorageID,
				PollMillis: 500, CurrentTimeoutMS: 1000, StateMaxAgeSeconds: 5},
			LeaseSeconds: 60, DNSMaxAnswers: spec.dnsMaxAnswers, DenyRawIP: true, DenyAlternateDNS: true,
			DenyProxyEnvironment: true, DenyRedirectAuthority: true, DenyMetadataPrivateRanges: true,
			Targets: slices.Clone(spec.targets),
		})
	}
	return result, nil
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
			policy.LeaseSeconds != 60 || policy.DNSMaxAnswers != expected.dnsMaxAnswers || !slices.Equal(policy.Targets, expected.targets) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
