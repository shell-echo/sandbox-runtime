package phase6security

import (
	"net/netip"
	"slices"
)

// BrokerBoundaryForPolicy returns the single deployment address authority for
// both the broker's local bind and its caller's dial. A second listen or dial
// address in command configuration cannot enlarge this edge.
func (p Profile) BrokerBoundaryForPolicy(policyID string) (TrustEdge, Principal, Principal, Network, error) {
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, Network{}, ErrInvalidProfile
	}
	for _, policy := range p.EgressPolicies {
		if policy.ID != policyID {
			continue
		}
		for _, edge := range p.TrustEdges {
			if edge.From != policy.Principal || edge.To != policy.Broker || edge.Protocol != "tls" {
				continue
			}
			var caller, broker Principal
			for _, principal := range p.Principals {
				switch principal.Name {
				case policy.Principal:
					caller = principal
				case policy.Broker:
					broker = principal
				}
			}
			for _, network := range p.Networks {
				if slices.Contains(caller.Networks, network.Name) && slices.Contains(broker.Networks, network.Name) {
					return edge, caller, broker, network, nil
				}
			}
		}
	}
	return TrustEdge{}, Principal{}, Principal{}, Network{}, ErrInvalidProfile
}

func validateBrokerBoundaries(policies []EgressPolicy, edges map[string]TrustEdge, principals map[string]Principal, networks []Network) error {
	matched := make(map[string]bool, len(policies))
	for _, policy := range policies {
		caller, callerOK := principals[policy.Principal]
		broker, brokerOK := principals[policy.Broker]
		if !callerOK || !brokerOK || broker.Kind != "egress_broker" || len(broker.Listeners) != 1 {
			return ErrInvalidProfile
		}
		var inbound TrustEdge
		for _, edge := range edges {
			if edge.To != broker.Name {
				continue
			}
			if inbound.ID != "" || edge.From != caller.Name || edge.Protocol != "tls" {
				return ErrInvalidProfile
			}
			inbound = edge
		}
		if inbound.ID == "" || matched[inbound.ID] || inbound.Authentication != "mtls" || inbound.RoutePath != "" ||
			inbound.CrossDomain || inbound.ExternalIdentityDigest != "" || inbound.TenantScope != "system" ||
			inbound.ServerAnchorID != "internal-server-ca" || inbound.ClientAnchorID != "internal-client-ca" ||
			inbound.FromPrincipalDigest != caller.PrincipalDigest || inbound.ToPrincipalDigest != broker.PrincipalDigest ||
			caller.TLS == nil || broker.TLS == nil || len(broker.TLS.DNSNames) != 1 || !validDNSName(broker.TLS.DNSNames[0]) ||
			!slices.Equal(broker.TLS.Usages, []string{"client_auth", "server_auth"}) ||
			inbound.FromURI != caller.TLS.URI || inbound.ToURI != broker.TLS.URI ||
			inbound.Port != broker.Listeners[0].Port || inbound.MaxConnectionSeconds < 1 || inbound.MaxConnectionSeconds > 300 {
			return ErrInvalidProfile
		}
		matched[inbound.ID] = true
		target, err := netip.ParseAddrPort(inbound.TargetAddress)
		if err != nil || !target.Addr().Is4() || !target.Addr().IsPrivate() ||
			target.String() != inbound.TargetAddress || int(target.Port()) != inbound.Port {
			return ErrInvalidProfile
		}
		shared := 0
		for _, network := range networks {
			if !slices.Contains(caller.Networks, network.Name) || !slices.Contains(broker.Networks, network.Name) {
				continue
			}
			shared++
			prefix, prefixErr := netip.ParsePrefix(network.IPv4Subnet)
			if prefixErr != nil || !network.Internal || network.GatewayModeIPv4 != "isolated" ||
				(network.Kind != "role_internal" && network.Kind != "trust_edge") ||
				len(network.Principals) != 2 || !slices.Contains(network.Principals, caller.Name) ||
				!slices.Contains(network.Principals, broker.Name) ||
				!prefix.Contains(target.Addr()) || target.Addr() == prefix.Addr() || !prefix.Contains(target.Addr().Next()) {
				return ErrInvalidProfile
			}
		}
		if shared != 1 {
			return ErrInvalidProfile
		}
	}
	for _, edge := range edges {
		if principal, ok := principals[edge.To]; ok && principal.Kind == "egress_broker" && !matched[edge.ID] {
			return ErrInvalidProfile
		}
	}
	return nil
}
