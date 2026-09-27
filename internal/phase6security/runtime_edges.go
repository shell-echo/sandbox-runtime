package phase6security

import (
	"net/netip"
	"slices"
)

// These are the approved service-to-service runtime dialing authorities.
// Broker, data-service and Unix controller edges have separate validators.
// A profile may choose its exact private target IP and port, but cannot omit
// or alias one of these directions to another edge.
var requiredRuntimeEdges = []struct {
	id, from, to, network, listener, protocol, route, tenantScope string
}{
	{"product-provider-contract", "product-runtime", "provider-runtime", "product-provider", "contract", "https", "/v1", "bound"},
	{"gateway-provider-private", "gateway-runtime", "provider-runtime", "gateway-provider", "private", "wss", "/private/terminal", "bound"},
	{"product-provider-browser-contract", "product-runtime", "provider-browser-runtime", "product-provider-browser", "contract", "https", "/v1", "bound"},
	{"product-provider-desktop-contract", "product-runtime", "provider-desktop-runtime", "product-provider-desktop", "contract", "https", "/v1", "bound"},
	{"gateway-browser-action-ingress", "gateway-runtime", "browser-action-ingress-runtime", "gateway-browser-action-ingress", "action", "wss", "/browser/action", "bound"},
	{"browser-action-ingress-provider-private", "browser-action-ingress-runtime", "provider-browser-runtime", "browser-action-ingress-provider", "private", "wss", "/private/browser", "bound"},
	{"gateway-provider-desktop-private", "gateway-runtime", "provider-desktop-runtime", "gateway-provider-desktop", "private", "wss", "/desktop", "bound"},
	{"guest-product", "guest-runtime", "product-runtime", "guest-product", "guest-control", "wss", "/agent", "bound"},
	{"provider-browser-attach", "provider-browser-runtime", "browser-runtime-role", "provider-browser", "attach", "wss", "/executor", "bound"},
	{"provider-desktop-attach", "provider-desktop-runtime", "desktop-runtime-role", "provider-desktop", "attach", "wss", "/executor", "bound"},
	{"executor-browser", "browser-runtime-role", "browser-executor-backend", "executor-browser", "executor", "wss", "/executor", "system"},
	{"executor-desktop", "desktop-runtime-role", "desktop-executor-backend", "executor-desktop", "executor", "wss", "/executor", "system"},
}

func validateRuntimeEdges(edges map[string]TrustEdge, principals map[string]Principal, networks []Network) error {
	networkByName := make(map[string]Network, len(networks))
	for _, network := range networks {
		networkByName[network.Name] = network
	}
	requiredIDs := make(map[string]struct{}, len(requiredRuntimeEdges))
	for _, spec := range requiredRuntimeEdges {
		requiredIDs[spec.id] = struct{}{}
		edge, ok := edges[spec.id]
		from, fromOK := principals[spec.from]
		to, toOK := principals[spec.to]
		network, networkOK := networkByName[spec.network]
		if !ok || !fromOK || !toOK || !networkOK || edge.From != spec.from || edge.To != spec.to ||
			edge.Protocol != spec.protocol || edge.Authentication != "mtls" || edge.RoutePath != spec.route ||
			edge.TenantScope != spec.tenantScope || edge.ServerAnchorID == "" || edge.ClientAnchorID == "" ||
			edge.ServerAnchorID == edge.ClientAnchorID || edge.Port < 1 || edge.TargetAddress == "" ||
			!network.Internal || network.Kind != "trust_edge" || network.GatewayModeIPv4 != "isolated" || network.IPv6Enabled ||
			!slices.Contains(from.Networks, spec.network) || !slices.Contains(to.Networks, spec.network) ||
			len(network.Principals) != 2 || !slices.Contains(network.Principals, spec.from) || !slices.Contains(network.Principals, spec.to) {
			return ErrInvalidProfile
		}
		if spec.listener == "executor" && (to.TLS == nil || !slices.Equal(to.TLS.Usages, []string{"server_auth"}) ||
			len(to.TLS.DNSNames) != 1 || !validDNSName(to.TLS.DNSNames[0]) ||
			edge.ToURI != to.TLS.URI || edge.ToPrincipalDigest != to.PrincipalDigest) {
			return ErrInvalidProfile
		}
		shared := 0
		for _, name := range from.Networks {
			if slices.Contains(to.Networks, name) {
				shared++
			}
		}
		if shared != 1 {
			return ErrInvalidProfile
		}
		listenerFound := false
		for _, listener := range to.Listeners {
			if listener.Name == spec.listener && listener.Protocol == "tcp" &&
				listener.Exposure == "trust_edge" && listener.Port == edge.Port {
				listenerFound = true
			}
		}
		if !listenerFound {
			return ErrInvalidProfile
		}
		target, targetErr := netip.ParseAddrPort(edge.TargetAddress)
		prefix, prefixErr := netip.ParsePrefix(network.IPv4Subnet)
		if targetErr != nil || prefixErr != nil || int(target.Port()) != edge.Port ||
			!prefix.Contains(target.Addr()) || target.Addr() == prefix.Addr() {
			return ErrInvalidProfile
		}
	}
	for _, edge := range edges {
		from, fromOK := principals[edge.From]
		to, toOK := principals[edge.To]
		if fromOK && toOK && from.Kind == "runtime" && (to.Kind == "runtime" || to.Kind == "executor") {
			if _, required := requiredIDs[edge.ID]; !required {
				return ErrInvalidProfile
			}
		}
	}
	// There must be no routable direct Browser write path around the unique
	// action ingress, even if an operator adds an otherwise well-formed network
	// without declaring a second trust edge.
	for _, pair := range [][2]string{
		{"gateway-runtime", "provider-browser-runtime"},
		{"gateway-runtime", "browser-runtime-role"},
		{"gateway-runtime", "browser-executor-backend"},
		{"gateway-runtime", "browser-sandbox-runtime"},
		{"browser-action-ingress-runtime", "browser-runtime-role"},
		{"browser-action-ingress-runtime", "browser-executor-backend"},
		{"browser-action-ingress-runtime", "browser-sandbox-runtime"},
	} {
		left, leftOK := principals[pair[0]]
		right, rightOK := principals[pair[1]]
		if !leftOK || !rightOK {
			return ErrInvalidProfile
		}
		for _, network := range left.Networks {
			if slices.Contains(right.Networks, network) {
				return ErrInvalidProfile
			}
		}
	}
	return nil
}
