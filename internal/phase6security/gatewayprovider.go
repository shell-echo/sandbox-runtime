package phase6security

import (
	"net/netip"
	"slices"
)

const GatewayProviderPrivateEdgeID = "gateway-provider-private"

const (
	GatewayProviderBrowserPrivateEdgeID = "gateway-provider-browser-private"
	GatewayProviderDesktopPrivateEdgeID = "gateway-provider-desktop-private"
)

// GatewayProviderBoundary resolves only the repository-owned private
// Gateway→Provider handoff route. It is not a Provider Contract endpoint or
// permission to dial any other Provider listener.
func (p Profile) GatewayProviderBoundary(origin string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	return p.GatewayProviderInstanceBoundary("provider-runtime", origin)
}

// GatewayProviderInstanceBoundary binds one Gateway private route to exactly
// its matching Provider process and principal. A Browser/Desktop route cannot
// be relabeled as the coding-shell Terminal route.
func (p Profile) GatewayProviderInstanceBoundary(providerName, origin string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	var edgeID, networkName, route string
	switch providerName {
	case "provider-runtime":
		edgeID, networkName, route = GatewayProviderPrivateEdgeID, "gateway-provider", "/private/terminal"
	case "provider-browser-runtime":
		edgeID, networkName, route = GatewayProviderBrowserPrivateEdgeID, "gateway-provider-browser", "/private/browser"
	case "provider-desktop-runtime":
		edgeID, networkName, route = GatewayProviderDesktopPrivateEdgeID, "gateway-provider-desktop", "/desktop"
	default:
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	var edge TrustEdge
	var gateway, provider Principal
	var network Network
	for _, candidate := range p.TrustEdges {
		if candidate.ID == edgeID {
			edge = candidate
		}
	}
	for _, principal := range p.Principals {
		switch principal.Name {
		case "gateway-runtime":
			gateway = principal
		case providerName:
			provider = principal
		}
	}
	for _, candidate := range p.Networks {
		if candidate.Name == networkName {
			network = candidate
		}
	}
	target, targetErr := netip.ParseAddrPort(edge.TargetAddress)
	subnet, subnetErr := netip.ParsePrefix(network.IPv4Subnet)
	if edge.ID != edgeID || edge.From != gateway.Name || gateway.Name != "gateway-runtime" ||
		edge.To != provider.Name || provider.Name != providerName || edge.Protocol != "wss" ||
		edge.Authentication != "mtls" || edge.TenantScope != "bound" || edge.RoutePath != route ||
		provider.TLS == nil || gateway.TLS == nil ||
		edge.FromPrincipalDigest != gateway.PrincipalDigest || edge.ToPrincipalDigest != provider.PrincipalDigest ||
		edge.FromURI != gateway.TLS.URI || edge.ToURI != provider.TLS.URI ||
		origin != "wss://"+edge.TargetAddress+edge.RoutePath || targetErr != nil || subnetErr != nil ||
		!subnet.Contains(target.Addr()) || network.Kind != "trust_edge" || !network.Internal ||
		!slices.Equal(network.Principals, []string{"gateway-runtime", providerName}) ||
		!slices.Contains(gateway.Networks, network.Name) || !slices.Contains(provider.Networks, network.Name) ||
		!slices.Contains(provider.TLS.Usages, "server_auth") ||
		!slices.Contains(gateway.TLS.Usages, "client_auth") || len(provider.TLS.DNSNames) != 1 {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	listenerFound := false
	for _, listener := range provider.Listeners {
		if listener.Name == "private" && listener.Protocol == "tcp" && listener.Port == edge.Port &&
			listener.Exposure == "trust_edge" {
			listenerFound = true
		}
	}
	if !listenerFound {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	server, client, err := p.EdgeTrustAnchors(edge.ID)
	if err != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	return edge, gateway, provider, server, client, nil
}
