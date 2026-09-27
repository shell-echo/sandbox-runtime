package phase6security

import (
	"net/netip"
	"slices"
)

const GatewayProviderPrivateEdgeID = "gateway-provider-private"

const (
	GatewayProviderDesktopPrivateEdgeID       = "gateway-provider-desktop-private"
	GatewayBrowserActionIngressEdgeID         = "gateway-browser-action-ingress"
	BrowserActionIngressProviderPrivateEdgeID = "browser-action-ingress-provider-private"
)

// GatewayProviderBoundary resolves only the repository-owned private
// Gateway→Provider handoff route. It is not a Provider Contract endpoint or
// permission to dial any other Provider listener.
func (p Profile) GatewayProviderBoundary(origin string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	return p.GatewayProviderInstanceBoundary("provider-runtime", origin)
}

// GatewayProviderInstanceBoundary binds Terminal and Desktop routes only.
// Browser's action-fenced route must pass through its distinct ingress.
func (p Profile) GatewayProviderInstanceBoundary(providerName, origin string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	var edgeID, networkName, route string
	switch providerName {
	case "provider-runtime":
		edgeID, networkName, route = GatewayProviderPrivateEdgeID, "gateway-provider", "/private/terminal"
	case "provider-desktop-runtime":
		edgeID, networkName, route = GatewayProviderDesktopPrivateEdgeID, "gateway-provider-desktop", "/desktop"
	default:
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	return p.privateRuntimeBoundary("gateway-runtime", providerName, edgeID, networkName, route, "private", origin)
}

func (p Profile) GatewayBrowserActionIngressBoundary(origin string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	return p.privateRuntimeBoundary("gateway-runtime", "browser-action-ingress-runtime", GatewayBrowserActionIngressEdgeID,
		"gateway-browser-action-ingress", "/browser/action", "action", origin)
}

func (p Profile) BrowserActionIngressProviderBoundary(origin string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	return p.privateRuntimeBoundary("browser-action-ingress-runtime", "provider-browser-runtime", BrowserActionIngressProviderPrivateEdgeID,
		"browser-action-ingress-provider", "/private/browser", "private", origin)
}

func (p Profile) privateRuntimeBoundary(callerName, providerName, edgeID, networkName, route, listenerName, origin string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	var edge TrustEdge
	var caller, provider Principal
	var network Network
	for _, candidate := range p.TrustEdges {
		if candidate.ID == edgeID {
			edge = candidate
		}
	}
	for _, principal := range p.Principals {
		switch principal.Name {
		case callerName:
			caller = principal
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
	if edge.ID != edgeID || edge.From != caller.Name || caller.Name != callerName ||
		edge.To != provider.Name || provider.Name != providerName || edge.Protocol != "wss" ||
		edge.Authentication != "mtls" || edge.TenantScope != "bound" || edge.RoutePath != route ||
		provider.TLS == nil || caller.TLS == nil ||
		edge.FromPrincipalDigest != caller.PrincipalDigest || edge.ToPrincipalDigest != provider.PrincipalDigest ||
		edge.FromURI != caller.TLS.URI || edge.ToURI != provider.TLS.URI ||
		origin != "wss://"+edge.TargetAddress+edge.RoutePath || targetErr != nil || subnetErr != nil ||
		!subnet.Contains(target.Addr()) || network.Kind != "trust_edge" || !network.Internal ||
		len(network.Principals) != 2 || !slices.Contains(network.Principals, callerName) || !slices.Contains(network.Principals, providerName) ||
		!slices.Contains(caller.Networks, network.Name) || !slices.Contains(provider.Networks, network.Name) ||
		!slices.Contains(provider.TLS.Usages, "server_auth") ||
		!slices.Contains(caller.TLS.Usages, "client_auth") || len(provider.TLS.DNSNames) != 1 {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	listenerFound := false
	for _, listener := range provider.Listeners {
		if listener.Name == listenerName && listener.Protocol == "tcp" && listener.Port == edge.Port &&
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
	return edge, caller, provider, server, client, nil
}
