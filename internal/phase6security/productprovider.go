package phase6security

import (
	"net/netip"
	"slices"
)

const ProductProviderContractEdgeID = "product-provider-contract"

const (
	ProductProviderBrowserContractEdgeID = "product-provider-browser-contract"
	ProductProviderDesktopContractEdgeID = "product-provider-desktop-contract"
)

// ProductProviderBoundary resolves the protected Provider Contract listener,
// not the Product or Gateway public ingress. The Contract DTO and JWS
// admission policy remain independently owned by Provider.
func (p Profile) ProductProviderBoundary() (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	return p.ProductProviderInstanceBoundary("provider-runtime")
}

// ProductProviderInstanceBoundary selects exactly one Provider instance's
// locked Contract listener. Three Provider processes cannot share this TLS
// or CRL authority simply because they implement the same Contract.
func (p Profile) ProductProviderInstanceBoundary(providerName string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	var edgeID, networkName string
	switch providerName {
	case "provider-runtime":
		edgeID, networkName = ProductProviderContractEdgeID, "product-provider"
	case "provider-browser-runtime":
		edgeID, networkName = ProductProviderBrowserContractEdgeID, "product-provider-browser"
	case "provider-desktop-runtime":
		edgeID, networkName = ProductProviderDesktopContractEdgeID, "product-provider-desktop"
	default:
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	var edge TrustEdge
	var product, provider Principal
	var network Network
	for _, candidate := range p.TrustEdges {
		if candidate.ID == edgeID {
			edge = candidate
		}
	}
	for _, candidate := range p.Principals {
		switch candidate.Name {
		case "product-runtime":
			product = candidate
		case providerName:
			provider = candidate
		}
	}
	for _, candidate := range p.Networks {
		if candidate.Name == networkName {
			network = candidate
		}
	}
	target, targetErr := netip.ParseAddrPort(edge.TargetAddress)
	subnet, subnetErr := netip.ParsePrefix(network.IPv4Subnet)
	if edge.ID != edgeID || edge.From != product.Name || product.Name != "product-runtime" ||
		edge.To != provider.Name || provider.Name != providerName || edge.Protocol != "https" ||
		edge.Authentication != "mtls" || edge.TenantScope != "bound" || edge.RoutePath != "/v1" ||
		product.TLS == nil || provider.TLS == nil ||
		edge.FromPrincipalDigest != product.PrincipalDigest || edge.ToPrincipalDigest != provider.PrincipalDigest ||
		edge.FromURI != product.TLS.URI || edge.ToURI != provider.TLS.URI ||
		targetErr != nil || subnetErr != nil || !subnet.Contains(target.Addr()) ||
		network.Kind != "trust_edge" || !network.Internal ||
		!slices.Equal(network.Principals, []string{"product-runtime", providerName}) ||
		!slices.Contains(product.Networks, network.Name) || !slices.Contains(provider.Networks, network.Name) ||
		!slices.Contains(product.TLS.Usages, "client_auth") ||
		!slices.Contains(provider.TLS.Usages, "server_auth") || len(provider.TLS.DNSNames) != 1 {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	listenerFound := false
	for _, listener := range provider.Listeners {
		if listener.Name == "contract" && listener.Protocol == "tcp" && listener.Port == edge.Port &&
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
	return edge, product, provider, server, client, nil
}
