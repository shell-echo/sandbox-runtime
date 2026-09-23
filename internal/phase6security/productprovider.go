package phase6security

import (
	"net/netip"
	"slices"
)

const ProductProviderContractEdgeID = "product-provider-contract"

// ProductProviderBoundary resolves the protected Provider Contract listener,
// not the Product or Gateway public ingress. The Contract DTO and JWS
// admission policy remain independently owned by Provider.
func (p Profile) ProductProviderBoundary() (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	var edge TrustEdge
	var product, provider Principal
	var network Network
	for _, candidate := range p.TrustEdges {
		if candidate.ID == ProductProviderContractEdgeID {
			edge = candidate
		}
	}
	for _, candidate := range p.Principals {
		switch candidate.Name {
		case "product-runtime":
			product = candidate
		case "provider-runtime":
			provider = candidate
		}
	}
	for _, candidate := range p.Networks {
		if candidate.Name == "product-provider" {
			network = candidate
		}
	}
	target, targetErr := netip.ParseAddrPort(edge.TargetAddress)
	subnet, subnetErr := netip.ParsePrefix(network.IPv4Subnet)
	if edge.ID != ProductProviderContractEdgeID || edge.From != product.Name || product.Name != "product-runtime" ||
		edge.To != provider.Name || provider.Name != "provider-runtime" || edge.Protocol != "https" ||
		edge.Authentication != "mtls" || edge.TenantScope != "bound" || edge.RoutePath != "/v1" ||
		targetErr != nil || subnetErr != nil || !subnet.Contains(target.Addr()) ||
		network.Kind != "trust_edge" || !network.Internal ||
		!slices.Equal(network.Principals, []string{"product-runtime", "provider-runtime"}) ||
		!slices.Contains(product.Networks, network.Name) || !slices.Contains(provider.Networks, network.Name) ||
		product.TLS == nil || provider.TLS == nil || !slices.Contains(product.TLS.Usages, "client_auth") ||
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
