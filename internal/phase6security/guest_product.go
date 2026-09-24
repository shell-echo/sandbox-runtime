package phase6security

import "slices"

// GuestProductBoundary resolves only the outbound Guest-control connection
// into Product. Product's public API listener and Provider Contract are not
// interchangeable with this private receiver.
func (p Profile) GuestProductBoundary(origin string) (
	TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	var edge TrustEdge
	var guest, product Principal
	for _, candidate := range p.TrustEdges {
		if candidate.ID == "guest-product" {
			edge = candidate
		}
	}
	for _, principal := range p.Principals {
		switch principal.Name {
		case "guest-runtime":
			guest = principal
		case "product-runtime":
			product = principal
		}
	}
	if edge.ID != "guest-product" || edge.From != guest.Name || edge.To != product.Name ||
		edge.Protocol != "wss" || edge.Authentication != "mtls" || edge.RoutePath != "/agent" ||
		origin != "wss://"+edge.TargetAddress+edge.RoutePath || guest.TLS == nil || product.TLS == nil ||
		edge.FromPrincipalDigest != guest.PrincipalDigest || edge.ToPrincipalDigest != product.PrincipalDigest ||
		edge.FromURI != guest.TLS.URI || edge.ToURI != product.TLS.URI ||
		!slices.Contains(guest.TLS.Usages, "client_auth") ||
		!slices.Contains(product.TLS.Usages, "server_auth") || len(product.TLS.DNSNames) != 1 ||
		!validDNSName(product.TLS.DNSNames[0]) {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	serverAnchor, clientAnchor, err := p.EdgeTrustAnchors(edge.ID)
	if err != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	return edge, guest, product, serverAnchor, clientAnchor, nil
}
