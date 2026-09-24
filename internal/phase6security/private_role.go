package phase6security

import (
	"net/netip"
	"slices"
)

// PrivateRoleAttachBoundary selects exactly one approved Provider-instance to
// Browser/Desktop private attach edge. The executor-backend edge is separate.
func (p Profile) PrivateRoleAttachBoundary(role, listenAddress string) (
	TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	var edgeID, providerName, roleName string
	switch role {
	case "browser":
		edgeID, providerName, roleName = "provider-browser-attach", "provider-browser-runtime", "browser-runtime-role"
	case "desktop":
		edgeID, providerName, roleName = "provider-desktop-attach", "provider-desktop-runtime", "desktop-runtime-role"
	default:
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	var edge TrustEdge
	var provider, receiver Principal
	for _, candidate := range p.TrustEdges {
		if candidate.ID == edgeID {
			edge = candidate
		}
	}
	for _, candidate := range p.Principals {
		switch candidate.Name {
		case providerName:
			provider = candidate
		case roleName:
			receiver = candidate
		}
	}
	target, targetErr := netip.ParseAddrPort(listenAddress)
	if edge.ID != edgeID || edge.From != providerName || edge.To != roleName ||
		edge.Protocol != "wss" || edge.Authentication != "mtls" || edge.RoutePath != "/executor" ||
		edge.TargetAddress != listenAddress || targetErr != nil || int(target.Port()) != edge.Port ||
		provider.TLS == nil || receiver.TLS == nil ||
		edge.FromPrincipalDigest != provider.PrincipalDigest || edge.ToPrincipalDigest != receiver.PrincipalDigest ||
		edge.FromURI != provider.TLS.URI || edge.ToURI != receiver.TLS.URI ||
		!slices.Contains(provider.TLS.Usages, "client_auth") ||
		!slices.Contains(receiver.TLS.Usages, "server_auth") || len(receiver.TLS.DNSNames) != 1 {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	serverAnchor, clientAnchor, err := p.EdgeTrustAnchors(edgeID)
	if err != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	return edge, provider, receiver, serverAnchor, clientAnchor, nil
}

// PrivateRoleBackendBoundary selects the separate Browser/Desktop role to
// executor-backend edge. Its server root cannot be substituted for attach.
func (p Profile) PrivateRoleBackendBoundary(role, origin string) (
	TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	var edgeID, roleName, backendName string
	switch role {
	case "browser":
		edgeID, roleName, backendName = "executor-browser", "browser-runtime-role", "browser-executor-backend"
	case "desktop":
		edgeID, roleName, backendName = "executor-desktop", "desktop-runtime-role", "desktop-executor-backend"
	default:
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	var edge TrustEdge
	var caller, backend Principal
	for _, candidate := range p.TrustEdges {
		if candidate.ID == edgeID {
			edge = candidate
		}
	}
	for _, candidate := range p.Principals {
		switch candidate.Name {
		case roleName:
			caller = candidate
		case backendName:
			backend = candidate
		}
	}
	if edge.ID != edgeID || edge.From != roleName || edge.To != backendName ||
		edge.Protocol != "wss" || edge.Authentication != "mtls" || edge.RoutePath != "/executor" ||
		origin != "wss://"+edge.TargetAddress+edge.RoutePath || caller.TLS == nil || backend.TLS == nil ||
		edge.FromPrincipalDigest != caller.PrincipalDigest || edge.ToPrincipalDigest != backend.PrincipalDigest ||
		edge.FromURI != caller.TLS.URI || edge.ToURI != backend.TLS.URI ||
		!slices.Contains(caller.TLS.Usages, "client_auth") ||
		!slices.Equal(backend.TLS.Usages, []string{"server_auth"}) ||
		len(backend.TLS.DNSNames) != 1 || !validDNSName(backend.TLS.DNSNames[0]) {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	serverAnchor, clientAnchor, err := p.EdgeTrustAnchors(edgeID)
	if err != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	return edge, caller, backend, serverAnchor, clientAnchor, nil
}
