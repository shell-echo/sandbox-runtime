package phase6security

// IsSlice6DNSPeerEdge is the sole exception that permits a role-owned peer-CRL
// read on an external edge without a client anchor. It does not authorize
// arbitrary external services or an inbound DNS direction. The caller still
// validates the complete profile and the issuer/source mapping separately.
func (p Profile) IsSlice6DNSPeerEdge(edgeID, localPrincipalDigest, direction string) bool {
	if direction != "outbound" || edgeID == "" || localPrincipalDigest == "" {
		return false
	}
	var spec slice6ExternalEdge
	for _, candidate := range slice6DesiredExternalEdges {
		if candidate.id == edgeID && candidate.to == "dns" && candidate.protocol == "dns_tcp" {
			spec = candidate
			break
		}
	}
	if spec.id == "" {
		return false
	}
	var broker Principal
	for _, candidate := range p.Principals {
		if candidate.Name == spec.from {
			broker = candidate
			break
		}
	}
	if broker.Name != spec.from || broker.Kind != "egress_broker" || broker.TLS == nil ||
		broker.PrincipalDigest != localPrincipalDigest || broker.AuthorizationPrincipal == nil ||
		broker.AuthorizationPrincipal.Digest() != localPrincipalDigest {
		return false
	}
	var service ExternalService
	for _, candidate := range p.External {
		if candidate.Name == "dns" {
			service = candidate
			break
		}
	}
	if service.Name != "dns" || service.URI != "spiffe://sandbox-runtime.test/external/dns" ||
		len(service.DNSNames) != 1 || service.DNSNames[0] != "dns.sandbox-runtime.test" ||
		service.IdentityDigest == "" || service.IdentityDigest != service.Digest() {
		return false
	}
	for _, edge := range p.TrustEdges {
		if edge.ID == edgeID {
			return edge.From == spec.from && edge.To == "dns" && edge.Protocol == "dns_tcp" &&
				edge.Port == 853 && edge.Authentication == "mtls" && edge.CrossDomain &&
				edge.TenantScope == "system" && edge.MaxConnectionSeconds == spec.maxSeconds &&
				edge.ServerAnchorID == "external-server-ca" && edge.ClientAnchorID == "" &&
				edge.FromURI == broker.TLS.URI && edge.FromPrincipalDigest == localPrincipalDigest &&
				edge.ToURI == service.URI && edge.ExternalIdentityDigest == service.IdentityDigest &&
				edge.ToPrincipalDigest == "" && edge.TargetAddress == "" && edge.RoutePath == ""
		}
	}
	return false
}
