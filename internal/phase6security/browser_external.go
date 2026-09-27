package phase6security

import "slices"

// Browser capacity and action history are different external authorities. A
// trust edge names the service identity; its caller's sole egress policy fixes
// the dial target. Neither a DNS alias nor a second policy may replace it.
func validateBrowserExternalAuthority(services map[string]ExternalService, edges map[string]TrustEdge, policies []EgressPolicy) error {
	witness, capacity, productDB := services["action-history-postgres"], services["capacity-valkey"], services["postgres"]
	if len(witness.DNSNames) != 1 || len(capacity.DNSNames) != 1 ||
		witness.DNSNames[0] == capacity.DNSNames[0] || witness.DNSNames[0] == productDB.DNSNames[0] ||
		capacity.DNSNames[0] == productDB.DNSNames[0] ||
		witness.URI == productDB.URI || capacity.URI == productDB.URI {
		return ErrInvalidProfile
	}
	type externalEdge struct {
		id, from, to, protocol string
		port                   int
	}
	required := []externalEdge{
		{"browser-action-history-postgres", "browser-action-ingress-runtime", "action-history-postgres", "postgres", 5432},
		{"browser-capacity-valkey", "browser-action-ingress-runtime", "capacity-valkey", "tls", 6379},
		{"egress-browser-action-history-postgres", "egress-broker-browser-action-ingress", "action-history-postgres", "postgres", 5432},
		{"egress-browser-capacity-valkey", "egress-broker-browser-action-ingress", "capacity-valkey", "tls", 6379},
		{"egress-gateway-capacity-valkey", "egress-broker-gateway", "capacity-valkey", "tls", 6379},
		{"gateway-capacity-valkey", "gateway-runtime", "capacity-valkey", "tls", 6379},
	}
	for _, spec := range required {
		edge, ok := edges[spec.id]
		service := services[spec.to]
		if !ok || edge.From != spec.from || edge.To != spec.to || edge.Protocol != spec.protocol || edge.Port != spec.port ||
			edge.Authentication != "mtls" || edge.ServerAnchorID != "external-server-ca" || edge.ClientAnchorID != "" ||
			edge.TenantScope != "bound" || !edge.CrossDomain || edge.TargetAddress != "" || edge.RoutePath != "" ||
			edge.ExternalIdentityDigest != service.IdentityDigest || edge.ToURI != service.URI ||
			!slices.Contains(service.IngressEdges, spec.id) {
			return ErrInvalidProfile
		}
	}
	for _, spec := range []struct{ id, broker string }{
		{"egress-dns-browser-action-ingress", "egress-broker-browser-action-ingress"},
		{"egress-dns-gateway", "egress-broker-gateway"},
	} {
		service := services["dns"]
		edge, ok := edges[spec.id]
		if !ok || edge.From != spec.broker || edge.To != "dns" || edge.Protocol != "dns_tcp" || edge.Port != 853 ||
			edge.Authentication != "mtls" || edge.ServerAnchorID != "external-server-ca" || edge.ClientAnchorID != "" ||
			edge.TenantScope != "system" || !edge.CrossDomain || edge.ExternalIdentityDigest != service.IdentityDigest ||
			edge.ToURI != service.URI || !slices.Contains(service.IngressEdges, spec.id) {
			return ErrInvalidProfile
		}
		count := 0
		for _, candidate := range edges {
			if candidate.From == spec.broker && candidate.To == "dns" {
				count++
			}
		}
		if count != 1 {
			return ErrInvalidProfile
		}
	}
	for _, service := range []struct {
		name string
		all  []string
	}{
		{"action-history-postgres", []string{"browser-action-history-postgres", "egress-browser-action-history-postgres"}},
		{"capacity-valkey", []string{"browser-capacity-valkey", "egress-browser-capacity-valkey", "egress-gateway-capacity-valkey", "gateway-capacity-valkey"}},
	} {
		if !slices.Equal(services[service.name].IngressEdges, service.all) {
			return ErrInvalidProfile
		}
		for _, edge := range edges {
			if edge.To == service.name && !slices.Contains(service.all, edge.ID) {
				return ErrInvalidProfile
			}
		}
	}
	for _, edge := range edges {
		if edge.From != "gateway-runtime" && edge.From != "browser-action-ingress-runtime" {
			continue
		}
		if _, external := services[edge.To]; external && edge.ID != "gateway-capacity-valkey" &&
			edge.ID != "browser-capacity-valkey" && edge.ID != "browser-action-history-postgres" {
			return ErrInvalidProfile
		}
	}
	type egressSpec struct {
		id, principal, broker, authority, roleEdge, authorityEdge string
		targets                                                   []EgressTarget
	}
	specs := []egressSpec{
		{"browser-action-ingress-egress", "browser-action-ingress-runtime", "egress-broker-browser-action-ingress", "egress-policy-authority-browser-action-ingress", "egress-role-browser-action-ingress", "egress-authority-browser-action-ingress", []EgressTarget{
			{Alias: "action-history", Host: services["action-history-postgres"].DNSNames[0], Port: 5432, Protocol: "postgres"},
			{Alias: "capacity", Host: services["capacity-valkey"].DNSNames[0], Port: 6379, Protocol: "tls"},
		}},
		{"gateway-egress", "gateway-runtime", "egress-broker-gateway", "egress-policy-authority-gateway", "egress-role-gateway", "egress-authority-gateway", []EgressTarget{
			{Alias: "capacity", Host: services["capacity-valkey"].DNSNames[0], Port: 6379, Protocol: "tls"},
		}},
	}
	for _, spec := range specs {
		found := false
		for _, policy := range policies {
			if policy.ID != spec.id {
				continue
			}
			if found || policy.Principal != spec.principal || policy.Broker != spec.broker ||
				policy.Authority.DeploymentName != spec.authority || !slices.Equal(policy.Targets, spec.targets) {
				return ErrInvalidProfile
			}
			found = true
		}
		role, roleOK := edges[spec.roleEdge]
		authority, authorityOK := edges[spec.authorityEdge]
		if !found || !roleOK || role.From != spec.principal || role.To != spec.broker || role.Protocol != "tls" ||
			role.Port != 8443 || role.Authentication != "mtls" || role.ServerAnchorID != "internal-server-ca" ||
			role.ClientAnchorID != "internal-client-ca" || role.TenantScope != "system" ||
			!authorityOK || authority.From != spec.broker || authority.To != spec.authority ||
			authority.Protocol != "unix" || authority.Authentication != "unix_peer_credentials" ||
			authority.TenantScope != "system" {
			return ErrInvalidProfile
		}
	}
	return nil
}
