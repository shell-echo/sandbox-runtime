package phase6security

import "sort"

// BuildSlice6DesiredTrustEdges binds the reviewed exact-edge policy to already
// constructed principal and external-service identities. It derives numeric
// local targets from the preapproved IPAM graph, never from a running Docker
// endpoint. The caller must separately verify external image/identity inputs
// and the final complete profile before launching anything.
func BuildSlice6DesiredTrustEdges(principals []Principal, external []ExternalService) ([]TrustEdge, error) {
	if len(principals) != len(slice6ApprovedDeploymentKinds) || len(external) != len(slice6DesiredExternalServices) {
		return nil, errSlice6DesiredInventory
	}
	byPrincipal := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		if _, approved := slice6ApprovedDeploymentKinds[principal.Name]; !approved ||
			byPrincipal[principal.Name].Name != "" {
			return nil, errSlice6DesiredInventory
		}
		byPrincipal[principal.Name] = principal
	}
	byExternal := make(map[string]ExternalService, len(external))
	for _, service := range external {
		approved := false
		for _, desired := range slice6DesiredExternalServices {
			if service.Name == desired.name && service.URI == desired.uri {
				approved = true
				break
			}
		}
		if !approved || byExternal[service.Name].Name != "" || service.IdentityDigest != service.Digest() {
			return nil, errSlice6DesiredInventory
		}
		byExternal[service.Name] = service
	}
	edges := make([]TrustEdge, 0, len(slice6DesiredTrustEdges()))
	for _, spec := range slice6DesiredTrustEdges() {
		from, found := byPrincipal[spec.from]
		if !found || from.PrincipalDigest == "" || from.TLS == nil || from.TLS.URI == "" {
			return nil, errSlice6DesiredInventory
		}
		edge := TrustEdge{ID: spec.id, From: spec.from, To: spec.to,
			Protocol: spec.protocol, Port: spec.port, RoutePath: spec.route,
			Authentication: spec.authentication, ServerAnchorID: spec.serverAnchor,
			ClientAnchorID: spec.clientAnchor, FromURI: from.TLS.URI,
			FromPrincipalDigest: from.PrincipalDigest, CrossDomain: spec.crossDomain,
			TenantScope: spec.scope, MaxConnectionSeconds: spec.maxSeconds}
		if spec.crossDomain {
			service, found := byExternal[spec.to]
			if !found || service.URI == "" || service.IdentityDigest == "" {
				return nil, errSlice6DesiredInventory
			}
			edge.ToURI, edge.ExternalIdentityDigest = service.URI, service.IdentityDigest
		} else {
			to, found := byPrincipal[spec.to]
			if !found || to.PrincipalDigest == "" || to.TLS == nil || to.TLS.URI == "" {
				return nil, errSlice6DesiredInventory
			}
			edge.ToURI, edge.ToPrincipalDigest = to.TLS.URI, to.PrincipalDigest
		}
		if spec.numericTarget {
			target, err := slice6PlannedLocalTarget(edge)
			if err != nil {
				return nil, errSlice6DesiredInventory
			}
			edge.TargetAddress = target
		}
		edges = append(edges, edge)
	}
	return edges, nil
}

// BuildSlice6DesiredFinalTrustEdges binds the additional reviewed physical
// external callers to the final 30-path graph. It remains desired policy, not
// a live TLS, SQL or external-service observation.
func BuildSlice6DesiredFinalTrustEdges(principals []Principal, external []ExternalService) ([]TrustEdge, error) {
	base, err := BuildSlice6DesiredTrustEdges(principals, external)
	if err != nil || VerifySlice6DesiredFinalExternalGraph(Slice6DesiredFinalExternalTransports(),
		Slice6DesiredFinalExternalEdges()) != nil {
		return nil, errSlice6DesiredInventory
	}
	byPrincipal := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		byPrincipal[principal.Name] = principal
	}
	byService := make(map[string]ExternalService, len(external))
	for _, service := range external {
		byService[service.Name] = service
	}
	seen := make(map[string]bool, len(base))
	for _, edge := range base {
		if seen[edge.ID] {
			return nil, errSlice6DesiredInventory
		}
		seen[edge.ID] = true
	}
	for _, spec := range Slice6DesiredFinalExternalEdges() {
		if seen[spec.id] {
			continue
		}
		from, to := byPrincipal[spec.from], byService[spec.to]
		if from.Name == "" || from.TLS == nil || from.PrincipalDigest == "" ||
			to.Name == "" || to.IdentityDigest != to.Digest() {
			return nil, errSlice6DesiredInventory
		}
		base = append(base, TrustEdge{ID: spec.id, From: spec.from, To: spec.to,
			Protocol: spec.protocol, Port: spec.port, Authentication: "mtls",
			ServerAnchorID: "external-server-ca", FromURI: from.TLS.URI, ToURI: to.URI,
			FromPrincipalDigest: from.PrincipalDigest, ExternalIdentityDigest: to.IdentityDigest,
			TenantScope: spec.scope, MaxConnectionSeconds: spec.maxSeconds, CrossDomain: true})
		seen[spec.id] = true
	}
	sort.Slice(base, func(i, j int) bool { return base[i].ID < base[j].ID })
	if len(base) != len(slice6DesiredTrustEdges())+18 {
		return nil, errSlice6DesiredInventory
	}
	return base, nil
}
