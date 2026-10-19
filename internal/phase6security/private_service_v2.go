package phase6security

// PrivateServiceBoundaryV2 describes one closed Provider-to-Control/Scanner
// edge. A scope never selects an arbitrary deployment, route or address.
type PrivateServiceBoundaryV2 struct {
	Edge                       TrustEdge
	Provider, Service          Principal
	ServerAnchor, ClientAnchor TrustAnchor
}

func (p ProfileV2) PrivateServiceBoundary(scope, address string) (PrivateServiceBoundaryV2, error) {
	if p.Validate() != nil {
		return PrivateServiceBoundaryV2{}, ErrInvalidProfile
	}
	return p.privateServiceBoundaryFields(scope, address)
}

func (p ProfileV2) privateServiceBoundaryFields(scope, address string) (PrivateServiceBoundaryV2, error) {
	var selected ControlEndpointV2
	if scope == "scanner" {
		a := p.ArtifactScanner
		selected = ControlEndpointV2{Scope: scope, ProviderDeployment: a.ProviderDeployment, Network: a.Network, EdgeID: a.EdgeID, RoutePath: a.RoutePath}
	} else {
		for _, candidate := range v2ControlScopes {
			if candidate.Scope == scope {
				selected = candidate
			}
		}
	}
	if selected.Scope == "" {
		return PrivateServiceBoundaryV2{}, ErrInvalidProfile
	}
	principals := make(map[string]Principal, len(p.Principals))
	edges := make(map[string]TrustEdge, len(p.TrustEdges))
	for _, v := range p.Principals {
		if _, exists := principals[v.Name]; exists {
			return PrivateServiceBoundaryV2{}, ErrInvalidProfile
		}
		principals[v.Name] = v
	}
	for _, v := range p.TrustEdges {
		if _, exists := edges[v.ID]; exists {
			return PrivateServiceBoundaryV2{}, ErrInvalidProfile
		}
		edges[v.ID] = v
	}
	target := p.DockerControl.Deployment
	if scope == "scanner" {
		target = p.ArtifactScanner.Deployment
		if validateV2ScannerAuthority(p, principals, edges) != nil {
			return PrivateServiceBoundaryV2{}, ErrInvalidProfile
		}
	} else if validateV2ControlAuthority(p, principals, edges) != nil {
		return PrivateServiceBoundaryV2{}, ErrInvalidProfile
	}
	edge, ok := edges[selected.EdgeID]
	if !ok || edge.TargetAddress != address || edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 300 {
		return PrivateServiceBoundaryV2{}, ErrInvalidProfile
	}
	server, client, err := edgeTrustAnchorsFields(p.TrustEdges, p.TrustAnchors, edge.ID)
	if err != nil {
		return PrivateServiceBoundaryV2{}, err
	}
	return PrivateServiceBoundaryV2{Edge: edge, Provider: principals[selected.ProviderDeployment], Service: principals[target], ServerAnchor: server, ClientAnchor: client}, nil
}
