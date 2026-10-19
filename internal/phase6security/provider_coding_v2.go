package phase6security

import (
	"reflect"
	"slices"
	"sort"
)

// ResolveSlice6FinalPostgresAuthority admits the typed v2 authority, then
// closes the unchanged nine-owner PostgreSQL graph before returning a target.
// It does not attest live HBA/SQL grants or enable the held v2 profile.
func (p ProfileV2) ResolveSlice6FinalPostgresAuthority(owner string) (Slice6PostgresAuthority, error) {
	if p.Validate() != nil {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	return p.resolvePostgresV2Fields(owner)
}

func (p ProfileV2) resolvePostgresV2Fields(owner string) (Slice6PostgresAuthority, error) {
	if p.verifyPostgresV2Fields() != nil {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	return resolveSlice6PostgresAuthorityFields(p.PostgresClientAgents, p.Principals, p.TrustAnchors, p.External, p.TrustEdges, owner)
}

// Check the actual profile, not just the frozen recipe used to compute a dial
// address. Extra PG networks/edges, renamed peers and broker/direct changes
// must fail even when the caller recomputes its enclosing profile digest.
func (p ProfileV2) verifyPostgresV2Fields() error {
	if p.PostgresServerAuth.Scope != postgresSharedAuthScope || p.PostgresServerAuth.IngressCIDR != "" ||
		p.PostgresServerAuth.HBAArtifactID != "shared-postgres-hba" {
		return ErrInvalidProfile
	}
	paths := Slice6DesiredFinalExternalTransports()
	wantedNetworks := map[string]Network{}
	var networkNames, ingress []string
	for _, path := range paths {
		if path.Service != "postgres" {
			continue
		}
		for _, network := range Slice6DesiredFinalServiceBridges() {
			if network.Name == path.Network {
				wantedNetworks[network.Name] = network
				networkNames = append(networkNames, network.Name)
			}
		}
	}
	if len(wantedNetworks) != 9 || len(networkNames) != 9 {
		return ErrInvalidProfile
	}
	seen := map[string]bool{}
	for _, network := range p.Networks {
		wanted, exists := wantedNetworks[network.Name]
		if exists {
			if seen[network.Name] || !reflect.DeepEqual(network, wanted) {
				return ErrInvalidProfile
			}
			seen[network.Name] = true
		} else if slices.Contains(network.ExternalServices, "postgres") {
			return ErrInvalidProfile
		}
	}
	if len(seen) != 9 {
		return ErrInvalidProfile
	}
	expected := map[string]slice6ExternalEdge{}
	for _, edge := range Slice6DesiredFinalExternalEdges() {
		if edge.to == "postgres" {
			expected[edge.id] = edge
			ingress = append(ingress, edge.id)
		}
	}
	seen = map[string]bool{}
	for _, edge := range p.TrustEdges {
		wanted, exists := expected[edge.ID]
		if !exists {
			if edge.To == "postgres" {
				return ErrInvalidProfile
			}
			continue
		}
		if seen[edge.ID] || edge.From != wanted.from || edge.To != wanted.to || edge.Protocol != wanted.protocol ||
			edge.Port != wanted.port || edge.RoutePath != "" || edge.TenantScope != wanted.scope ||
			edge.MaxConnectionSeconds != wanted.maxSeconds || edge.Authentication != "mtls" ||
			edge.ServerAnchorID != "external-server-ca" || edge.ClientAnchorID != "" || !edge.CrossDomain || edge.TargetAddress != "" {
			return ErrInvalidProfile
		}
		seen[edge.ID] = true
	}
	if len(seen) != len(expected) {
		return ErrInvalidProfile
	}
	sort.Strings(networkNames)
	sort.Strings(ingress)
	count := 0
	for _, service := range p.External {
		if service.Name != "postgres" {
			continue
		}
		count++
		if service.URI != "spiffe://sandbox-runtime.test/external/postgres" || !slices.Equal(service.DNSNames, []string{"postgres.sandbox-runtime.test"}) ||
			!slices.Equal(service.Networks, networkNames) || !slices.Equal(service.IngressEdges, ingress) {
			return ErrInvalidProfile
		}
	}
	if count != 1 {
		return ErrInvalidProfile
	}
	return nil
}

func (p ProfileV2) ProductProviderInstanceBoundary(owner string) (TrustEdge, Principal, Principal, TrustAnchor, TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustEdge{}, Principal{}, Principal{}, TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	return productProviderInstanceBoundaryFields(p.TrustEdges, p.Principals, p.Networks, p.TrustAnchors, owner)
}

func (p ProfileV2) Slice6MaterialSocketForOwner(owner string) (Slice6MaterialSocketBinding, error) {
	if p.Validate() != nil {
		return Slice6MaterialSocketBinding{}, ErrInvalidProfile
	}
	for _, binding := range p.MaterialSockets {
		if binding.OwnerDeployment == owner {
			return binding, nil
		}
	}
	return Slice6MaterialSocketBinding{}, ErrInvalidProfile
}

func BuildSlice6DesiredMaterialAccessV2(p ProfileV2) ([]Slice6MaterialAccess, error) {
	if p.Validate() != nil {
		return nil, ErrInvalidProfile
	}
	return buildSlice6MaterialAccessFields(p.ProfileDigest, p.Principals, p.CredentialIssuerSockets)
}
