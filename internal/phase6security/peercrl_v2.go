package phase6security

import (
	"slices"
	"strings"
)

// Profile v2 keeps the existing CRL document wire and digest domains. Its
// authorization graph is independent: neither entry point projects v2 fields
// into a v1 Profile nor invokes a v1 admission validator.
func (p PeerCRLSources) ValidateV2(profile ProfileV2) error {
	if profile.Validate() != nil {
		return ErrInvalidProfile
	}
	return p.validateV2Fields(profile)
}

type peerCRLRequiredV2 struct {
	PeerCRLRoleEdgeBinding
	LocalPrincipalDigest string
	PostgresOwner        string
}

func peerCRLRequiredV2Key(edgeID, principalDigest, direction string) string {
	return edgeID + "/" + principalDigest + "/" + direction
}

func requiredPeerCRLV2(profile ProfileV2) (map[string]peerCRLRequiredV2, error) {
	if profile.validateFields() != nil {
		return nil, ErrInvalidProfile
	}
	result := make(map[string]peerCRLRequiredV2)
	add := func(edge TrustEdge, principalDigest, direction, anchor, postgresOwner string) error {
		if !digestPattern.MatchString(principalDigest) || anchor == "" {
			return ErrInvalidProfile
		}
		key := peerCRLRequiredV2Key(edge.ID, principalDigest, direction)
		if _, duplicate := result[key]; duplicate {
			return ErrInvalidProfile
		}
		result[key] = peerCRLRequiredV2{PeerCRLRoleEdgeBinding: PeerCRLRoleEdgeBinding{
			EdgeID: edge.ID, Direction: direction, PeerAnchorID: anchor},
			LocalPrincipalDigest: principalDigest, PostgresOwner: postgresOwner}
		return nil
	}
	for _, edge := range profile.TrustEdges {
		if edge.Authentication != "mtls" || edge.ClientAnchorID == "" {
			continue
		}
		if v2LocalAgentOwnsEdge(profile, edge.From, edge.FromPrincipalDigest) {
			if add(edge, edge.FromPrincipalDigest, "outbound", edge.ServerAnchorID, "") != nil {
				return nil, ErrInvalidProfile
			}
		}
		if v2LocalAgentOwnsEdge(profile, edge.To, edge.ToPrincipalDigest) {
			if add(edge, edge.ToPrincipalDigest, "inbound", edge.ClientAnchorID, "") != nil {
				return nil, ErrInvalidProfile
			}
		}
	}
	for _, desired := range slice6DesiredExternalEdges {
		if desired.to != "dns" || desired.protocol != "dns_tcp" {
			continue
		}
		var edge TrustEdge
		for _, candidate := range profile.TrustEdges {
			if candidate.ID == desired.id {
				edge = candidate
			}
		}
		var broker Principal
		var dns ExternalService
		for _, principal := range profile.Principals {
			if principal.Name == desired.from {
				broker = principal
			}
		}
		for _, service := range profile.External {
			if service.Name == "dns" {
				dns = service
			}
		}
		if edge.ID != desired.id || edge.From != desired.from || edge.To != "dns" ||
			edge.Protocol != "dns_tcp" || edge.Port != desired.port || !edge.CrossDomain ||
			edge.Authentication != "mtls" || edge.ServerAnchorID != "external-server-ca" ||
			edge.ClientAnchorID != "" || edge.TenantScope != desired.scope ||
			edge.MaxConnectionSeconds != desired.maxSeconds || edge.TargetAddress != "" ||
			edge.RoutePath != "" || broker.Kind != "egress_broker" || broker.TLS == nil ||
			edge.FromPrincipalDigest != broker.PrincipalDigest || edge.FromURI != broker.TLS.URI ||
			edge.ToPrincipalDigest != "" || edge.ToURI != dns.URI ||
			edge.ExternalIdentityDigest != dns.IdentityDigest ||
			!v2LocalAgentOwnsEdge(profile, edge.From, edge.FromPrincipalDigest) ||
			add(edge, edge.FromPrincipalDigest, "outbound", edge.ServerAnchorID, "") != nil {
			return nil, ErrInvalidProfile
		}
	}
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		var owner Principal
		var signer PostgresClientAgentBinding
		var edge TrustEdge
		var desired slice6ExternalEdge
		var postgres ExternalService
		for _, principal := range profile.Principals {
			if principal.Name == target.SubjectDeployment {
				owner = principal
			}
		}
		for _, binding := range profile.PostgresClientAgents {
			if binding.SubjectDeployment == target.SubjectDeployment &&
				binding.AgentDeployment == target.AgentDeployment {
				signer = binding
			}
		}
		for _, service := range profile.External {
			if service.Name == "postgres" {
				postgres = service
			}
		}
		for _, path := range Slice6DesiredFinalExternalTransports() {
			if path.LogicalCaller != target.SubjectDeployment || path.Service != "postgres" {
				continue
			}
			for _, candidate := range profile.TrustEdges {
				if slices.Contains(path.EdgeIDs, candidate.ID) &&
					candidate.From == target.SubjectDeployment && candidate.To == "postgres" {
					if edge.ID != "" {
						return nil, ErrInvalidProfile
					}
					edge = candidate
				}
			}
		}
		for _, candidate := range Slice6DesiredFinalExternalEdges() {
			if candidate.id == edge.ID {
				desired = candidate
			}
		}
		if owner.Name == "" || signer.AgentDeployment != target.AgentDeployment ||
			signer.SubjectPrincipalDigest != owner.PrincipalDigest ||
			signer.IssuerAnchorID != postgresClientIssuerAnchorID ||
			edge.ID == "" || desired.id != edge.ID || desired.from != owner.Name ||
			desired.to != "postgres" || desired.protocol != "postgres" ||
			edge.FromPrincipalDigest != owner.PrincipalDigest || owner.TLS == nil ||
			edge.FromURI != owner.TLS.URI || edge.ToURI != postgres.URI ||
			edge.ToPrincipalDigest != "" || edge.ExternalIdentityDigest != postgres.IdentityDigest ||
			edge.Protocol != desired.protocol || edge.Port != desired.port || !edge.CrossDomain ||
			edge.Authentication != "mtls" || edge.ServerAnchorID != "external-server-ca" ||
			edge.ClientAnchorID != "" || edge.TenantScope != desired.scope ||
			edge.MaxConnectionSeconds != desired.maxSeconds || edge.TargetAddress != "" ||
			edge.RoutePath != "" ||
			add(edge, owner.PrincipalDigest, "outbound", edge.ServerAnchorID, owner.Name) != nil {
			return nil, ErrInvalidProfile
		}
	}
	if len(result) == 0 || len(result) > 512 {
		return nil, ErrInvalidProfile
	}
	return result, nil
}

func v2LocalAgentOwnsEdge(profile ProfileV2, name, principalDigest string) bool {
	for _, binding := range profile.TLSAgentBindings {
		if binding.SubjectDeployment == name && binding.SubjectPrincipalDigest == principalDigest {
			return true
		}
	}
	return false
}

// validateV2Fields is testable only within this package while ProfileV2's
// public launch hold remains in force. It requires an exhaustive tuple set,
// not merely that each caller-listed mapping happens to be valid.
func (p PeerCRLSources) validateV2Fields(profile ProfileV2) error {
	required, err := requiredPeerCRLV2(profile)
	if err != nil || p.Protocol != PeerCRLSourcesProtocolID ||
		p.SecurityProfileDigest != profile.ProfileDigest ||
		len(p.Sources) != 2 || len(p.Edges) != len(required) {
		return ErrInvalidProfile
	}
	vaultDigest, vaultEdge := "", false
	brokerIssuerDigest, brokerIssuerID := "", ""
	for _, service := range profile.External {
		switch service.Name {
		case "vault":
			vaultDigest = service.IdentityDigest
		case "dns":
			if service.DNSClientCA != nil {
				brokerIssuerDigest = service.DNSClientCA.IssuerDigest
				brokerIssuerID = service.DNSClientCA.IssuerID
			}
		}
	}
	for _, edge := range profile.TrustEdges {
		if edge.ID == "certificate-vault" && edge.From == "certificate-controller" &&
			edge.To == "vault" && edge.Authentication == "mtls" {
			vaultEdge = true
		}
	}
	if vaultDigest == "" || p.VaultExternalIdentityDigest != vaultDigest || !vaultEdge ||
		!digestPattern.MatchString(brokerIssuerDigest) || !ValidSlice6IssuerID(brokerIssuerID) {
		return ErrInvalidProfile
	}
	sources := make(map[string]PeerCRLSource, len(p.Sources))
	locations, used := make(map[string]bool), make(map[string]bool)
	previous, brokerSource, generalSource := "", "", ""
	for _, source := range p.Sources {
		location := source.Mount + "/" + source.IssuerID
		if source.ID <= previous || !namePattern.MatchString(source.ID) || source.Mount != "pki" ||
			!ValidSlice6IssuerID(source.IssuerID) ||
			!digestPattern.MatchString(source.IssuerDigest) || locations[location] {
			return ErrInvalidProfile
		}
		previous = source.ID
		locations[location] = true
		sources[source.ID] = source
		if source.IssuerID == brokerIssuerID && source.IssuerDigest == brokerIssuerDigest {
			brokerSource = source.ID
		} else {
			generalSource = source.ID
		}
	}
	if brokerSource == "" || generalSource == "" || brokerSource == generalSource ||
		sources[generalSource].IssuerID == brokerIssuerID ||
		sources[generalSource].IssuerDigest == brokerIssuerDigest {
		return ErrInvalidProfile
	}
	edges := make(map[string]TrustEdge, len(profile.TrustEdges))
	for _, edge := range profile.TrustEdges {
		edges[edge.ID] = edge
	}
	previous = ""
	for _, binding := range p.Edges {
		key := peerCRLRequiredV2Key(binding.EdgeID, binding.LocalPrincipalDigest, binding.Direction)
		want, requiredEdge := required[key]
		edge, edgeExists := edges[binding.EdgeID]
		peer := edge.To
		if binding.Direction == "inbound" {
			peer = edge.From
		}
		expectedSource := generalSource
		if slices.Contains(slice6DNSBrokerSubjects, peer) {
			expectedSource = brokerSource
		}
		if key <= previous || !requiredEdge || !edgeExists ||
			binding.PeerAnchorID != want.PeerAnchorID ||
			binding.SourceID != expectedSource {
			return ErrInvalidProfile
		}
		previous = key
		used[binding.SourceID] = true
	}
	for id := range sources {
		if !used[id] {
			return ErrInvalidProfile
		}
	}
	return nil
}

func (d PeerCRLRoleDocument) ValidateV2(profile ProfileV2, expectedMappingDigest,
	expectedLocalPrincipalDigest string) error {
	if profile.Validate() != nil || d.LocalPrincipalDigest != expectedLocalPrincipalDigest {
		return ErrInvalidProfile
	}
	return d.validateV2Fields(profile, expectedMappingDigest)
}

func (d PeerCRLRoleDocument) validateV2Fields(profile ProfileV2, expectedMappingDigest string) error {
	required, err := requiredPeerCRLV2(profile)
	if err != nil || d.Protocol != PeerCRLRoleProtocolID ||
		d.SecurityProfileDigest != profile.ProfileDigest ||
		!digestPattern.MatchString(expectedMappingDigest) ||
		d.SourceMappingDigest != expectedMappingDigest ||
		!digestPattern.MatchString(d.LocalPrincipalDigest) {
		return ErrInvalidProfile
	}
	roleRequired := make([]PeerCRLRoleEdgeBinding, 0)
	for _, item := range required {
		if item.LocalPrincipalDigest == d.LocalPrincipalDigest && item.PostgresOwner == "" {
			roleRequired = append(roleRequired, item.PeerCRLRoleEdgeBinding)
		}
	}
	slices.SortFunc(roleRequired, func(a, b PeerCRLRoleEdgeBinding) int {
		return strings.Compare(a.EdgeID+"/"+a.Direction, b.EdgeID+"/"+b.Direction)
	})
	if len(roleRequired) == 0 || len(roleRequired) != len(d.Edges) {
		return ErrInvalidProfile
	}
	for index, edge := range d.Edges {
		if edge.EdgeID != roleRequired[index].EdgeID ||
			edge.Direction != roleRequired[index].Direction ||
			edge.PeerAnchorID != roleRequired[index].PeerAnchorID ||
			!digestPattern.MatchString(edge.IssuerDigest) {
			return ErrInvalidProfile
		}
	}
	return nil
}

func DerivePeerCRLRoleDocumentV2(profile ProfileV2, sources PeerCRLSources,
	expectedMappingDigest, localPrincipalDigest string) (PeerCRLRoleDocument, error) {
	if profile.Validate() != nil || sources.Digest() != expectedMappingDigest {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return derivePeerCRLRoleDocumentV2Fields(profile, sources, localPrincipalDigest)
}

func derivePeerCRLRoleDocumentV2Fields(profile ProfileV2, sources PeerCRLSources,
	localPrincipalDigest string) (PeerCRLRoleDocument, error) {
	if sources.validateV2Fields(profile) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	all, err := requiredPeerCRLV2(profile)
	if err != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	document := PeerCRLRoleDocument{Protocol: PeerCRLRoleProtocolID,
		SecurityProfileDigest: profile.ProfileDigest, SourceMappingDigest: sources.Digest(),
		LocalPrincipalDigest: localPrincipalDigest}
	for _, binding := range sources.Edges {
		if binding.LocalPrincipalDigest != localPrincipalDigest {
			continue
		}
		required := all[peerCRLRequiredV2Key(binding.EdgeID, binding.LocalPrincipalDigest, binding.Direction)]
		if required.PostgresOwner != "" {
			continue
		}
		for _, source := range sources.Sources {
			if source.ID == binding.SourceID {
				document.Edges = append(document.Edges, PeerCRLRoleEdgeBinding{
					EdgeID: binding.EdgeID, Direction: binding.Direction,
					PeerAnchorID: binding.PeerAnchorID, IssuerDigest: source.IssuerDigest})
			}
		}
	}
	slices.SortFunc(document.Edges, func(a, b PeerCRLRoleEdgeBinding) int {
		return strings.Compare(a.EdgeID+"/"+a.Direction, b.EdgeID+"/"+b.Direction)
	})
	if document.validateV2Fields(profile, sources.Digest()) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return document, nil
}

func CompilePeerCRLAuthorizerV2(profile ProfileV2, sources PeerCRLSources,
	expectedMappingDigest string) (PeerCRLAuthorizer, error) {
	if profile.Validate() != nil || sources.Digest() != expectedMappingDigest {
		return PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	return compilePeerCRLAuthorizerV2Fields(profile, sources)
}

// This private field-layer compiler is exercised by synthetic tests while
// ProfileV2's public admission hold remains closed. Its map retains only
// immutable scalar copies, not caller-owned Profile or source slices.
func compilePeerCRLAuthorizerV2Fields(profile ProfileV2, sources PeerCRLSources) (PeerCRLAuthorizer, error) {
	if sources.validateV2Fields(profile) != nil {
		return PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	required, err := requiredPeerCRLV2(profile)
	if err != nil {
		return PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	bySource := make(map[string]PeerCRLSource, len(sources.Sources))
	for _, source := range sources.Sources {
		bySource[source.ID] = source
	}
	index := PeerCRLAuthorizer{profileDigest: profile.ProfileDigest,
		mappingDigest: sources.Digest(), entries: make(map[peerCRLAuthorizationKey]peerCRLAuthorization, len(sources.Edges)),
		postgresSubjects: make(map[string]string)}
	for _, binding := range sources.Edges {
		source, known := bySource[binding.SourceID]
		wanted, requiredEdge := required[peerCRLRequiredV2Key(binding.EdgeID,
			binding.LocalPrincipalDigest, binding.Direction)]
		key := peerCRLAuthorizationKey{binding.EdgeID, binding.LocalPrincipalDigest,
			binding.Direction, binding.PeerAnchorID, source.IssuerDigest}
		if !known || !requiredEdge || (wanted.PostgresOwner != "" && binding.Direction != "outbound") {
			return PeerCRLAuthorizer{}, ErrInvalidProfile
		}
		if _, duplicate := index.entries[key]; duplicate {
			return PeerCRLAuthorizer{}, ErrInvalidProfile
		}
		index.entries[key] = peerCRLAuthorization{sourceID: source.ID, postgresOwner: wanted.PostgresOwner}
		if wanted.PostgresOwner != "" {
			index.postgresSubjects[wanted.PostgresOwner] = binding.LocalPrincipalDigest
		}
	}
	if len(index.entries) != len(required) {
		return PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	return index, nil
}
