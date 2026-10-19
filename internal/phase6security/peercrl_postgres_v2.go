package phase6security

// PostgreSQL-purpose documents deliberately have a separate v2 entry point.
// An ordinary role document cannot grant its agent a PostgreSQL source, and
// a PostgreSQL document cannot grant the owner's ordinary internal edges.
func (d PeerCRLRoleDocument) ValidatePostgresV2(profile ProfileV2,
	expectedMappingDigest, owner, expectedLocalPrincipalDigest string) error {
	if profile.Validate() != nil || d.LocalPrincipalDigest != expectedLocalPrincipalDigest {
		return ErrInvalidProfile
	}
	return d.validatePostgresV2Fields(profile, expectedMappingDigest, owner)
}

func (d PeerCRLRoleDocument) validatePostgresV2Fields(profile ProfileV2,
	expectedMappingDigest, owner string) error {
	if owner == "" || d.Protocol != PeerCRLRoleProtocolID ||
		d.SecurityProfileDigest != profile.ProfileDigest ||
		!digestPattern.MatchString(expectedMappingDigest) || d.SourceMappingDigest != expectedMappingDigest ||
		!digestPattern.MatchString(d.LocalPrincipalDigest) || len(d.Edges) != 1 {
		return ErrInvalidProfile
	}
	required, err := requiredPeerCRLV2(profile)
	if err != nil {
		return ErrInvalidProfile
	}
	edge := d.Edges[0]
	wanted, exists := required[peerCRLRequiredV2Key(edge.EdgeID, d.LocalPrincipalDigest, edge.Direction)]
	if !exists || wanted.PostgresOwner != owner || edge.Direction != "outbound" ||
		edge.PeerAnchorID != wanted.PeerAnchorID || !digestPattern.MatchString(edge.IssuerDigest) {
		return ErrInvalidProfile
	}
	return nil
}

func DerivePostgresPeerCRLRoleDocumentV2(profile ProfileV2, sources PeerCRLSources,
	expectedMappingDigest, owner string) (PeerCRLRoleDocument, error) {
	if profile.Validate() != nil || sources.Digest() != expectedMappingDigest {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return derivePostgresPeerCRLRoleDocumentV2Fields(profile, sources, owner)
}

func derivePostgresPeerCRLRoleDocumentV2Fields(profile ProfileV2, sources PeerCRLSources,
	owner string) (PeerCRLRoleDocument, error) {
	if owner == "" || sources.validateV2Fields(profile) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	required, err := requiredPeerCRLV2(profile)
	if err != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	document := PeerCRLRoleDocument{Protocol: PeerCRLRoleProtocolID,
		SecurityProfileDigest: profile.ProfileDigest, SourceMappingDigest: sources.Digest()}
	for _, binding := range sources.Edges {
		wanted := required[peerCRLRequiredV2Key(binding.EdgeID, binding.LocalPrincipalDigest, binding.Direction)]
		if wanted.PostgresOwner != owner {
			continue
		}
		if document.LocalPrincipalDigest != "" {
			return PeerCRLRoleDocument{}, ErrInvalidProfile
		}
		document.LocalPrincipalDigest = binding.LocalPrincipalDigest
		for _, source := range sources.Sources {
			if source.ID == binding.SourceID {
				document.Edges = []PeerCRLRoleEdgeBinding{{EdgeID: binding.EdgeID,
					Direction: binding.Direction, PeerAnchorID: binding.PeerAnchorID, IssuerDigest: source.IssuerDigest}}
			}
		}
	}
	if document.validatePostgresV2Fields(profile, sources.Digest(), owner) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return document, nil
}
