package phase6security

import "encoding/json"

// PeerCRLAuthorizer is a finite, private lookup compiled only from an already
// private Profile/Sources snapshot. Its constructor fully validates the very
// same snapshot it compiles. Callers must not publish or mutate that snapshot;
// this value retains only scalar copies and no references to its slices/maps.
// A changed document requires a new constructor and the existing restart and
// source-reopen gates. This indexes static authority, never CRL evidence.
type PeerCRLAuthorizer struct {
	profileDigest, mappingDigest string
	entries                      map[peerCRLAuthorizationKey]peerCRLAuthorization
	postgresSubjects             map[string]string
}

type peerCRLAuthorizationKey struct {
	edgeID, localPrincipalDigest, direction, peerAnchorID, issuerDigest string
}

type peerCRLAuthorization struct {
	sourceID, postgresOwner string
}

func CompilePeerCRLAuthorizer(profile Profile, sources PeerCRLSources) (PeerCRLAuthorizer, error) {
	postgresOwners, err := sources.validatedPostgresOwners(profile)
	if err != nil {
		return PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	bySource := make(map[string]PeerCRLSource, len(sources.Sources))
	for _, source := range sources.Sources {
		if _, duplicate := bySource[source.ID]; duplicate {
			return PeerCRLAuthorizer{}, ErrInvalidProfile
		}
		bySource[source.ID] = source
	}
	// validatedPostgresOwners projected the nine final-Profile owners during
	// the same source validation. Never revalidate the full graph to rediscover
	// them, and never permit a non-final logical PostgreSQL peer.
	entries := make(map[peerCRLAuthorizationKey]peerCRLAuthorization, len(sources.Edges))
	postgresSubjects := make(map[string]string, len(postgresOwners))
	for _, binding := range sources.Edges {
		source, known := bySource[binding.SourceID]
		if !known {
			return PeerCRLAuthorizer{}, ErrInvalidProfile
		}
		key := peerCRLAuthorizationKey{binding.EdgeID, binding.LocalPrincipalDigest,
			binding.Direction, binding.PeerAnchorID, source.IssuerDigest}
		if _, duplicate := entries[key]; duplicate {
			return PeerCRLAuthorizer{}, ErrInvalidProfile
		}
		owner := postgresOwners[[2]string{binding.EdgeID, binding.LocalPrincipalDigest}]
		if owner != "" && binding.Direction != "outbound" {
			return PeerCRLAuthorizer{}, ErrInvalidProfile
		}
		entries[key] = peerCRLAuthorization{sourceID: source.ID, postgresOwner: owner}
		if owner != "" {
			postgresSubjects[owner] = binding.LocalPrincipalDigest
		}
	}
	if len(entries) != len(sources.Edges) || len(entries) == 0 {
		return PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	return PeerCRLAuthorizer{profileDigest: profile.ProfileDigest,
		mappingDigest: sources.Digest(), entries: entries, postgresSubjects: postgresSubjects}, nil
}

// CompilePrivatePeerCRLAuthorizer makes one bounded, typed private copy and
// validates that same copy exactly through CompilePeerCRLAuthorizer. The JSON
// is generated from Go values, so unknown/duplicate/noncanonical input is not
// an alternate ingress; file decoders remain strict and unchanged. Neither
// returned value aliases the caller's slices. No skip-validation API exists.
func CompilePrivatePeerCRLAuthorizer(profile Profile, sources PeerCRLSources) (Profile, PeerCRLSources, PeerCRLAuthorizer, error) {
	profileDocument, err := json.Marshal(profile)
	if err != nil || len(profileDocument) < 1 || len(profileDocument) > maxBytes {
		return Profile{}, PeerCRLSources{}, PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	defer clear(profileDocument)
	var privateProfile Profile
	if json.Unmarshal(profileDocument, &privateProfile) != nil {
		return Profile{}, PeerCRLSources{}, PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	sourcesDocument, err := json.Marshal(sources)
	if err != nil || len(sourcesDocument) < 1 || len(sourcesDocument) > 128<<10 {
		return Profile{}, PeerCRLSources{}, PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	defer clear(sourcesDocument)
	var privateSources PeerCRLSources
	if json.Unmarshal(sourcesDocument, &privateSources) != nil {
		return Profile{}, PeerCRLSources{}, PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	identity, err := CompilePeerCRLAuthorizer(privateProfile, privateSources)
	if err != nil {
		return Profile{}, PeerCRLSources{}, PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	return privateProfile, privateSources, identity, nil
}

// AuthorizedSourceID checks the exact signed/requested tuple against the
// constructor-validated snapshot. postgresOwner must be the policy's fixed
// owner for a PostgreSQL-purpose signer; it must be empty for an ordinary
// signer. It exposes only the opaque source ID, never Vault coordinates.
func (a PeerCRLAuthorizer) AuthorizedSourceID(profileDigest, mappingDigest, edgeID, localPrincipalDigest,
	direction, peerAnchorID, issuerDigest, postgresOwner string) (string, error) {
	if a.entries == nil || a.profileDigest == "" || a.mappingDigest == "" ||
		profileDigest != a.profileDigest || mappingDigest != a.mappingDigest ||
		!digestPattern.MatchString(issuerDigest) {
		return "", ErrInvalidProfile
	}
	entry, found := a.entries[peerCRLAuthorizationKey{edgeID, localPrincipalDigest, direction,
		peerAnchorID, issuerDigest}]
	if !found || entry.sourceID == "" || entry.postgresOwner != postgresOwner {
		return "", ErrInvalidProfile
	}
	return entry.sourceID, nil
}

func (a PeerCRLAuthorizer) MappingDigest() string { return a.mappingDigest }

// PostgresSubjectForOwner is constructor-only metadata from the validated
// final authority and a present source binding. It grants no CRL read.
func (a PeerCRLAuthorizer) PostgresSubjectForOwner(owner string) (string, bool) {
	digest, ok := a.postgresSubjects[owner]
	return digest, ok && digest != ""
}
