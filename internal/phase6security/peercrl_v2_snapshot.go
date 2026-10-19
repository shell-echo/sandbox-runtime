package phase6security

import "encoding/json"

// CompilePrivatePeerCRLAuthorizerV2 freezes both typed inputs before compiling
// the same private snapshot. The caller must supply the independently pinned
// source digest; neither a v1 projection nor a field-only admission is used.
func CompilePrivatePeerCRLAuthorizerV2(profile ProfileV2, sources PeerCRLSources,
	expectedMappingDigest string) (ProfileV2, PeerCRLSources, PeerCRLAuthorizer, error) {
	privateProfile, privateSources, err := copyPeerCRLSnapshotV2(profile, sources)
	if err != nil {
		return ProfileV2{}, PeerCRLSources{}, PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	identity, err := CompilePeerCRLAuthorizerV2(privateProfile, privateSources, expectedMappingDigest)
	if err != nil {
		return ProfileV2{}, PeerCRLSources{}, PeerCRLAuthorizer{}, ErrInvalidProfile
	}
	return privateProfile, privateSources, identity, nil
}

// Copying is not validation. Only the public compiler above may return an
// admitted snapshot; this helper is also tested for nested alias isolation.
func copyPeerCRLSnapshotV2(profile ProfileV2, sources PeerCRLSources) (ProfileV2, PeerCRLSources, error) {
	profileDocument, err := json.Marshal(profile)
	if err != nil || len(profileDocument) == 0 || len(profileDocument) > maxBytes {
		return ProfileV2{}, PeerCRLSources{}, ErrInvalidProfile
	}
	defer clear(profileDocument)
	var privateProfile ProfileV2
	if json.Unmarshal(profileDocument, &privateProfile) != nil {
		return ProfileV2{}, PeerCRLSources{}, ErrInvalidProfile
	}
	sourcesDocument, err := json.Marshal(sources)
	if err != nil || len(sourcesDocument) == 0 || len(sourcesDocument) > 128<<10 {
		return ProfileV2{}, PeerCRLSources{}, ErrInvalidProfile
	}
	defer clear(sourcesDocument)
	var privateSources PeerCRLSources
	if json.Unmarshal(sourcesDocument, &privateSources) != nil {
		return ProfileV2{}, PeerCRLSources{}, ErrInvalidProfile
	}
	return privateProfile, privateSources, nil
}
