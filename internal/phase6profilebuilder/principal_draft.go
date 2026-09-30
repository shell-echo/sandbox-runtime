package phase6profilebuilder

import "github.com/shell-echo/sandbox-runtime/internal/phase6security"

// PrincipalDraft is the first deterministic, non-launchable Slice 6 profile
// layer. Images, resources, TLS artifacts, external services, the remaining
// mounts/edges and the final profile digest must still be bound and verified.
type PrincipalDraft struct {
	Principals              []phase6security.Principal
	Networks                []phase6security.Network
	CredentialIssuerSockets []phase6security.CredentialIssuerSocketBinding
	ImageSupply             ImageSupply
}

// BuildSlice6PrincipalDraft composes fresh identities, reviewed UID/GID and
// network placement, then the exact per-client credential issuer mounts.
func BuildSlice6PrincipalDraft(runID, environmentDigest, principalProfileDigest string) (PrincipalDraft, error) {
	principals, err := newPrincipalSkeleton(runID, environmentDigest, principalProfileDigest)
	if err != nil {
		return PrincipalDraft{}, err
	}
	placed, networks, err := bindPrincipalPlacement(principals)
	if err != nil {
		return PrincipalDraft{}, err
	}
	bound, credentialSockets, err := bindCredentialIssuerSockets(placed)
	if err != nil {
		return PrincipalDraft{}, err
	}
	return PrincipalDraft{Principals: bound, Networks: networks, CredentialIssuerSockets: credentialSockets}, nil
}
