package phase6security

import "github.com/shell-echo/sandbox-runtime/internal/securityprincipal"

// These accessors admit the complete typed v2 authority before resolving a
// command's immutable startup inputs. They never project through Profile v1.
func (p ProfileV2) PrincipalRegistry() (*securityprincipal.Registry, error) {
	if p.Validate() != nil {
		return nil, ErrInvalidProfile
	}
	return p.principalRegistryV2()
}

func (p ProfileV2) TLSAgentForSubject(subject string) (TLSAgentBinding, Principal, Principal, error) {
	if p.Validate() != nil {
		return TLSAgentBinding{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	return tlsAgentForSubjectFields(p.TLSAgentBindings, p.Principals, subject)
}

func (p ProfileV2) PostgresClientSignerForOwner(owner string) (PostgresClientAgentBinding, Slice6PostgresSignerTarget, Principal, Principal, TrustAnchor, error) {
	if p.Validate() != nil {
		return PostgresClientAgentBinding{}, Slice6PostgresSignerTarget{}, Principal{}, Principal{}, TrustAnchor{}, ErrInvalidProfile
	}
	return postgresClientSignerForOwnerFields(p.PostgresClientAgents, p.Principals, p.TrustAnchors, owner)
}

func (p ProfileV2) CredentialIssuerSocketForClient(name string) (CredentialIssuerSocketBinding, Principal, Principal, error) {
	if p.Validate() != nil {
		return CredentialIssuerSocketBinding{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	return credentialIssuerSocketForClientFields(p.CredentialIssuerSockets, p.Principals, name)
}

func (p ProfileV2) EdgeTrustAnchors(edgeID string) (TrustAnchor, TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	return edgeTrustAnchorsFields(p.TrustEdges, p.TrustAnchors, edgeID)
}

func (p ProfileV2) ConsumerTrustAnchor(anchorID, consumer, purpose string) (TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustAnchor{}, ErrInvalidProfile
	}
	return consumerTrustAnchorFields(p.TrustAnchors, anchorID, consumer, purpose)
}
