package workloadtlsagent

import (
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func NewControllerPeerCRLProviderV2(profile phase6security.ProfileV2, sources phase6security.PeerCRLSources,
	expectedMappingDigest, subjectDigest string, client PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
	return newControllerPeerCRLProviderV2(profile, sources, expectedMappingDigest, subjectDigest, "", client, now)
}

func NewPostgresControllerPeerCRLProviderV2(profile phase6security.ProfileV2, sources phase6security.PeerCRLSources,
	expectedMappingDigest, owner, subjectDigest string, client PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
	if owner == "" {
		return nil, ErrUnavailable
	}
	return newControllerPeerCRLProviderV2(profile, sources, expectedMappingDigest, subjectDigest, owner, client, now)
}

func newControllerPeerCRLProviderV2(profile phase6security.ProfileV2, sources phase6security.PeerCRLSources,
	expectedMappingDigest, subjectDigest, postgresOwner string, client PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
	if client == nil || now == nil || now().IsZero() {
		return nil, ErrUnavailable
	}
	privateProfile, _, identity, err := phase6security.CompilePrivatePeerCRLAuthorizerV2(profile, sources, expectedMappingDigest)
	if err != nil {
		return nil, ErrUnavailable
	}
	found := false
	if postgresOwner == "" {
		for _, binding := range privateProfile.TLSAgentBindings {
			if binding.SubjectPrincipalDigest == subjectDigest {
				found = true
				break
			}
		}
	} else {
		bound, ok := identity.PostgresSubjectForOwner(postgresOwner)
		found = ok && bound == subjectDigest
	}
	if !found {
		return nil, ErrUnavailable
	}
	return &ControllerPeerCRLProvider{profileDigest: privateProfile.ProfileDigest, identity: identity,
		subjectDigest: subjectDigest, postgresOwner: postgresOwner, client: client, now: now}, nil
}
