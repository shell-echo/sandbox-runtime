package workloadpki

import (
	"crypto/ed25519"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// NewControllerV2 has an explicit, externally pinned v2 admission path. It
// cannot be combined with the legacy Profile fields, nor bypass the public
// Profile-v2 hold. All profile/policy checks precede authority or ledger work.
func NewControllerV2(config ControllerConfig, profile phase6security.ProfileV2,
	sources phase6security.PeerCRLSources, expectedMappingDigest string) (*Controller, error) {
	if config.PeerCRLProfile != nil || config.PeerCRLSources != nil || len(config.ControllerKey) != ed25519.PrivateKeySize {
		return nil, ErrUnavailable
	}
	privateProfile, privateSources, identity, err := phase6security.CompilePrivatePeerCRLAuthorizerV2(profile, sources, expectedMappingDigest)
	if err != nil {
		return nil, ErrUnavailable
	}
	config.Policies = freezeControllerPolicies(config.Policies)
	if validateControllerPoliciesV2Fields(privateProfile, privateSources, config.Policies) != nil ||
		config.ControllerKeyID != privateProfile.CertificateController.ResponseKeyID ||
		phase6security.CertificateControllerPublicKeyDigest(config.ControllerKey.Public().(ed25519.PublicKey)) != privateProfile.CertificateController.ResponsePublicKeyDigest {
		return nil, ErrUnavailable
	}
	return newController(config, &controllerPeerCRLBinding{profileDigest: privateProfile.ProfileDigest,
		sources: privateSources.Sources, identity: identity})
}

// ValidateControllerPoliciesV2 is the pure startup preflight. Commands must
// call it before reading private keys or contacting credential/Vault services;
// their socket, FD, process UID/GID and request-key-ID checks remain required.
func ValidateControllerPoliciesV2(profile phase6security.ProfileV2, sources phase6security.PeerCRLSources,
	expectedMappingDigest string, policies []Policy) error {
	privateProfile, privateSources, _, err := phase6security.CompilePrivatePeerCRLAuthorizerV2(profile, sources, expectedMappingDigest)
	if err != nil {
		return ErrUnavailable
	}
	return validateControllerPoliciesV2Fields(privateProfile, privateSources, freezeControllerPolicies(policies))
}

// Only called after public v2 admission in production. Field tests can prove
// exact policy binding without making a synthetic Profile admissible.
func validateControllerPoliciesV2Fields(profile phase6security.ProfileV2, sources phase6security.PeerCRLSources, policies []Policy) error {
	if len(policies) != len(profile.TLSAgentBindings)+len(profile.PostgresClientAgents)+2 ||
		len(policies) > maxControllerPolicies || len(sources.Sources) != 2 {
		return ErrUnavailable
	}
	principals := make(map[string]phase6security.Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		if _, duplicate := principals[principal.Name]; duplicate {
			return ErrUnavailable
		}
		principals[principal.Name] = principal
	}
	byID := make(map[string]Policy, len(policies))
	for _, policy := range policies {
		if policy.Validate() != nil {
			return ErrUnavailable
		}
		if _, duplicate := byID[policy.ID]; duplicate {
			return ErrUnavailable
		}
		byID[policy.ID] = policy
	}
	brokerSource, generalSource := "", ""
	for _, external := range profile.External {
		if external.Name != "dns" || external.DNSClientCA == nil {
			continue
		}
		for _, source := range sources.Sources {
			if source.Mount != "pki" {
				return ErrUnavailable
			}
			if source.IssuerID == external.DNSClientCA.IssuerID && source.IssuerDigest == external.DNSClientCA.IssuerDigest {
				brokerSource = source.ID
			} else {
				generalSource = source.ID
			}
		}
	}
	if brokerSource == "" || generalSource == "" || brokerSource == generalSource ||
		sources.Sources[0].IssuerID == sources.Sources[1].IssuerID || sources.Sources[0].IssuerDigest == sources.Sources[1].IssuerDigest {
		return ErrUnavailable
	}
	consume := func(id, requesterName, subjectName, keyDigest, vaultRole, sourceID string, uid, gid uint32, pg *PostgresClientIdentity) bool {
		policy, found := byID[id]
		requester, subject := principals[requesterName], principals[subjectName]
		if !found || requester.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil || subject.TLS == nil {
			return false
		}
		identity := *subject.TLS
		if pg == nil {
			if policy.Purpose != "" || policy.Postgres != (PostgresClientIdentity{}) {
				return false
			}
		} else {
			if policy.Purpose != PostgresClientPurpose || policy.Postgres != *pg {
				return false
			}
			identity.DNSNames, identity.Usages = nil, []string{"client_auth"}
		}
		if policy.Requester != *requester.AuthorizationPrincipal || policy.Subject != *subject.AuthorizationPrincipal ||
			phase6security.TLSAgentRequestPublicKeyDigest(policy.PublicKey) != keyDigest ||
			policy.TrustDomain != identity.TrustDomain || policy.URI != identity.URI ||
			!slices.Equal(policy.DNSNames, identity.DNSNames) || !slices.Equal(policy.Usages, identity.Usages) ||
			policy.VaultRole != vaultRole || policy.IssuerSourceID != sourceID || policy.MaxTTLSeconds != identity.TTLSeconds ||
			policy.ExpectedUID != uid || policy.ExpectedGID != gid {
			return false
		}
		delete(byID, id)
		return true
	}
	for _, binding := range profile.TLSAgentBindings {
		sourceID := generalSource
		switch binding.SubjectDeployment {
		case "egress-broker-product", "egress-broker-gateway", "egress-broker-browser-action-ingress", "egress-broker-provider-browser", "egress-broker-provider-desktop":
			sourceID = brokerSource
		}
		if !consume(binding.IssuerPolicyID, binding.AgentDeployment, binding.SubjectDeployment, binding.AgentRequestKeyDigest,
			binding.IssuerVaultRole, sourceID, binding.AgentUID, binding.AgentGID, nil) {
			return ErrUnavailable
		}
	}
	for _, binding := range profile.PostgresClientAgents {
		var target phase6security.Slice6PostgresSignerTarget
		for _, candidate := range phase6security.Slice6DesiredFinalPostgresSignerTargets() {
			if candidate.SubjectDeployment == binding.SubjectDeployment {
				target = candidate
			}
		}
		subject := principals[binding.SubjectDeployment]
		if target.SubjectDeployment == "" || subject.TLS == nil {
			return ErrUnavailable
		}
		pg := PostgresClientIdentity{OwnerDeployment: target.SubjectDeployment, DatabaseName: target.DatabaseName,
			RuntimeRole: target.SQLRole, ServiceName: "postgres", URI: subject.TLS.URI,
			CommonName: binding.CommonName, MaxTTL: time.Duration(subject.TLS.TTLSeconds) * time.Second}
		if !consume(binding.IssuerPolicyID, binding.AgentDeployment, binding.SubjectDeployment, binding.AgentRequestKeyDigest,
			binding.IssuerVaultRole, generalSource, binding.AgentUID, binding.AgentGID, &pg) {
			return ErrUnavailable
		}
	}
	authority := profile.CertificateController
	credential := authority.CredentialController
	credentialPrincipal := principals["workload-credential-controller"]
	if !consume(authority.ManagedPolicyID, authority.DeploymentName, authority.DeploymentName, authority.ManagedRequestKeyDigest,
		authority.ManagedVaultRole, generalSource, authority.UID, authority.GID, nil) ||
		!consume(credential.PolicyID, credentialPrincipal.Name, credentialPrincipal.Name, credential.RequestKeyDigest,
			credential.VaultRole, generalSource, credentialPrincipal.UID, credentialPrincipal.GID, nil) || len(byID) != 0 {
		return ErrUnavailable
	}
	return nil
}
