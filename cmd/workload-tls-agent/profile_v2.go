package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

func validAgentConfig(c configDocument) bool {
	sources := filepath.IsAbs(c.PeerCRLSourcesPath) && c.PeerCRLSourcesDigest != ""
	switch c.Protocol {
	case peerCRLConfigProtocol, profileV2ConfigProtocol:
		return c.Purpose == "" && c.Postgres == nil && sources
	case postgresConfigProtocol, postgresV2ConfigProtocol:
		return c.Purpose == workloadpki.PostgresClientPurpose && c.Postgres != nil && sources
	default:
		return false
	}
}

// Only immutable comparison fields are shared. No v2 Profile is converted to
// the v1 admission type, and each loader has a single explicit version path.
type agentProfileFields struct {
	ProfileDigest, EnvironmentDigest, PrincipalProfileDigest string
	CertificateController                                    phase6security.CertificateControllerAuthority
}

func agentProfileFieldsV1(p phase6security.Profile) agentProfileFields {
	return agentProfileFields{p.ProfileDigest, p.EnvironmentDigest, p.PrincipalProfileDigest, p.CertificateController}
}

func agentProfileFieldsV2(p phase6security.ProfileV2) agentProfileFields {
	return agentProfileFields{p.ProfileDigest, p.EnvironmentDigest, p.PrincipalProfileDigest, p.CertificateController}
}

type agentStartupProfile struct {
	v1       *phase6security.Profile
	v2       *phase6security.ProfileV2
	sources  *phase6security.PeerCRLSources
	registry *securityprincipal.Registry
}

func loadAgentProfile(c configDocument) (agentStartupProfile, error) {
	var result agentStartupProfile
	if !validAgentConfig(c) {
		return result, stageError("config-version")
	}
	if c.Protocol == profileV2ConfigProtocol || c.Protocol == postgresV2ConfigProtocol {
		p, err := phase6security.VerifyFileV2(c.SecurityProfilePath)
		if err != nil || !validateProfileBindingV2(p, c) ||
			phase6security.VerifySlice6PrivateConfigPathV2(p, c.AgentDeployment, phase6security.Slice6ProfileConfigFile, c.SecurityProfilePath) != nil {
			return result, stageError("security-profile-binding")
		}
		if phase6security.VerifySlice6PrivateConfigPathV2(p, c.AgentDeployment, phase6security.Slice6PeerCRLSourcesFile, c.PeerCRLSourcesPath) != nil {
			return result, stageError("peer-crl-sources-path")
		}
		sources, err := phase6security.VerifyPeerCRLSourcesFileV2(c.PeerCRLSourcesPath, p, c.PeerCRLSourcesDigest)
		if err != nil {
			return result, stageError("peer-crl-sources")
		}
		result.v2, result.sources = &p, &sources
		result.registry, err = p.PrincipalRegistry()
		if err != nil {
			return agentStartupProfile{}, stageError("principal-registry")
		}
	} else {
		p, err := phase6security.VerifyFile(c.SecurityProfilePath)
		if err != nil || !validateProfileBinding(p, c) ||
			phase6security.VerifySlice6PrivateConfigPath(p, c.AgentDeployment, phase6security.Slice6ProfileConfigFile, c.SecurityProfilePath) != nil {
			return result, stageError("security-profile-binding")
		}
		if phase6security.VerifySlice6PrivateConfigPath(p, c.AgentDeployment, phase6security.Slice6PeerCRLSourcesFile, c.PeerCRLSourcesPath) != nil {
			return result, stageError("peer-crl-sources-path")
		}
		sources, err := phase6security.VerifyPeerCRLSourcesFile(c.PeerCRLSourcesPath, p)
		if err != nil || sources.Digest() != c.PeerCRLSourcesDigest {
			return result, stageError("peer-crl-sources")
		}
		result.sources = &sources
		result.v1 = &p
		result.registry, err = p.PrincipalRegistry()
		if err != nil {
			return agentStartupProfile{}, stageError("principal-registry")
		}
	}
	if result.registry.Validate(c.Requester) != nil || result.registry.Validate(c.Subject) != nil {
		return agentStartupProfile{}, stageError("principal-registry")
	}
	return result, nil
}

func validateProfileBindingV2(p phase6security.ProfileV2, c configDocument) bool {
	if !validAgentConfig(c) {
		return false
	}
	switch c.Protocol {
	case postgresV2ConfigProtocol:
		binding, target, agent, subject, _, err := p.PostgresClientSignerForOwner(c.SubjectDeployment)
		return err == nil && matchesPostgresBindingFields(agentProfileFieldsV2(p), binding, target, agent, subject, c)
	case profileV2ConfigProtocol:
		binding, agent, subject, err := p.TLSAgentForSubject(c.SubjectDeployment)
		return err == nil && matchesBindingFields(agentProfileFieldsV2(p), binding, agent, subject, c)
	default:
		return false
	}
}

func prepareAgentPolicy(c configDocument, registry *securityprincipal.Registry) (workloadpki.Policy, ed25519.PublicKey, ed25519.PublicKey, error) {
	if !validAgentConfig(c) || registry == nil {
		return workloadpki.Policy{}, nil, nil, stageError("certificate-policy")
	}
	agentPublic, err := base64.RawURLEncoding.DecodeString(c.AgentPublicKey)
	if err != nil || len(agentPublic) != ed25519.PublicKeySize {
		return workloadpki.Policy{}, nil, nil, stageError("request-identity")
	}
	controllerPublic, err := base64.RawURLEncoding.DecodeString(c.CertificateControllerPublic)
	if err != nil || len(controllerPublic) != ed25519.PublicKeySize {
		return workloadpki.Policy{}, nil, nil, stageError("controller-identity")
	}
	p := workloadpki.Policy{ID: c.PolicyID, Registry: registry, Requester: c.Requester, Subject: c.Subject,
		TrustDomain: c.TrustDomain, URI: c.URI, DNSNames: c.DNSNames, Usages: c.Usages, VaultRole: c.VaultRole,
		MaxTTLSeconds: c.MaxTTLSeconds, ExpectedUID: c.AgentUID, ExpectedGID: c.AgentGID, PublicKey: ed25519.PublicKey(agentPublic)}
	if c.Purpose == workloadpki.PostgresClientPurpose {
		p.Purpose = c.Purpose
		p.Postgres = workloadpki.PostgresClientIdentity{OwnerDeployment: c.Postgres.OwnerDeployment, DatabaseName: c.Postgres.DatabaseName,
			RuntimeRole: c.Postgres.RuntimeRole, ServiceName: "postgres", URI: c.URI, CommonName: c.Postgres.CommonName,
			MaxTTL: time.Duration(c.MaxTTLSeconds) * time.Second}
	}
	if p.Validate() != nil {
		return workloadpki.Policy{}, nil, nil, stageError("certificate-policy")
	}
	return p, ed25519.PublicKey(agentPublic), ed25519.PublicKey(controllerPublic), nil
}

func (p agentStartupProfile) peerProvider(c configDocument, client workloadtlsagent.PeerCRLControllerClient) (workloadtlsagent.PeerCRLProvider, error) {
	if p.v2 != nil && p.v1 == nil && p.sources != nil {
		if c.Protocol == postgresV2ConfigProtocol {
			return workloadtlsagent.NewPostgresControllerPeerCRLProviderV2(*p.v2, *p.sources, c.PeerCRLSourcesDigest, c.SubjectDeployment, c.Subject.Digest(), client, time.Now)
		}
		if c.Protocol == profileV2ConfigProtocol {
			return workloadtlsagent.NewControllerPeerCRLProviderV2(*p.v2, *p.sources, c.PeerCRLSourcesDigest, c.Subject.Digest(), client, time.Now)
		}
	} else if p.v1 != nil && p.v2 == nil && p.sources != nil {
		if c.Protocol == postgresConfigProtocol {
			return workloadtlsagent.NewPostgresControllerPeerCRLProvider(*p.v1, *p.sources, c.SubjectDeployment, c.Subject.Digest(), client, time.Now)
		}
		if c.Protocol == peerCRLConfigProtocol {
			return workloadtlsagent.NewControllerPeerCRLProvider(*p.v1, *p.sources, c.Subject.Digest(), client, time.Now)
		}
	}
	return nil, workloadtlsagent.ErrUnavailable
}
