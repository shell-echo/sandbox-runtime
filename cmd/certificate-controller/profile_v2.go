package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func validControllerConfigVersion(c configDocument) bool {
	switch c.Protocol {
	case configProtocol:
		return c.PeerCRLSourcesPath == "" && c.PeerCRLSourcesDigest == ""
	case peerCRLConfigProtocol, profileV2ConfigProtocol:
		return filepath.IsAbs(c.PeerCRLSourcesPath) && c.PeerCRLSourcesDigest != ""
	default:
		return false
	}
}

func validCertificatePolicyPurpose(p certificatePolicy) bool {
	return p.Purpose == "" && p.Postgres == nil ||
		p.Purpose == workloadpki.PostgresClientPurpose && p.Postgres != nil
}

type controllerProfileFields struct {
	CertificateController              phase6security.CertificateControllerAuthority
	Principals                         []phase6security.Principal
	TLSAgentBindings                   []phase6security.TLSAgentBinding
	PostgresClientAgents               []phase6security.PostgresClientAgentBinding
	External                           []phase6security.ExternalService
	TrustEdges                         []phase6security.TrustEdge
	issuerSocket                       phase6security.CredentialIssuerSocketBinding
	credentialServer, credentialClient phase6security.Principal
}

func controllerFieldsV1(p phase6security.Profile) (controllerProfileFields, error) {
	b, server, client, err := p.CredentialIssuerSocketForClient("certificate-controller")
	return controllerProfileFields{p.CertificateController, p.Principals, p.TLSAgentBindings, p.PostgresClientAgents, p.External, p.TrustEdges, b, server, client}, err
}

func controllerFieldsV2(p phase6security.ProfileV2) (controllerProfileFields, error) {
	b, server, client, err := p.CredentialIssuerSocketForClient("certificate-controller")
	return controllerProfileFields{p.CertificateController, p.Principals, p.TLSAgentBindings, p.PostgresClientAgents, p.External, p.TrustEdges, b, server, client}, err
}

type controllerStartupProfile struct {
	v1                           *phase6security.Profile
	v2                           *phase6security.ProfileV2
	sources                      *phase6security.PeerCRLSources
	registry                     *securityprincipal.Registry
	fields                       controllerProfileFields
	vaultAnchor, bootstrapAnchor phase6security.TrustAnchor
}

// Admission happens before reading inherited key FDs, contacting an authority,
// or opening a ledger/listener. A rejected v2 document never falls back to v1.
func loadControllerProfile(c configDocument) (controllerStartupProfile, error) {
	var result controllerStartupProfile
	if !validControllerConfigVersion(c) {
		return result, stageError("config-version")
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount("certificate-controller")
	if err != nil || c.LedgerPath != ledgerPath {
		return result, stageError("ledger-binding")
	}
	if c.Protocol == profileV2ConfigProtocol {
		p, err := phase6security.VerifyFileV2(c.SecurityProfilePath)
		if err != nil || p.ProfileDigest != c.SecurityProfileDigest || p.EnvironmentDigest != c.EnvironmentDigest || p.PrincipalProfileDigest != c.ProfileDigest ||
			phase6security.VerifySlice6PrivateConfigPathV2(p, "certificate-controller", phase6security.Slice6ProfileConfigFile, c.SecurityProfilePath) != nil {
			return result, stageError("security-profile")
		}
		if phase6security.VerifySlice6ControllerLedgerMountsV2(p) != nil {
			return result, stageError("ledger-binding")
		}
		if phase6security.VerifySlice6PrivateConfigPathV2(p, "certificate-controller", phase6security.Slice6PeerCRLSourcesFile, c.PeerCRLSourcesPath) != nil {
			return result, stageError("peer-crl-sources-path")
		}
		sources, err := phase6security.VerifyPeerCRLSourcesFileV2(c.PeerCRLSourcesPath, p, c.PeerCRLSourcesDigest)
		if err != nil {
			return result, stageError("peer-crl-sources")
		}
		result.sources, result.v2 = &sources, &p
		result.registry, err = p.PrincipalRegistry()
		if err != nil {
			return controllerStartupProfile{}, stageError("profile-principal-registry")
		}
		result.fields, err = controllerFieldsV2(p)
		if err != nil {
			return controllerStartupProfile{}, stageError("credential-socket")
		}
		result.vaultAnchor, _, err = p.EdgeTrustAnchors("certificate-vault")
		if err != nil {
			return controllerStartupProfile{}, stageError("vault-anchor")
		}
		result.bootstrapAnchor, err = p.ConsumerTrustAnchor(p.CertificateController.BootstrapClientAnchorID, "certificate-controller", "client_verification")
		if err != nil {
			return controllerStartupProfile{}, stageError("vault-bootstrap-anchor")
		}
	} else {
		p, err := phase6security.VerifyFile(c.SecurityProfilePath)
		if err != nil || p.ProfileDigest != c.SecurityProfileDigest || p.EnvironmentDigest != c.EnvironmentDigest || p.PrincipalProfileDigest != c.ProfileDigest ||
			(len(p.PostgresClientAgents) != 0 && c.Protocol != postgresConfigProtocol) ||
			phase6security.VerifySlice6PrivateConfigPath(p, "certificate-controller", phase6security.Slice6ProfileConfigFile, c.SecurityProfilePath) != nil {
			return result, stageError("security-profile")
		}
		if phase6security.VerifySlice6ControllerLedgerMounts(p) != nil {
			return result, stageError("ledger-binding")
		}
		if c.Protocol == peerCRLConfigProtocol {
			if phase6security.VerifySlice6PrivateConfigPath(p, "certificate-controller", phase6security.Slice6PeerCRLSourcesFile, c.PeerCRLSourcesPath) != nil {
				return result, stageError("peer-crl-sources-path")
			}
			sources, err := phase6security.VerifyPeerCRLSourcesFile(c.PeerCRLSourcesPath, p)
			if err != nil || sources.Digest() != c.PeerCRLSourcesDigest {
				return result, stageError("peer-crl-sources")
			}
			result.sources = &sources
		}
		result.v1 = &p
		result.registry, err = p.PrincipalRegistry()
		if err != nil {
			return controllerStartupProfile{}, stageError("profile-principal-registry")
		}
		result.fields, err = controllerFieldsV1(p)
		if err != nil {
			return controllerStartupProfile{}, stageError("credential-socket")
		}
		result.vaultAnchor, _, err = p.EdgeTrustAnchors("certificate-vault")
		if err != nil {
			return controllerStartupProfile{}, stageError("vault-anchor")
		}
		result.bootstrapAnchor, err = p.ConsumerTrustAnchor(p.CertificateController.BootstrapClientAnchorID, "certificate-controller", "client_verification")
		if err != nil {
			return controllerStartupProfile{}, stageError("vault-bootstrap-anchor")
		}
	}
	return result, nil
}

func controllerProcessGroupsMatch(gid uint32) bool {
	groups, err := os.Getgroups()
	if err != nil || gid == 0 {
		return false
	}
	for _, group := range groups {
		if group < 0 || uint32(group) != gid {
			return false
		}
	}
	return true
}

func controllerKeyBindingMatches(authority phase6security.CertificateControllerAuthority, response, request ed25519.PublicKey) bool {
	return phase6security.CertificateControllerPublicKeyDigest(response) == authority.ResponsePublicKeyDigest &&
		phase6security.TLSAgentRequestPublicKeyDigest(request) == authority.ManagedRequestKeyDigest
}

func (p controllerStartupProfile) validatePolicies(c configDocument, policies []workloadpki.Policy) error {
	if p.v2 != nil && p.v1 == nil && p.sources != nil && c.Protocol == profileV2ConfigProtocol {
		if workloadpki.ValidateControllerPoliciesV2(*p.v2, *p.sources, c.PeerCRLSourcesDigest, policies) != nil {
			return workloadpki.ErrUnavailable
		}
		return validateFiniteIssuerPolicyGroupsV2(*p.v2, *p.sources, c.PeerCRLSourcesDigest, policies)
	}
	if p.v1 != nil && p.v2 == nil {
		if c.Protocol == configProtocol && p.sources == nil {
			return nil
		}
		if c.Protocol == peerCRLConfigProtocol && p.sources != nil {
			return validateFiniteIssuerPolicyGroups(*p.v1, *p.sources, policies)
		}
	}
	return workloadpki.ErrUnavailable
}

func (p controllerStartupProfile) newController(c configDocument, config workloadpki.ControllerConfig) (*workloadpki.Controller, error) {
	if p.v2 != nil && p.v1 == nil && p.sources != nil && c.Protocol == profileV2ConfigProtocol {
		return workloadpki.NewControllerV2(config, *p.v2, *p.sources, c.PeerCRLSourcesDigest)
	}
	if p.v1 != nil && p.v2 == nil && (c.Protocol == configProtocol || c.Protocol == peerCRLConfigProtocol) {
		if p.sources != nil {
			config.PeerCRLProfile, config.PeerCRLSources = p.v1, p.sources
		}
		return workloadpki.NewController(config)
	}
	return nil, workloadpki.ErrUnavailable
}
