//go:build phase6slice6gate

package productphase6gate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// The field order matches the production workload-tls-agent v3 canonical
// decoder. The omitted purpose/postgres fields are not part of an ordinary
// material-agent Vault client certificate.
type slice6GuestTLSAgentConfig struct {
	Protocol                      string                      `json:"protocol"`
	SecurityProfilePath           string                      `json:"security_profile_path"`
	SecurityProfileDigest         string                      `json:"security_profile_digest"`
	PeerCRLSourcesPath            string                      `json:"peer_crl_sources_path"`
	PeerCRLSourcesDigest          string                      `json:"peer_crl_sources_digest"`
	AgentDeployment               string                      `json:"agent_deployment"`
	SubjectDeployment             string                      `json:"subject_deployment"`
	EnvironmentDigest             string                      `json:"environment_digest"`
	ProfileDigest                 string                      `json:"profile_digest"`
	Requester                     securityprincipal.Principal `json:"requester"`
	Subject                       securityprincipal.Principal `json:"subject"`
	PolicyID                      string                      `json:"policy_id"`
	TrustDomain                   string                      `json:"trust_domain"`
	URI                           string                      `json:"uri"`
	DNSNames                      []string                    `json:"dns_names"`
	Usages                        []string                    `json:"usages"`
	VaultRole                     string                      `json:"vault_role"`
	MaxTTLSeconds                 int64                       `json:"max_ttl_seconds"`
	CertificateControllerSocket   string                      `json:"certificate_controller_socket"`
	CertificateControllerUID      uint32                      `json:"certificate_controller_uid"`
	CertificateControllerGID      uint32                      `json:"certificate_controller_gid"`
	CertificateControllerKeyID    string                      `json:"certificate_controller_key_id"`
	CertificateControllerPublic   string                      `json:"certificate_controller_public_key"`
	AgentPublicKey                string                      `json:"agent_public_key"`
	AgentRequestKeyID             string                      `json:"agent_request_key_id"`
	AgentUID                      uint32                      `json:"agent_uid"`
	AgentGID                      uint32                      `json:"agent_gid"`
	SignerSocket                  string                      `json:"signer_socket"`
	SignerSocketUID               uint32                      `json:"signer_socket_uid"`
	SignerSocketGID               uint32                      `json:"signer_socket_gid"`
	ExpectedRoleUID               uint32                      `json:"expected_role_uid"`
	ExpectedRoleGID               uint32                      `json:"expected_role_gid"`
	MaxConnections                int                         `json:"max_connections"`
	ReplayCapacity                int                         `json:"replay_capacity"`
	CertificateTTLSeconds         int                         `json:"certificate_ttl_seconds"`
	RotateAfterSeconds            int                         `json:"rotate_after_seconds"`
	OverlapSeconds                int                         `json:"overlap_seconds"`
	CheckIntervalMilliseconds     int                         `json:"check_interval_milliseconds"`
	RevocationPollIntervalSeconds int                         `json:"revocation_poll_interval_seconds"`
	RevocationMaxStalenessSeconds int                         `json:"revocation_max_staleness_seconds"`
	OperationTimeoutSeconds       int                         `json:"operation_timeout_seconds"`
}

func slice6BuildGuestTLSAgentConfig(composed slice6VaultComposedInputs) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		composed.PeerSources.Validate(profile) != nil {
		return nil, errors.New("incomplete Guest TLS-agent Profile or peer sources")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject("guest-agent")
	if err != nil || agent.Name != "guest-agent-tls-agent" || subject.Name != "guest-agent" ||
		agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil ||
		subject.TLS == nil || binding.AgentRequestKeyID == "" ||
		binding.ControllerSocketPath == "" || binding.SocketPath == "" ||
		binding.AgentUID == 0 || binding.AgentGID == 0 || binding.SubjectUID == 0 || binding.SubjectGID == 0 {
		return nil, errors.New("Guest TLS-agent authority binding drifted")
	}
	requestPrivate, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[binding.AgentRequestKeyID])
	if err != nil {
		return nil, errors.New("Guest TLS-agent request key unavailable")
	}
	requestPublic := slices.Clone(requestPrivate.Public().(ed25519.PublicKey))
	clear(requestPrivate)
	defer clear(requestPublic)
	if phase6security.TLSAgentRequestPublicKeyDigest(requestPublic) != binding.AgentRequestKeyDigest {
		return nil, errors.New("Guest TLS-agent request key does not match frozen Profile")
	}
	responsePrivate, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[profile.CertificateController.ResponseKeyID])
	if err != nil {
		return nil, errors.New("certificate controller response key unavailable")
	}
	responsePublic := slices.Clone(responsePrivate.Public().(ed25519.PublicKey))
	clear(responsePrivate)
	defer clear(responsePublic)
	if phase6security.CertificateControllerPublicKeyDigest(responsePublic) != profile.CertificateController.ResponsePublicKeyDigest {
		return nil, errors.New("certificate controller response key does not match frozen Profile")
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil {
		return nil, errors.New("Guest TLS-agent principal registry invalid")
	}
	policy := workloadpki.Policy{ID: binding.IssuerPolicyID, Registry: registry,
		Requester: *agent.AuthorizationPrincipal, Subject: *subject.AuthorizationPrincipal,
		TrustDomain: subject.TLS.TrustDomain, URI: subject.TLS.URI,
		DNSNames: slices.Clone(subject.TLS.DNSNames), Usages: slices.Clone(subject.TLS.Usages),
		VaultRole: binding.IssuerVaultRole, MaxTTLSeconds: subject.TLS.TTLSeconds,
		ExpectedUID: binding.AgentUID, ExpectedGID: binding.AgentGID,
		PublicKey: ed25519.PublicKey(requestPublic)}
	if policy.Validate() != nil {
		return nil, errors.New("Guest TLS-agent certificate policy invalid")
	}
	config := slice6GuestTLSAgentConfig{
		Protocol:            "sandbox-runtime.workload-tls-agent-config.v3",
		SecurityProfilePath: "/run/phase6/config/profile.json", SecurityProfileDigest: profile.ProfileDigest,
		PeerCRLSourcesPath: "/run/phase6/config/peer-crl-sources.json", PeerCRLSourcesDigest: composed.PeerSources.Digest(),
		AgentDeployment: agent.Name, SubjectDeployment: subject.Name,
		EnvironmentDigest: profile.EnvironmentDigest, ProfileDigest: profile.PrincipalProfileDigest,
		Requester: *agent.AuthorizationPrincipal, Subject: *subject.AuthorizationPrincipal,
		PolicyID: binding.IssuerPolicyID, TrustDomain: subject.TLS.TrustDomain,
		URI: subject.TLS.URI, DNSNames: slices.Clone(subject.TLS.DNSNames), Usages: slices.Clone(subject.TLS.Usages),
		VaultRole: binding.IssuerVaultRole, MaxTTLSeconds: subject.TLS.TTLSeconds,
		CertificateControllerSocket: binding.ControllerSocketPath,
		CertificateControllerUID:    binding.ControllerUID, CertificateControllerGID: binding.ControllerGID,
		CertificateControllerKeyID:  profile.CertificateController.ResponseKeyID,
		CertificateControllerPublic: base64.RawURLEncoding.EncodeToString(responsePublic),
		AgentPublicKey:              base64.RawURLEncoding.EncodeToString(requestPublic),
		AgentRequestKeyID:           binding.AgentRequestKeyID,
		AgentUID:                    binding.AgentUID, AgentGID: binding.AgentGID,
		SignerSocket: binding.SocketPath, SignerSocketUID: binding.AgentUID, SignerSocketGID: binding.SubjectGID,
		ExpectedRoleUID: binding.SubjectUID, ExpectedRoleGID: binding.SubjectGID,
		MaxConnections: 16, ReplayCapacity: 128,
		CertificateTTLSeconds: int(subject.TLS.TTLSeconds),
		RotateAfterSeconds:    int(subject.TLS.RotateAfterSeconds), OverlapSeconds: int(subject.TLS.OverlapSeconds),
		CheckIntervalMilliseconds: 1000, RevocationPollIntervalSeconds: 1,
		RevocationMaxStalenessSeconds: int(subject.TLS.RevocationMaxStalenessSeconds),
		OperationTimeoutSeconds:       15,
	}
	return json.Marshal(config)
}
