//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// These field orders match the production command's closed canonical v4 JSON.
// The builder only prepares same-run input; the process remains the authority
// for accepting the config, opening sockets and signing through real Vault.
type slice6CertificateControllerConfig struct {
	Protocol                  string                      `json:"protocol"`
	SecurityProfilePath       string                      `json:"security_profile_path"`
	SecurityProfileDigest     string                      `json:"security_profile_digest"`
	PeerCRLSourcesPath        string                      `json:"peer_crl_sources_path"`
	PeerCRLSourcesDigest      string                      `json:"peer_crl_sources_digest"`
	EnvironmentDigest         string                      `json:"environment_digest"`
	ProfileDigest             string                      `json:"profile_digest"`
	LedgerPath                string                      `json:"ledger_path"`
	ControllerKeyID           string                      `json:"controller_key_id"`
	MaximumActiveCertificates int                         `json:"maximum_active_certificates"`
	MaximumLedgerAgeSeconds   int                         `json:"maximum_ledger_age_seconds"`
	ReapIntervalSeconds       int                         `json:"reap_interval_seconds"`
	VaultEndpoint             string                      `json:"vault_endpoint"`
	VaultServerName           string                      `json:"vault_server_name"`
	VaultClientCertificatePEM []byte                      `json:"vault_client_certificate_pem"`
	VaultMount                string                      `json:"vault_mount"`
	OperationTimeoutSeconds   int                         `json:"operation_timeout_seconds"`
	ManagedVaultTLS           slice6CertificateManagedTLS `json:"managed_vault_tls"`
	Credential                slice6CertificateCredential `json:"credential"`
	Listeners                 []slice6CertificateListener `json:"listeners"`
	Policies                  []slice6CertificatePolicy   `json:"policies"`
}

type slice6CertificateManagedTLS struct {
	PolicyID                      string `json:"policy_id"`
	ControllerSocket              string `json:"controller_socket"`
	CertificateTTLSeconds         int    `json:"certificate_ttl_seconds"`
	RotateAfterSeconds            int    `json:"rotate_after_seconds"`
	OverlapSeconds                int    `json:"overlap_seconds"`
	CheckIntervalMilliseconds     int    `json:"check_interval_milliseconds"`
	RevocationPollIntervalSeconds int    `json:"revocation_poll_interval_seconds"`
	RevocationMaxStalenessSeconds int    `json:"revocation_max_staleness_seconds"`
}

type slice6CertificateCredential struct {
	SocketPath           string                      `json:"socket_path"`
	ExpectedUID          uint32                      `json:"expected_uid"`
	ExpectedGID          uint32                      `json:"expected_gid"`
	Principal            securityprincipal.Principal `json:"principal"`
	PolicyID             string                      `json:"policy_id"`
	Purpose              secretref.Purpose           `json:"purpose"`
	BackendID            string                      `json:"backend_id"`
	BackendPolicy        string                      `json:"backend_policy"`
	MaxTTLSeconds        int                         `json:"max_ttl_seconds"`
	CredentialTTLSeconds int                         `json:"credential_ttl_seconds"`
	PublicKey            string                      `json:"public_key"`
	ControllerUID        uint32                      `json:"controller_uid"`
	ControllerGID        uint32                      `json:"controller_gid"`
}

type slice6CertificateListener struct {
	SocketPath        string `json:"socket_path"`
	SocketUID         uint32 `json:"socket_uid"`
	SocketGID         uint32 `json:"socket_gid"`
	ExpectedClientUID uint32 `json:"expected_client_uid"`
	ExpectedClientGID uint32 `json:"expected_client_gid"`
	MaxConnections    int    `json:"max_connections"`
}

type slice6CertificatePolicy struct {
	ID                string                      `json:"id"`
	Purpose           string                      `json:"purpose,omitempty"`
	Postgres          *slice6CertificatePostgres  `json:"postgres,omitempty"`
	AgentRequestKeyID string                      `json:"agent_request_key_id"`
	Requester         securityprincipal.Principal `json:"requester"`
	Subject           securityprincipal.Principal `json:"subject"`
	TrustDomain       string                      `json:"trust_domain"`
	URI               string                      `json:"uri"`
	DNSNames          []string                    `json:"dns_names"`
	Usages            []string                    `json:"usages"`
	VaultRole         string                      `json:"vault_role"`
	IssuerSourceID    string                      `json:"issuer_source_id,omitempty"`
	MaxTTLSeconds     int64                       `json:"max_ttl_seconds"`
	ExpectedUID       uint32                      `json:"expected_uid"`
	ExpectedGID       uint32                      `json:"expected_gid"`
	AgentPublicKey    string                      `json:"agent_public_key"`
}

type slice6CertificatePostgres struct {
	OwnerDeployment string `json:"owner_deployment"`
	DatabaseName    string `json:"database_name"`
	RuntimeRole     string `json:"runtime_role"`
	CommonName      string `json:"common_name"`
	IssuerAnchorID  string `json:"issuer_anchor_id"`
}

func slice6BuildCertificateControllerConfig(composed slice6VaultComposedInputs,
	vaultClientCertificate []byte) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		composed.PeerSources.Validate(profile) != nil || len(vaultClientCertificate) == 0 ||
		len(composed.CertificateKeys) != len(phase6security.Slice6DesiredCertificateKeyIDs()) ||
		len(composed.CredentialKeys) != 12 {
		return nil, errors.New("incomplete same-run certificate controller input")
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount("certificate-controller")
	if err != nil || phase6security.VerifySlice6ControllerLedgerMounts(profile) != nil {
		return nil, errors.New("certificate ledger binding drift")
	}
	byName := make(map[string]phase6security.Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		byName[principal.Name] = principal
	}
	controller := byName["certificate-controller"]
	credentialController := byName["workload-credential-controller"]
	if controller.TLS == nil || controller.AuthorizationPrincipal == nil ||
		credentialController.TLS == nil || credentialController.AuthorizationPrincipal == nil ||
		controller.UID != profile.CertificateController.UID || controller.GID != profile.CertificateController.GID {
		return nil, errors.New("controller principal drift")
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil {
		return nil, errors.New("certificate principal registry drift")
	}
	requestTTL, err := phase6security.Slice6ManagedCertificateRequestTTL(controller.TLS.TTLSeconds,
		controller.TLS.RotateAfterSeconds)
	if err != nil {
		return nil, errors.New("certificate controller lifetime budget invalid")
	}
	issuerSocket, issuerServer, issuerClient, err := profile.CredentialIssuerSocketForClient(controller.Name)
	if err != nil || issuerServer.Name != credentialController.Name || issuerClient.Name != controller.Name {
		return nil, errors.New("certificate credential socket drift")
	}
	credentialPrivate, err := slice6ReadPrivateSigningKey(composed.CredentialKeys["credential-"+controller.Name])
	if err != nil {
		return nil, err
	}
	credentialPublic := base64.RawURLEncoding.EncodeToString(credentialPrivate.Public().(ed25519.PublicKey))
	clear(credentialPrivate)
	config := slice6CertificateControllerConfig{
		Protocol:            "sandbox-runtime.certificate-controller-config.v4",
		SecurityProfilePath: "/run/phase6/config/profile.json", SecurityProfileDigest: profile.ProfileDigest,
		PeerCRLSourcesPath: "/run/phase6/config/peer-crl-sources.json", PeerCRLSourcesDigest: composed.PeerSources.Digest(),
		EnvironmentDigest: profile.EnvironmentDigest, ProfileDigest: profile.PrincipalProfileDigest,
		LedgerPath: ledgerPath, ControllerKeyID: profile.CertificateController.ResponseKeyID,
		MaximumActiveCertificates: 2, MaximumLedgerAgeSeconds: 24 * 3600, ReapIntervalSeconds: 1,
		VaultEndpoint: "https://vault.sandbox-runtime.test:8200", VaultServerName: "vault.sandbox-runtime.test",
		VaultClientCertificatePEM: bytes.Clone(vaultClientCertificate), VaultMount: "pki", OperationTimeoutSeconds: 15,
		ManagedVaultTLS: slice6CertificateManagedTLS{
			PolicyID:                  profile.CertificateController.ManagedPolicyID,
			ControllerSocket:          profile.CertificateController.SelfSocketPath,
			CertificateTTLSeconds:     int(requestTTL),
			RotateAfterSeconds:        int(controller.TLS.RotateAfterSeconds),
			OverlapSeconds:            int(controller.TLS.OverlapSeconds),
			CheckIntervalMilliseconds: 1000, RevocationPollIntervalSeconds: 1,
			RevocationMaxStalenessSeconds: int(controller.TLS.RevocationMaxStalenessSeconds),
		},
		Credential: slice6CertificateCredential{SocketPath: issuerSocket.SocketPath,
			ExpectedUID: issuerServer.UID, ExpectedGID: issuerServer.GID,
			Principal: *controller.AuthorizationPrincipal, PolicyID: "credential-certificate-controller",
			Purpose: secretref.PurposeWorkloadCredential, BackendID: "vault-primary",
			BackendPolicy: "certificate-controller-pki", MaxTTLSeconds: 900, CredentialTTLSeconds: 600,
			PublicKey: credentialPublic, ControllerUID: issuerClient.UID, ControllerGID: issuerClient.GID},
		Listeners: make([]slice6CertificateListener, 0, 38),
		Policies:  make([]slice6CertificatePolicy, 0, 38),
	}
	seenKeys := make(map[string]bool, len(composed.CertificateKeys))
	seenPublic := make(map[string]bool, len(composed.CertificateKeys))
	var validatorFailures []string
	add := func(id, keyID, keyDigest, role, agentName, subjectName, socketPath, sourceID string,
		socketGID, peerUID, peerGID uint32, postgres *slice6CertificatePostgres) error {
		agent, subject := byName[agentName], byName[subjectName]
		keyPath := composed.CertificateKeys[keyID]
		if id == "" || keyID == "" || role == "" || socketPath == "" ||
			agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil || subject.TLS == nil ||
			keyPath == "" || seenKeys[keyPath] || (sourceID != "general" && sourceID != "broker-only") {
			return errors.New("certificate signing policy input drift")
		}
		seenKeys[keyPath] = true
		private, keyErr := slice6ReadPrivateSigningKey(keyPath)
		if keyErr != nil {
			return fmt.Errorf("certificate signing key for %s: %w", id, keyErr)
		}
		public := bytes.Clone(private.Public().(ed25519.PublicKey))
		digest := phase6security.TLSAgentRequestPublicKeyDigest(public)
		clear(private)
		if digest == "" || digest != keyDigest || seenPublic[string(public)] {
			return errors.New("certificate signing key aliased")
		}
		seenPublic[string(public)] = true
		policy := slice6CertificatePolicy{ID: id, AgentRequestKeyID: keyID,
			Requester: *agent.AuthorizationPrincipal, Subject: *subject.AuthorizationPrincipal,
			TrustDomain: subject.TLS.TrustDomain, URI: subject.TLS.URI,
			DNSNames: slices.Clone(subject.TLS.DNSNames), Usages: slices.Clone(subject.TLS.Usages),
			VaultRole: role, IssuerSourceID: sourceID, MaxTTLSeconds: subject.TLS.TTLSeconds,
			ExpectedUID: peerUID, ExpectedGID: peerGID,
			AgentPublicKey: base64.RawURLEncoding.EncodeToString(public)}
		if postgres != nil {
			policy.Purpose, policy.Postgres = workloadpki.PostgresClientPurpose, postgres
			policy.DNSNames = nil
			policy.Usages = []string{"client_auth"}
		}
		checked := workloadpki.Policy{ID: policy.ID, Purpose: policy.Purpose, Registry: registry,
			Requester: policy.Requester, Subject: policy.Subject, TrustDomain: policy.TrustDomain,
			URI: policy.URI, DNSNames: policy.DNSNames, Usages: policy.Usages,
			VaultRole: policy.VaultRole, IssuerSourceID: policy.IssuerSourceID,
			MaxTTLSeconds: policy.MaxTTLSeconds, ExpectedUID: policy.ExpectedUID,
			ExpectedGID: policy.ExpectedGID, PublicKey: public}
		if postgres != nil {
			checked.Postgres = workloadpki.PostgresClientIdentity{
				OwnerDeployment: postgres.OwnerDeployment, DatabaseName: postgres.DatabaseName,
				RuntimeRole: postgres.RuntimeRole, ServiceName: "postgres", URI: policy.URI,
				CommonName: postgres.CommonName, MaxTTL: time.Duration(policy.MaxTTLSeconds) * time.Second,
			}
		}
		if checked.Validate() != nil {
			validatorFailures = append(validatorFailures, id)
		}
		config.Policies = append(config.Policies, policy)
		config.Listeners = append(config.Listeners, slice6CertificateListener{
			SocketPath: socketPath, SocketUID: controller.UID, SocketGID: socketGID,
			ExpectedClientUID: peerUID, ExpectedClientGID: peerGID, MaxConnections: 16})
		return nil
	}
	authority := profile.CertificateController
	if err := add(authority.ManagedPolicyID, authority.ManagedRequestKeyID, authority.ManagedRequestKeyDigest,
		authority.ManagedVaultRole,
		controller.Name, controller.Name, authority.SelfSocketPath, "general",
		controller.GID, controller.UID, controller.GID, nil); err != nil {
		return nil, err
	}
	reverse := authority.CredentialController
	if err := add(reverse.PolicyID, reverse.RequestKeyID, reverse.RequestKeyDigest, reverse.VaultRole,
		credentialController.Name, credentialController.Name, reverse.SocketPath, "general",
		credentialController.GID, credentialController.UID, credentialController.GID, nil); err != nil {
		return nil, err
	}
	for _, binding := range profile.TLSAgentBindings {
		sourceID := "general"
		if slice6VaultBrokerOnlySubject(binding.SubjectDeployment) {
			sourceID = "broker-only"
		}
		if err := add(binding.IssuerPolicyID, binding.AgentRequestKeyID, binding.AgentRequestKeyDigest,
			binding.IssuerVaultRole,
			binding.AgentDeployment, binding.SubjectDeployment, binding.ControllerSocketPath, sourceID,
			binding.AgentGID, binding.AgentUID, binding.AgentGID, nil); err != nil {
			return nil, err
		}
	}
	for _, binding := range profile.PostgresClientAgents {
		var target phase6security.Slice6PostgresSignerTarget
		for _, candidate := range phase6security.Slice6DesiredFinalPostgresSignerTargets() {
			if candidate.AgentDeployment == binding.AgentDeployment {
				target = candidate
			}
		}
		if target.SubjectDeployment != binding.SubjectDeployment || target.SQLRole != binding.CommonName {
			return nil, errors.New("postgres certificate purpose drift")
		}
		postgres := &slice6CertificatePostgres{OwnerDeployment: target.SubjectDeployment,
			DatabaseName: target.DatabaseName, RuntimeRole: target.SQLRole,
			CommonName: binding.CommonName, IssuerAnchorID: binding.IssuerAnchorID}
		if err := add(binding.IssuerPolicyID, binding.AgentRequestKeyID, binding.AgentRequestKeyDigest,
			binding.IssuerVaultRole,
			binding.AgentDeployment, binding.SubjectDeployment, binding.ControllerSocketPath, "general",
			binding.AgentGID, binding.AgentUID, binding.AgentGID, postgres); err != nil {
			return nil, err
		}
	}
	if len(config.Policies) != 38 || len(config.Listeners) != 38 || len(seenKeys) != 38 ||
		seenKeys[composed.CertificateKeys[authority.ResponseKeyID]] {
		return nil, errors.New("certificate policy or signing key inventory drift")
	}
	if len(validatorFailures) != 0 {
		return nil, fmt.Errorf("production validator rejected certificate policies %v", validatorFailures)
	}
	return json.Marshal(config)
}
