//go:build phase6slice6gate

package productphase6gate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// Build only the reviewed migration-job PostgreSQL-purpose v4 signer. An
// ordinary Vault/material TLS signer cannot impersonate this SQL client.
func slice6BuildProductMigrationPostgresSignerConfig(composed slice6VaultComposedInputs) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		composed.PeerSources.Validate(profile) != nil {
		return nil, errors.New("Product migration PostgreSQL signer Profile unavailable")
	}
	binding, target, agent, subject, anchor, err := profile.PostgresClientSignerForOwner("product-migration-job")
	if err != nil || target.AgentDeployment != "product-migration-postgres-tls-agent" ||
		target.SubjectDeployment != "product-migration-job" || target.DatabaseName != "product" ||
		target.SQLRole != "product_migrator" || !target.Migration ||
		agent.Name != target.AgentDeployment || subject.Name != target.SubjectDeployment ||
		anchor.ID != "postgres-client-ca" || binding.IssuerAnchorID != anchor.ID ||
		binding.CommonName != target.SQLRole || subject.TLS == nil ||
		agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil ||
		binding.AgentRequestKeyID == "" || binding.ControllerSocketPath == "" || binding.SocketPath == "" {
		return nil, errors.New("Product migration PostgreSQL signer authority drift")
	}
	requestKey, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[binding.AgentRequestKeyID])
	if err != nil {
		return nil, errors.New("Product migration PostgreSQL signer request key unavailable")
	}
	requestPublic := slices.Clone(requestKey.Public().(ed25519.PublicKey))
	clear(requestKey)
	defer clear(requestPublic)
	if phase6security.TLSAgentRequestPublicKeyDigest(requestPublic) != binding.AgentRequestKeyDigest {
		return nil, errors.New("Product migration PostgreSQL signer key digest drift")
	}
	responseKey, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[profile.CertificateController.ResponseKeyID])
	if err != nil {
		return nil, errors.New("Product migration PostgreSQL controller response key unavailable")
	}
	responsePublic := slices.Clone(responseKey.Public().(ed25519.PublicKey))
	clear(responseKey)
	defer clear(responsePublic)
	if phase6security.CertificateControllerPublicKeyDigest(responsePublic) !=
		profile.CertificateController.ResponsePublicKeyDigest {
		return nil, errors.New("Product migration PostgreSQL controller response key digest drift")
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil {
		return nil, errors.New("Product migration PostgreSQL signer registry unavailable")
	}
	identity := workloadpki.PostgresClientIdentity{OwnerDeployment: target.SubjectDeployment,
		DatabaseName: target.DatabaseName, RuntimeRole: target.SQLRole,
		ServiceName: "postgres", URI: subject.TLS.URI, CommonName: binding.CommonName,
		MaxTTL: time.Duration(subject.TLS.TTLSeconds) * time.Second}
	policy := workloadpki.Policy{ID: binding.IssuerPolicyID, Registry: registry,
		Requester: *agent.AuthorizationPrincipal, Subject: *subject.AuthorizationPrincipal,
		TrustDomain: subject.TLS.TrustDomain, URI: subject.TLS.URI,
		Usages: []string{"client_auth"}, VaultRole: binding.IssuerVaultRole,
		MaxTTLSeconds: subject.TLS.TTLSeconds, ExpectedUID: binding.AgentUID,
		ExpectedGID: binding.AgentGID, PublicKey: ed25519.PublicKey(requestPublic),
		Purpose: workloadpki.PostgresClientPurpose, Postgres: identity}
	if policy.Validate() != nil {
		return nil, errors.New("Product migration PostgreSQL signer policy invalid")
	}
	requestTTL, err := phase6security.Slice6ManagedCertificateRequestTTL(subject.TLS.TTLSeconds,
		subject.TLS.RotateAfterSeconds)
	if err != nil {
		return nil, errors.New("Product migration PostgreSQL signer lifetime invalid")
	}
	config := slice6TLSAgentConfig{
		Protocol: "sandbox-runtime.workload-tls-agent-config.v4",
		Purpose:  workloadpki.PostgresClientPurpose,
		Postgres: &slice6TLSAgentPostgres{OwnerDeployment: target.SubjectDeployment,
			DatabaseName: target.DatabaseName, RuntimeRole: target.SQLRole,
			CommonName: binding.CommonName, IssuerAnchorID: binding.IssuerAnchorID},
		SecurityProfilePath: "/run/phase6/config/profile.json", SecurityProfileDigest: profile.ProfileDigest,
		PeerCRLSourcesPath:   "/run/phase6/config/peer-crl-sources.json",
		PeerCRLSourcesDigest: composed.PeerSources.Digest(),
		AgentDeployment:      agent.Name, SubjectDeployment: subject.Name,
		EnvironmentDigest: profile.EnvironmentDigest, ProfileDigest: profile.PrincipalProfileDigest,
		Requester: *agent.AuthorizationPrincipal, Subject: *subject.AuthorizationPrincipal,
		PolicyID: binding.IssuerPolicyID, TrustDomain: subject.TLS.TrustDomain,
		URI: subject.TLS.URI, DNSNames: nil, Usages: []string{"client_auth"},
		VaultRole: binding.IssuerVaultRole, MaxTTLSeconds: subject.TLS.TTLSeconds,
		CertificateControllerSocket: binding.ControllerSocketPath,
		CertificateControllerUID:    binding.ControllerUID, CertificateControllerGID: binding.ControllerGID,
		CertificateControllerKeyID:  profile.CertificateController.ResponseKeyID,
		CertificateControllerPublic: base64.RawURLEncoding.EncodeToString(responsePublic),
		AgentPublicKey:              base64.RawURLEncoding.EncodeToString(requestPublic),
		AgentRequestKeyID:           binding.AgentRequestKeyID,
		AgentUID:                    binding.AgentUID, AgentGID: binding.AgentGID,
		SignerSocket: binding.SocketPath, SignerSocketUID: binding.AgentUID,
		SignerSocketGID: binding.SubjectGID,
		ExpectedRoleUID: binding.SubjectUID, ExpectedRoleGID: binding.SubjectGID,
		MaxConnections: 16, ReplayCapacity: 128,
		CertificateTTLSeconds:     int(requestTTL),
		RotateAfterSeconds:        int(subject.TLS.RotateAfterSeconds),
		OverlapSeconds:            int(subject.TLS.OverlapSeconds),
		CheckIntervalMilliseconds: 1000, RevocationPollIntervalSeconds: 1,
		RevocationMaxStalenessSeconds: int(subject.TLS.RevocationMaxStalenessSeconds),
		OperationTimeoutSeconds:       15,
	}
	return json.Marshal(config)
}
