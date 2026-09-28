// certificate-controller signs Principal-bound CSR requests through a
// digest-pinned Vault PKI mount. Agent and controller signing keys are accepted
// only through inherited descriptors; workload TLS private keys never enter
// this process.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

const (
	configProtocol         = "sandbox-runtime.certificate-controller-config.v3"
	postgresConfigProtocol = "sandbox-runtime.certificate-controller-config.v4"
	peerCRLConfigProtocol  = "sandbox-runtime.certificate-controller-config.v4"
	maxConfigBytes         = 2 << 20
	credentialAgentFD      = 3
	controllerSigningFD    = 4
	vaultTLSKeyFD          = 5
	vaultTLSRequestFD      = 6
)

type configDocument struct {
	Protocol                  string              `json:"protocol"`
	SecurityProfilePath       string              `json:"security_profile_path"`
	SecurityProfileDigest     string              `json:"security_profile_digest"`
	PeerCRLSourcesPath        string              `json:"peer_crl_sources_path"`
	PeerCRLSourcesDigest      string              `json:"peer_crl_sources_digest"`
	EnvironmentDigest         string              `json:"environment_digest"`
	ProfileDigest             string              `json:"profile_digest"`
	LedgerPath                string              `json:"ledger_path"`
	ControllerKeyID           string              `json:"controller_key_id"`
	MaximumActiveCertificates int                 `json:"maximum_active_certificates"`
	MaximumLedgerAgeSeconds   int                 `json:"maximum_ledger_age_seconds"`
	ReapIntervalSeconds       int                 `json:"reap_interval_seconds"`
	VaultEndpoint             string              `json:"vault_endpoint"`
	VaultServerName           string              `json:"vault_server_name"`
	VaultClientCertificatePEM []byte              `json:"vault_client_certificate_pem"`
	VaultMount                string              `json:"vault_mount"`
	OperationTimeoutSeconds   int                 `json:"operation_timeout_seconds"`
	ManagedVaultTLS           managedTLSConfig    `json:"managed_vault_tls"`
	Credential                credentialDocument  `json:"credential"`
	Listeners                 []listenerDocument  `json:"listeners"`
	Policies                  []certificatePolicy `json:"policies"`
}

type managedTLSConfig struct {
	PolicyID                      string `json:"policy_id"`
	ControllerSocket              string `json:"controller_socket"`
	CertificateTTLSeconds         int    `json:"certificate_ttl_seconds"`
	RotateAfterSeconds            int    `json:"rotate_after_seconds"`
	OverlapSeconds                int    `json:"overlap_seconds"`
	CheckIntervalMilliseconds     int    `json:"check_interval_milliseconds"`
	RevocationPollIntervalSeconds int    `json:"revocation_poll_interval_seconds"`
	RevocationMaxStalenessSeconds int    `json:"revocation_max_staleness_seconds"`
}

type credentialDocument struct {
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

type listenerDocument struct {
	SocketPath        string `json:"socket_path"`
	SocketUID         uint32 `json:"socket_uid"`
	SocketGID         uint32 `json:"socket_gid"`
	ExpectedClientUID uint32 `json:"expected_client_uid"`
	ExpectedClientGID uint32 `json:"expected_client_gid"`
	MaxConnections    int    `json:"max_connections"`
}

type certificatePolicy struct {
	ID                string                      `json:"id"`
	Purpose           string                      `json:"purpose,omitempty"`
	Postgres          *postgresClientConfig       `json:"postgres,omitempty"`
	AgentRequestKeyID string                      `json:"agent_request_key_id"`
	Requester         securityprincipal.Principal `json:"requester"`
	Subject           securityprincipal.Principal `json:"subject"`
	TrustDomain       string                      `json:"trust_domain"`
	URI               string                      `json:"uri"`
	DNSNames          []string                    `json:"dns_names"`
	Usages            []string                    `json:"usages"`
	VaultRole         string                      `json:"vault_role"`
	MaxTTLSeconds     int64                       `json:"max_ttl_seconds"`
	ExpectedUID       uint32                      `json:"expected_uid"`
	ExpectedGID       uint32                      `json:"expected_gid"`
	AgentPublicKey    string                      `json:"agent_public_key"`
}

type postgresClientConfig struct {
	OwnerDeployment string `json:"owner_deployment"`
	DatabaseName    string `json:"database_name"`
	RuntimeRole     string `json:"runtime_role"`
	CommonName      string `json:"common_name"`
	IssuerAnchorID  string `json:"issuer_anchor_id"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "certificate controller failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error { //nolint:gocyclo
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) < 1 || len(document) > maxConfigBytes {
		return workloadpki.ErrUnavailable
	}
	defer clear(document)
	var config configDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return stageError("config-decode")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return stageError("config-trailing")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) ||
		!((config.Protocol == configProtocol && config.PeerCRLSourcesPath == "" && config.PeerCRLSourcesDigest == "") ||
			(config.Protocol == peerCRLConfigProtocol && filepath.IsAbs(config.PeerCRLSourcesPath) && config.PeerCRLSourcesDigest != "") ||
			(config.Protocol == postgresConfigProtocol && filepath.IsAbs(config.PeerCRLSourcesPath) && config.PeerCRLSourcesDigest != "")) ||
		len(config.Listeners) < 1 || len(config.Listeners) > 128 ||
		len(config.Policies) < 1 || len(config.Policies) > 128 || len(config.VaultClientCertificatePEM) < 1 ||
		config.VaultServerName == "" || config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 ||
		config.MaximumLedgerAgeSeconds < 3600 || config.MaximumLedgerAgeSeconds > 7*24*3600 || config.ReapIntervalSeconds < 1 || config.ReapIntervalSeconds > 60 ||
		config.ManagedVaultTLS.PolicyID == "" || config.ManagedVaultTLS.ControllerSocket == "" ||
		config.ManagedVaultTLS.CertificateTTLSeconds < 60 || config.ManagedVaultTLS.CertificateTTLSeconds > 3600 ||
		config.ManagedVaultTLS.RotateAfterSeconds < 1 || config.ManagedVaultTLS.RotateAfterSeconds > config.ManagedVaultTLS.CertificateTTLSeconds*2/3 ||
		config.ManagedVaultTLS.OverlapSeconds < 0 || config.ManagedVaultTLS.OverlapSeconds >= config.ManagedVaultTLS.RotateAfterSeconds ||
		config.ManagedVaultTLS.CheckIntervalMilliseconds < 100 || config.ManagedVaultTLS.CheckIntervalMilliseconds > 60000 ||
		config.ManagedVaultTLS.RevocationPollIntervalSeconds < 1 || config.ManagedVaultTLS.RevocationPollIntervalSeconds > 60 ||
		config.ManagedVaultTLS.RevocationMaxStalenessSeconds < 1 || config.ManagedVaultTLS.RevocationMaxStalenessSeconds > 300 ||
		!filepath.IsAbs(config.SecurityProfilePath) {
		clear(canonical)
		return stageError("config-validate")
	}
	clear(canonical)
	profile, err := phase6security.VerifyFile(config.SecurityProfilePath)
	if err != nil || profile.ProfileDigest != config.SecurityProfileDigest ||
		profile.EnvironmentDigest != config.EnvironmentDigest || profile.PrincipalProfileDigest != config.ProfileDigest ||
		(len(profile.PostgresClientAgents) != 0 && config.Protocol != postgresConfigProtocol) {
		return stageError("security-profile")
	}
	var peerSources *phase6security.PeerCRLSources
	var peerProfile *phase6security.Profile
	var vaultPeerSources []workloadpki.VaultPeerIssuerSource
	if config.Protocol == peerCRLConfigProtocol || config.Protocol == postgresConfigProtocol {
		mapping, mappingErr := phase6security.VerifyPeerCRLSourcesFile(config.PeerCRLSourcesPath, profile)
		if mappingErr != nil || mapping.Digest() != config.PeerCRLSourcesDigest {
			return stageError("peer-crl-sources")
		}
		peerSources, peerProfile = &mapping, &profile
		vaultPeerSources = make([]workloadpki.VaultPeerIssuerSource, 0, len(mapping.Sources))
		for _, source := range mapping.Sources {
			vaultPeerSources = append(vaultPeerSources, workloadpki.VaultPeerIssuerSource{
				SourceID: source.ID, Mount: source.Mount, IssuerID: source.IssuerID, IssuerDigest: source.IssuerDigest})
		}
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil {
		return stageError("profile-principal-registry")
	}

	credentialPrivate, err := readExactKey(credentialAgentFD, "credential-agent-signing-key", ed25519.PrivateKeySize)
	if err != nil {
		return stageError("credential-key")
	}
	defer clear(credentialPrivate)
	controllerPrivate, err := readExactKey(controllerSigningFD, "certificate-controller-signing-key", ed25519.PrivateKeySize)
	if err != nil {
		return stageError("controller-key")
	}
	defer clear(controllerPrivate)
	vaultTLSKey, err := readBounded(vaultTLSKeyFD, "vault-client-tls-private-key", 64<<10)
	if err != nil {
		return stageError("vault-tls-key")
	}
	defer clear(vaultTLSKey)
	vaultTLSRequestPrivate, err := readExactKey(vaultTLSRequestFD, "vault-tls-certificate-request-key", ed25519.PrivateKeySize)
	if err != nil {
		return stageError("vault-tls-request-key")
	}
	defer clear(vaultTLSRequestPrivate)
	if !validateControllerProfileConfig(profile, config,
		ed25519.PrivateKey(controllerPrivate).Public().(ed25519.PublicKey),
		ed25519.PrivateKey(vaultTLSRequestPrivate).Public().(ed25519.PublicKey)) {
		return stageError("security-profile-binding")
	}

	credentialPublic, err := base64.RawURLEncoding.DecodeString(config.Credential.PublicKey)
	if err != nil || len(credentialPublic) != ed25519.PublicKeySize || !ed25519.PrivateKey(credentialPrivate).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(credentialPublic)) ||
		registry.Validate(config.Credential.Principal) != nil || config.Credential.Principal.Kind != securityprincipal.KindController || config.Credential.Principal.Name != "certificate_controller" {
		clear(credentialPublic)
		return stageError("credential-identity")
	}
	credentialPolicy := workloadcredentialv2.Policy{ID: config.Credential.PolicyID, Registry: registry, Principal: config.Credential.Principal,
		Purpose: config.Credential.Purpose, BackendID: config.Credential.BackendID, BackendPolicy: config.Credential.BackendPolicy,
		MaxTTL: time.Duration(config.Credential.MaxTTLSeconds) * time.Second, Renewable: true, PublicKey: ed25519.PublicKey(credentialPublic),
		ExpectedUID: config.Credential.ControllerUID, ExpectedGID: config.Credential.ControllerGID}
	if credentialPolicy.Validate() != nil || config.Credential.CredentialTTLSeconds < 60 || config.Credential.CredentialTTLSeconds > config.Credential.MaxTTLSeconds {
		return stageError("credential-policy")
	}
	credentialClient, err := workloadcredentialv2.NewProductionClient(workloadcredentialv2.ClientConfig{SocketPath: config.Credential.SocketPath,
		ExpectedUID: config.Credential.ExpectedUID, ExpectedGID: config.Credential.ExpectedGID, Policy: credentialPolicy,
		PrivateKey: ed25519.PrivateKey(credentialPrivate), OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("credential-client")
	}
	defer credentialClient.Close()
	tokenSource, err := workloadpki.NewCredentialTokenSource(workloadpki.CredentialTokenSourceConfig{Client: workloadpki.V2CredentialAdapter{Client: credentialClient},
		TTL: time.Duration(config.Credential.CredentialTTLSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("credential-token-source")
	}

	if !vaultTrustEdgeMatches(profile, config.VaultEndpoint, config.VaultServerName) {
		return stageError("vault-edge")
	}
	vaultAnchor, _, err := profile.EdgeTrustAnchors("certificate-vault")
	if err != nil {
		return stageError("vault-anchor")
	}
	vaultBundle, err := trustanchor.Load(vaultAnchor, time.Now())
	if err != nil {
		return stageError("vault-ca")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(vaultBundle) {
		clear(vaultBundle)
		return stageError("vault-ca")
	}
	clear(vaultBundle)
	bootstrapAnchor, err := profile.ConsumerTrustAnchor(profile.CertificateController.BootstrapClientAnchorID,
		"certificate-controller", "client_verification")
	if err != nil {
		return stageError("vault-bootstrap-anchor")
	}
	bootstrapBundle, err := trustanchor.Load(bootstrapAnchor, time.Now())
	if err != nil {
		return stageError("vault-bootstrap-ca")
	}
	bootstrapRoots := x509.NewCertPool()
	if !bootstrapRoots.AppendCertsFromPEM(bootstrapBundle) {
		clear(bootstrapBundle)
		return stageError("vault-bootstrap-ca")
	}
	clear(bootstrapBundle)
	policies := make([]workloadpki.Policy, 0, len(config.Policies))
	vaultPolicies := make(map[string]string, len(config.Policies))
	peerPairs := make(map[[2]uint32]struct{}, len(config.Policies))
	var managedPolicy workloadpki.Policy
	for _, value := range config.Policies {
		publicKey, decodeErr := base64.RawURLEncoding.DecodeString(value.AgentPublicKey)
		if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize {
			clear(publicKey)
			return stageError("certificate-agent-key")
		}
		policy := workloadpki.Policy{ID: value.ID, Registry: registry, Requester: value.Requester, Subject: value.Subject,
			TrustDomain: value.TrustDomain, URI: value.URI, DNSNames: value.DNSNames, Usages: value.Usages, VaultRole: value.VaultRole,
			MaxTTLSeconds: value.MaxTTLSeconds, ExpectedUID: value.ExpectedUID, ExpectedGID: value.ExpectedGID, PublicKey: ed25519.PublicKey(publicKey)}
		if value.Purpose == workloadpki.PostgresClientPurpose && value.Postgres != nil {
			policy.Purpose = value.Purpose
			policy.Postgres = workloadpki.PostgresClientIdentity{OwnerDeployment: value.Postgres.OwnerDeployment,
				DatabaseName: value.Postgres.DatabaseName, RuntimeRole: value.Postgres.RuntimeRole,
				ServiceName: "postgres", URI: value.URI, CommonName: value.Postgres.CommonName,
				MaxTTL: time.Duration(value.MaxTTLSeconds) * time.Second}
		}
		if policy.Validate() != nil {
			clear(publicKey)
			return stageError("certificate-policy")
		}
		if _, duplicate := vaultPolicies[policy.ID]; duplicate {
			return stageError("certificate-policy-duplicate")
		}
		policies = append(policies, policy)
		vaultPolicies[policy.ID] = policy.VaultRole
		peerPairs[[2]uint32{policy.ExpectedUID, policy.ExpectedGID}] = struct{}{}
		if policy.ID == config.ManagedVaultTLS.PolicyID {
			managedPolicy = policy
		}
	}
	if managedPolicy.ID == "" || managedPolicy.Requester.Kind != securityprincipal.KindController ||
		managedPolicy.Requester.Name != "certificate_controller" || managedPolicy.Subject != managedPolicy.Requester ||
		!slices.Equal(managedPolicy.Usages, []string{"client_auth"}) ||
		!ed25519.PrivateKey(vaultTLSRequestPrivate).Public().(ed25519.PublicKey).Equal(managedPolicy.PublicKey) ||
		int64(config.ManagedVaultTLS.CertificateTTLSeconds) > managedPolicy.MaxTTLSeconds {
		return stageError("managed-vault-tls-policy")
	}
	vaultPair, err := workloadtlsagent.ValidateBootstrapCertificate(config.VaultClientCertificatePEM, vaultTLSKey, bootstrapRoots, managedPolicy, time.Now().UTC())
	if err != nil {
		return stageError("vault-client-certificate")
	}
	defer workloadtlsagent.DestroyTLSCertificate(&vaultPair)
	var managedCertificateAgent atomic.Pointer[workloadtlsagent.Manager]
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: config.VaultServerName}
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if manager := managedCertificateAgent.Load(); manager != nil {
			certificate, certificateErr := manager.Certificate()
			if certificateErr != nil {
				return nil, workloadpki.ErrUnavailable
			}
			return &certificate, nil
		}
		return &vaultPair, nil
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport}
	client, err := workloadpki.NewVaultClient(workloadpki.VaultConfig{Endpoint: config.VaultEndpoint, Mount: config.VaultMount,
		AllowedPolicies: vaultPolicies, OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now,
		RequireImmediateCompleteCRL: peerSources != nil, PeerIssuerSources: vaultPeerSources}, httpClient, tokenSource)
	if err != nil {
		return stageError("vault-pki")
	}
	controller, err := workloadpki.NewController(workloadpki.ControllerConfig{LedgerPath: config.LedgerPath, Policies: policies, Authority: client,
		ControllerKeyID: config.ControllerKeyID, ControllerKey: ed25519.PrivateKey(controllerPrivate), Now: time.Now,
		MaximumActive: config.MaximumActiveCertificates, MaximumLedgerAge: time.Duration(config.MaximumLedgerAgeSeconds) * time.Second,
		PeerCRLProfile: peerProfile, PeerCRLSources: peerSources})
	if err != nil {
		return stageError("controller")
	}
	defer controller.Close()
	listenerPairs := make(map[[2]uint32]struct{}, len(config.Listeners))
	servers := make([]*workloadpki.Server, 0, len(config.Listeners))
	var managedListener listenerDocument
	for _, listener := range config.Listeners {
		pair := [2]uint32{listener.ExpectedClientUID, listener.ExpectedClientGID}
		if _, known := peerPairs[pair]; !known {
			return stageError("listener-peer")
		}
		listenerPairs[pair] = struct{}{}
		server, listenErr := workloadpki.Listen(workloadpki.ServerConfig{SocketPath: listener.SocketPath, SocketUID: listener.SocketUID,
			SocketGID: listener.SocketGID, InternalSelf: listener.SocketPath == config.ManagedVaultTLS.ControllerSocket,
			ExpectedClientUID: listener.ExpectedClientUID, ExpectedClientGID: listener.ExpectedClientGID,
			MaxConnections: listener.MaxConnections, ReapInterval: time.Duration(config.ReapIntervalSeconds) * time.Second}, controller)
		if listenErr != nil {
			for _, active := range servers {
				_ = active.Close()
			}
			return stageError("listen")
		}
		servers = append(servers, server)
		if listener.SocketPath == config.ManagedVaultTLS.ControllerSocket {
			if managedListener.SocketPath != "" || pair != [2]uint32{managedPolicy.ExpectedUID, managedPolicy.ExpectedGID} {
				for _, active := range servers {
					_ = active.Close()
				}
				return stageError("managed-vault-tls-listener")
			}
			managedListener = listener
		}
	}
	if len(listenerPairs) != len(peerPairs) || managedListener.SocketPath == "" {
		return stageError("listener-coverage")
	}
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	serveContext, stopServers := context.WithCancel(context.Background())
	defer stopServers()
	errChannel := make(chan error, len(servers)+1)
	var wait sync.WaitGroup
	for _, server := range servers {
		wait.Add(1)
		go func(value *workloadpki.Server) {
			defer wait.Done()
			errChannel <- value.Serve(serveContext)
		}(server)
	}
	managedClient, err := workloadpki.NewProductionClient(workloadpki.ClientConfig{SocketPath: managedListener.SocketPath,
		ExpectedUID: managedListener.SocketUID, ExpectedGID: managedListener.SocketGID,
		DirectoryGID: managedListener.SocketGID, InternalSelf: true, Policy: managedPolicy,
		AgentPrivateKey: ed25519.PrivateKey(vaultTLSRequestPrivate), ControllerKeyID: config.ControllerKeyID,
		ControllerPublic: ed25519.PrivateKey(controllerPrivate).Public().(ed25519.PublicKey),
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		stopServers()
		for _, server := range servers {
			_ = server.Close()
		}
		wait.Wait()
		return stageError("managed-vault-tls-client")
	}
	defer managedClient.Close()
	managedManager, err := workloadtlsagent.NewProduction(workloadtlsagent.Config{Policy: managedPolicy, Client: managedClient,
		TTL:                    time.Duration(config.ManagedVaultTLS.CertificateTTLSeconds) * time.Second,
		RotateAfter:            time.Duration(config.ManagedVaultTLS.RotateAfterSeconds) * time.Second,
		Overlap:                time.Duration(config.ManagedVaultTLS.OverlapSeconds) * time.Second,
		CheckInterval:          time.Duration(config.ManagedVaultTLS.CheckIntervalMilliseconds) * time.Millisecond,
		RevocationPollInterval: time.Duration(config.ManagedVaultTLS.RevocationPollIntervalSeconds) * time.Second,
		RevocationMaxStaleness: time.Duration(config.ManagedVaultTLS.RevocationMaxStalenessSeconds) * time.Second,
		OperationTimeout:       time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		stopServers()
		for _, server := range servers {
			_ = server.Close()
		}
		wait.Wait()
		return stageError("managed-vault-tls-manager")
	}
	bootstrapContext, bootstrapCancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
	bootstrapErr := managedManager.Bootstrap(bootstrapContext)
	bootstrapCancel()
	if bootstrapErr != nil {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
		_ = managedManager.Close(cleanupContext)
		cleanupCancel()
		stopServers()
		for _, server := range servers {
			_ = server.Close()
		}
		wait.Wait()
		return stageError("managed-vault-tls-bootstrap")
	}
	managedCertificateAgent.Store(managedManager)
	transport.CloseIdleConnections()
	workloadtlsagent.DestroyTLSCertificate(&vaultPair)
	managerContext, stopManager := context.WithCancel(context.Background())
	defer stopManager()
	go func() { errChannel <- managedManager.Run(managerContext) }()
	var firstErr error
	normalShutdown := false
	select {
	case <-signalContext.Done():
		normalShutdown = true
	case firstErr = <-errChannel:
	}
	stopManager()
	cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
	if closeErr := managedManager.Close(cleanupContext); closeErr != nil && firstErr == nil {
		firstErr = closeErr
	}
	cleanupCancel()
	managedCertificateAgent.Store(nil)
	transport.CloseIdleConnections()
	stopServers()
	for _, server := range servers {
		_ = server.Close()
	}
	wait.Wait()
	cleanupContext, cleanupCancel = context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
	defer cleanupCancel()
	if closeErr := tokenSource.Close(cleanupContext); closeErr != nil {
		return stageError("credential-revoke")
	}
	if normalShutdown && firstErr == nil || errors.Is(firstErr, context.Canceled) {
		return nil
	}
	return stageError("serve")
}

func validateControllerProfileConfig(profile phase6security.Profile, config configDocument,
	responsePublic, managedRequestPublic ed25519.PublicKey) bool {
	authority := profile.CertificateController
	var controller phase6security.Principal
	for _, principal := range profile.Principals {
		if principal.Name == authority.DeploymentName {
			controller = principal
			break
		}
	}
	if controller.AuthorizationPrincipal == nil || controller.TLS == nil ||
		uint32(os.Getuid()) != authority.UID || uint32(os.Getgid()) != authority.GID ||
		config.ControllerKeyID != authority.ResponseKeyID ||
		phase6security.CertificateControllerPublicKeyDigest(responsePublic) != authority.ResponsePublicKeyDigest ||
		phase6security.TLSAgentRequestPublicKeyDigest(managedRequestPublic) != authority.ManagedRequestKeyDigest ||
		config.Credential.Principal != *controller.AuthorizationPrincipal ||
		config.ManagedVaultTLS.PolicyID != authority.ManagedPolicyID ||
		config.ManagedVaultTLS.ControllerSocket != authority.SelfSocketPath ||
		int64(config.ManagedVaultTLS.CertificateTTLSeconds) != controller.TLS.TTLSeconds ||
		int64(config.ManagedVaultTLS.RotateAfterSeconds) != controller.TLS.RotateAfterSeconds ||
		int64(config.ManagedVaultTLS.OverlapSeconds) != controller.TLS.OverlapSeconds ||
		int64(config.ManagedVaultTLS.RevocationMaxStalenessSeconds) != controller.TLS.RevocationMaxStalenessSeconds ||
		len(config.Policies) != len(profile.TLSAgentBindings)+len(profile.PostgresClientAgents)+1 ||
		len(config.Listeners) != len(profile.TLSAgentBindings)+len(profile.PostgresClientAgents)+1 {
		return false
	}
	expectedPolicies := make(map[string]certificatePolicy, len(config.Policies))
	var managed certificatePolicy
	for _, policy := range config.Policies {
		if _, duplicate := expectedPolicies[policy.ID]; duplicate {
			return false
		}
		expectedPolicies[policy.ID] = policy
		if policy.ID == authority.ManagedPolicyID {
			managed = policy
		}
	}
	if managed.Purpose != "" || managed.Postgres != nil ||
		!matchesControllerPolicy(managed, *controller.AuthorizationPrincipal, *controller.AuthorizationPrincipal,
			*controller.TLS, authority.ManagedRequestKeyID, authority.ManagedRequestKeyDigest, authority.ManagedVaultRole,
			authority.UID, authority.GID) {
		return false
	}
	for _, binding := range profile.TLSAgentBindings {
		var agent, subject phase6security.Principal
		for _, principal := range profile.Principals {
			if principal.Name == binding.AgentDeployment {
				agent = principal
			}
			if principal.Name == binding.SubjectDeployment {
				subject = principal
			}
		}
		if agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil || subject.TLS == nil ||
			expectedPolicies[binding.IssuerPolicyID].Purpose != "" || expectedPolicies[binding.IssuerPolicyID].Postgres != nil ||
			!matchesControllerPolicy(expectedPolicies[binding.IssuerPolicyID], *agent.AuthorizationPrincipal,
				*subject.AuthorizationPrincipal, *subject.TLS, binding.AgentRequestKeyID,
				binding.AgentRequestKeyDigest, binding.IssuerVaultRole, binding.AgentUID, binding.AgentGID) {
			return false
		}
	}
	for _, binding := range profile.PostgresClientAgents {
		var agent, subject phase6security.Principal
		var target phase6security.Slice6PostgresSignerTarget
		for _, principal := range profile.Principals {
			if principal.Name == binding.AgentDeployment {
				agent = principal
			}
			if principal.Name == binding.SubjectDeployment {
				subject = principal
			}
		}
		for _, candidate := range phase6security.Slice6DesiredFinalPostgresSignerTargets() {
			if candidate.SubjectDeployment == binding.SubjectDeployment {
				target = candidate
			}
		}
		policy := expectedPolicies[binding.IssuerPolicyID]
		if target.SubjectDeployment == "" || agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil || subject.TLS == nil ||
			policy.Purpose != workloadpki.PostgresClientPurpose || policy.Postgres == nil ||
			policy.Postgres.OwnerDeployment != target.SubjectDeployment ||
			policy.Postgres.DatabaseName != target.DatabaseName || policy.Postgres.RuntimeRole != target.SQLRole ||
			policy.Postgres.CommonName != binding.CommonName || policy.Postgres.IssuerAnchorID != binding.IssuerAnchorID {
			return false
		}
		identity := *subject.TLS
		identity.DNSNames = nil
		identity.Usages = []string{"client_auth"}
		if !matchesControllerPolicy(policy, *agent.AuthorizationPrincipal, *subject.AuthorizationPrincipal, identity,
			binding.AgentRequestKeyID, binding.AgentRequestKeyDigest, binding.IssuerVaultRole, binding.AgentUID, binding.AgentGID) {
			return false
		}
	}
	expectedListeners := make(map[string]listenerDocument, len(config.Listeners))
	for _, listener := range config.Listeners {
		if _, duplicate := expectedListeners[listener.SocketPath]; duplicate {
			return false
		}
		expectedListeners[listener.SocketPath] = listener
	}
	self, hasSelf := expectedListeners[authority.SelfSocketPath]
	if !hasSelf || self.SocketUID != authority.UID || self.SocketGID != authority.GID ||
		self.ExpectedClientUID != authority.UID || self.ExpectedClientGID != authority.GID {
		return false
	}
	for _, binding := range profile.TLSAgentBindings {
		listener, found := expectedListeners[binding.ControllerSocketPath]
		if !found || listener.SocketUID != authority.UID || listener.SocketGID != binding.AgentGID ||
			listener.ExpectedClientUID != binding.AgentUID || listener.ExpectedClientGID != binding.AgentGID {
			return false
		}
	}
	for _, binding := range profile.PostgresClientAgents {
		listener, found := expectedListeners[binding.ControllerSocketPath]
		if !found || listener.SocketUID != authority.UID || listener.SocketGID != binding.AgentGID ||
			listener.ExpectedClientUID != binding.AgentUID || listener.ExpectedClientGID != binding.AgentGID {
			return false
		}
	}
	return true
}

func vaultTrustEdgeMatches(profile phase6security.Profile, endpoint, serverName string) bool {
	var service phase6security.ExternalService
	for _, external := range profile.External {
		if external.Name == "vault" {
			service = external
		}
	}
	if len(service.DNSNames) != 1 || service.DNSNames[0] != serverName {
		return false
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() != serverName ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return false
	}
	for _, edge := range profile.TrustEdges {
		if edge.ID == "certificate-vault" && edge.From == "certificate-controller" && edge.To == "vault" &&
			edge.Protocol == "https" && edge.Authentication == "mtls" && edge.ToURI == service.URI &&
			parsed.Port() == strconv.Itoa(edge.Port) {
			return true
		}
	}
	return false
}

func matchesControllerPolicy(policy certificatePolicy, requester, subject securityprincipal.Principal,
	identity phase6security.TLSIdentity, requestKeyID, requestKeyDigest, vaultRole string, uid, gid uint32) bool {
	publicKey, err := base64.RawURLEncoding.DecodeString(policy.AgentPublicKey)
	defer clear(publicKey)
	return err == nil && policy.ID != "" && policy.Requester == requester && policy.Subject == subject &&
		policy.AgentRequestKeyID == requestKeyID && phase6security.TLSAgentRequestPublicKeyDigest(publicKey) == requestKeyDigest &&
		policy.TrustDomain == identity.TrustDomain && policy.URI == identity.URI &&
		slices.Equal(policy.DNSNames, identity.DNSNames) && slices.Equal(policy.Usages, identity.Usages) &&
		policy.VaultRole == vaultRole && policy.MaxTTLSeconds == identity.TTLSeconds &&
		policy.ExpectedUID == uid && policy.ExpectedGID == gid
}

func readExactKey(fd uintptr, name string, size int) ([]byte, error) {
	value, err := readBounded(fd, name, size)
	if err != nil || len(value) != size {
		clear(value)
		return nil, workloadpki.ErrUnavailable
	}
	return value, nil
}

func readBounded(fd uintptr, name string, maximum int) ([]byte, error) {
	file := os.NewFile(fd, name)
	if file == nil {
		return nil, workloadpki.ErrUnavailable
	}
	info, statErr := file.Stat()
	offset, seekErr := file.Seek(0, io.SeekCurrent)
	if statErr != nil || seekErr != nil || offset != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 1 || info.Size() > int64(maximum) {
		_ = file.Close()
		return nil, workloadpki.ErrUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	_ = file.Close()
	if err != nil || len(value) < 1 || len(value) > maximum {
		clear(value)
		return nil, workloadpki.ErrUnavailable
	}
	return value, nil
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, workloadpki.ErrUnavailable)
}
