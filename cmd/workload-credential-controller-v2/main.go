// workload-credential-controller-v2 is the Principal-bound Slice 6 issuer.
// Its operator bootstrap token is an explicit external root-of-trust supplied
// through inherited descriptor 3; the token never enters JSON configuration.
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
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

const (
	configProtocol = "sandbox-runtime.workload-credential-controller-config.v2"
	maxConfigBytes = 2 << 20
	bootstrapFD    = 3
	vaultTLSKeyFD  = 4
	vaultRequestFD = 5
)

type configDocument struct {
	Protocol                  string             `json:"protocol"`
	SecurityProfilePath       string             `json:"security_profile_path"`
	SecurityProfileDigest     string             `json:"security_profile_digest"`
	LedgerPath                string             `json:"ledger_path"`
	ReapIntervalSeconds       int                `json:"reap_interval_seconds"`
	OverlapSeconds            int                `json:"overlap_seconds"`
	EnvironmentDigest         string             `json:"environment_digest"`
	ProfileDigest             string             `json:"profile_digest"`
	VaultEndpoint             string             `json:"vault_endpoint"`
	VaultServerName           string             `json:"vault_server_name"`
	VaultClientCertificatePEM []byte             `json:"vault_client_certificate_pem"`
	VaultBackendID            string             `json:"vault_backend_id"`
	ControllerKeyID           string             `json:"controller_key_id"`
	ControllerPublicKey       string             `json:"controller_public_key"`
	ManagedVaultTLS           managedTLSConfig   `json:"managed_vault_tls"`
	OperationTimeoutSeconds   int                `json:"operation_timeout_seconds"`
	Listeners                 []listenerDocument `json:"listeners"`
	Policies                  []policyDocument   `json:"policies"`
}

type managedTLSConfig struct {
	PolicyID                      string `json:"policy_id"`
	ControllerSocket              string `json:"controller_socket"`
	ControllerReadyTimeoutSeconds int    `json:"controller_ready_timeout_seconds"`
	CertificateTTLSeconds         int    `json:"certificate_ttl_seconds"`
	RotateAfterSeconds            int    `json:"rotate_after_seconds"`
	OverlapSeconds                int    `json:"overlap_seconds"`
	CheckIntervalMilliseconds     int    `json:"check_interval_milliseconds"`
	RevocationPollIntervalSeconds int    `json:"revocation_poll_interval_seconds"`
	RevocationMaxStalenessSeconds int    `json:"revocation_max_staleness_seconds"`
}

type listenerDocument struct {
	SocketPath        string `json:"socket_path"`
	SocketUID         uint32 `json:"socket_uid"`
	SocketGID         uint32 `json:"socket_gid"`
	ExpectedClientUID uint32 `json:"expected_client_uid"`
	ExpectedClientGID uint32 `json:"expected_client_gid"`
	MaxConnections    int    `json:"max_connections"`
}

type policyDocument struct {
	ID            string                      `json:"id"`
	Principal     securityprincipal.Principal `json:"principal"`
	Purpose       secretref.Purpose           `json:"purpose"`
	BackendPolicy string                      `json:"backend_policy"`
	MaxTTLSeconds int                         `json:"max_ttl_seconds"`
	Renewable     bool                        `json:"renewable"`
	PublicKey     string                      `json:"public_key"`
	ExpectedUID   uint32                      `json:"expected_uid"`
	ExpectedGID   uint32                      `json:"expected_gid"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "workload credential controller v2 failed: %v\n", err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) < 1 || len(document) > maxConfigBytes {
		return workloadcredentialv2.ErrUnavailable
	}
	defer clear(document)
	var config configDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return stageError("config-decode")
	}
	defer clear(config.VaultClientCertificatePEM)
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return stageError("config-trailing")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol ||
		!filepath.IsAbs(config.SecurityProfilePath) || len(config.Listeners) < 1 || len(config.Listeners) > 128 ||
		len(config.Policies) < 1 || len(config.Policies) > 128 || len(config.VaultClientCertificatePEM) < 1 ||
		config.VaultServerName == "" || config.ControllerKeyID == "" || config.ControllerPublicKey == "" ||
		config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 ||
		config.ReapIntervalSeconds < 1 || config.ReapIntervalSeconds > 60 ||
		config.ManagedVaultTLS.CertificateTTLSeconds < 60 || config.ManagedVaultTLS.CertificateTTLSeconds > 3600 ||
		config.ManagedVaultTLS.RotateAfterSeconds < 1 ||
		config.ManagedVaultTLS.RotateAfterSeconds > config.ManagedVaultTLS.CertificateTTLSeconds*2/3 ||
		config.ManagedVaultTLS.OverlapSeconds < 0 ||
		config.ManagedVaultTLS.OverlapSeconds >= config.ManagedVaultTLS.RotateAfterSeconds ||
		config.ManagedVaultTLS.CheckIntervalMilliseconds < 100 || config.ManagedVaultTLS.CheckIntervalMilliseconds > 60000 ||
		config.ManagedVaultTLS.ControllerReadyTimeoutSeconds < 5 || config.ManagedVaultTLS.ControllerReadyTimeoutSeconds > 300 ||
		config.ManagedVaultTLS.RevocationPollIntervalSeconds < 1 || config.ManagedVaultTLS.RevocationPollIntervalSeconds > 60 ||
		config.ManagedVaultTLS.RevocationMaxStalenessSeconds < 1 || config.ManagedVaultTLS.RevocationMaxStalenessSeconds > 300 {
		clear(canonical)
		return stageError("config-validate")
	}
	clear(canonical)
	profile, err := phase6security.VerifyFile(config.SecurityProfilePath)
	if err != nil || profile.ProfileDigest != config.SecurityProfileDigest ||
		profile.EnvironmentDigest != config.EnvironmentDigest || profile.PrincipalProfileDigest != config.ProfileDigest ||
		!vaultTrustEdgeMatches(profile, config.VaultEndpoint, config.VaultServerName) {
		return stageError("security-profile")
	}
	materialPlan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil || !validateMaterialPolicyBindings(profile, config.Policies, materialPlan) {
		return stageError("material-policy-binding")
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil {
		return stageError("profile-principal-registry")
	}
	requestPrivate, err := readPrivateFD(vaultRequestFD, "vault-tls-certificate-request-key", ed25519.PrivateKeySize)
	if err != nil || len(requestPrivate) != ed25519.PrivateKeySize {
		clear(requestPrivate)
		return stageError("vault-tls-request-key")
	}
	defer clear(requestPrivate)
	controllerPublic, err := decodePublicKey(config.ControllerPublicKey)
	if err != nil || !validateProfileConfig(profile, config,
		ed25519.PrivateKey(requestPrivate).Public().(ed25519.PublicKey), controllerPublic) {
		clear(controllerPublic)
		return stageError("security-profile-binding")
	}
	defer clear(controllerPublic)
	policies := make([]workloadcredentialv2.Policy, 0, len(config.Policies))
	vaultPolicies := make(map[string]string, len(config.Policies))
	peerPairs := make(map[[2]uint32]struct{}, len(config.Policies))
	for _, value := range config.Policies {
		publicKey, decodeErr := base64.RawURLEncoding.DecodeString(value.PublicKey)
		if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize || registry.Validate(value.Principal) != nil {
			clear(publicKey)
			return stageError("policy-identity")
		}
		policy := workloadcredentialv2.Policy{ID: value.ID, Registry: registry, Principal: value.Principal, Purpose: value.Purpose,
			BackendID: config.VaultBackendID, BackendPolicy: value.BackendPolicy, MaxTTL: time.Duration(value.MaxTTLSeconds) * time.Second,
			Renewable: value.Renewable, PublicKey: ed25519.PublicKey(publicKey), ExpectedUID: value.ExpectedUID, ExpectedGID: value.ExpectedGID}
		if policy.Validate() != nil {
			clear(publicKey)
			return stageError("policy-invalid")
		}
		if _, duplicate := vaultPolicies[policy.ID]; duplicate {
			clear(publicKey)
			return stageError("policy-duplicate")
		}
		policies = append(policies, policy)
		vaultPolicies[policy.ID] = policy.BackendPolicy
		peerPairs[[2]uint32{policy.ExpectedUID, policy.ExpectedGID}] = struct{}{}
	}
	listenerPairs := make(map[[2]uint32]struct{}, len(config.Listeners))
	for _, listener := range config.Listeners {
		pair := [2]uint32{listener.ExpectedClientUID, listener.ExpectedClientGID}
		if _, known := peerPairs[pair]; !known {
			return stageError("listener-peer")
		}
		listenerPairs[pair] = struct{}{}
	}
	if len(listenerPairs) != len(peerPairs) || len(config.Listeners) != len(peerPairs) {
		return stageError("listener-coverage")
	}
	var bootstrapListener listenerDocument
	for _, listener := range config.Listeners {
		if listener.ExpectedClientUID == profile.CertificateController.UID &&
			listener.ExpectedClientGID == profile.CertificateController.GID {
			if bootstrapListener.SocketPath != "" {
				return stageError("bootstrap-listener-duplicate")
			}
			bootstrapListener = listener
		}
	}
	if bootstrapListener.SocketPath == "" {
		return stageError("bootstrap-listener-missing")
	}

	bootstrapToken, err := readPrivateFD(bootstrapFD, "vault-operator-bootstrap", 8<<10)
	if err != nil || len(bootstrapToken) < 1 {
		clear(bootstrapToken)
		return stageError("bootstrap-read")
	}
	defer clear(bootstrapToken)
	vaultKey, err := readPrivateFD(vaultTLSKeyFD, "vault-bootstrap-tls-private-key", 64<<10)
	if err != nil {
		return stageError("vault-bootstrap-tls-key")
	}
	defer clear(vaultKey)
	vaultAnchor, _, err := profile.EdgeTrustAnchors("credential-controller-vault")
	if err != nil {
		return stageError("vault-edge-anchor")
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
		"workload-credential-controller", "client_verification")
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
	managedPolicy, err := managedPolicyForProfile(profile, registry, config, requestPrivate, controllerPublic)
	if err != nil {
		return stageError("managed-policy")
	}
	vaultPair, err := workloadtlsagent.ValidateBootstrapCertificate(config.VaultClientCertificatePEM, vaultKey,
		bootstrapRoots, managedPolicy, time.Now().UTC())
	if err != nil || vaultPair.Leaf == nil ||
		vaultPair.Leaf.NotAfter.Sub(vaultPair.Leaf.NotBefore) > time.Duration(config.ManagedVaultTLS.CertificateTTLSeconds)*time.Second ||
		time.Until(vaultPair.Leaf.NotAfter) <= time.Duration(config.OperationTimeoutSeconds)*time.Second {
		workloadtlsagent.DestroyTLSCertificate(&vaultPair)
		return stageError("vault-bootstrap-certificate")
	}
	defer workloadtlsagent.DestroyTLSCertificate(&vaultPair)
	var managedCertificate atomic.Pointer[workloadtlsagent.Manager]
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: config.VaultServerName}
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if manager := managedCertificate.Load(); manager != nil {
			certificate, certificateErr := manager.Certificate()
			if certificateErr != nil {
				return nil, workloadcredentialv2.ErrUnavailable
			}
			return &certificate, nil
		}
		return &vaultPair, nil
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	tracked := workloadtlsagent.NewBootstrapTrackingTransport(transport)
	httpClient := &http.Client{Transport: tracked}
	issuer, err := workloadcredential.NewVaultIssuer(workloadcredential.VaultIssuerConfig{Endpoint: config.VaultEndpoint, BackendID: config.VaultBackendID,
		Policies: vaultPolicies, ManagementToken: bootstrapToken, OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second,
		Now: time.Now, RequireScopedTokenRoles: true}, httpClient)
	if err != nil {
		return stageError("vault-issuer")
	}
	defer issuer.Close()
	roleContext, stopRoleCheck := context.WithTimeout(context.Background(),
		time.Duration(config.ManagedVaultTLS.ControllerReadyTimeoutSeconds)*time.Second)
	roleErr := issuer.ValidateScopedRoles(roleContext)
	stopRoleCheck()
	if roleErr != nil {
		return stageError("vault-token-roles")
	}
	controller, err := workloadcredentialv2.NewProductionController(workloadcredentialv2.ControllerConfig{LedgerPath: config.LedgerPath,
		Policies: policies, Issuer: issuer, Overlap: time.Duration(config.OverlapSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("controller")
	}
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	serveContext, stopServers := context.WithCancel(context.Background())
	defer stopServers()
	errChannel := make(chan error, len(config.Listeners)+1)
	var wait sync.WaitGroup
	servers := make([]*workloadcredentialv2.Server, 0, len(config.Listeners))
	startListener := func(listener listenerDocument) error {
		server, listenErr := workloadcredentialv2.Listen(workloadcredentialv2.ServerConfig{SocketPath: listener.SocketPath,
			SocketUID: listener.SocketUID, SocketGID: listener.SocketGID, ExpectedClientUID: listener.ExpectedClientUID,
			ExpectedClientGID: listener.ExpectedClientGID, MaxConnections: listener.MaxConnections,
			ReapInterval: time.Duration(config.ReapIntervalSeconds) * time.Second}, controller)
		if listenErr != nil {
			return listenErr
		}
		servers = append(servers, server)
		wait.Add(1)
		go func(value *workloadcredentialv2.Server) {
			defer wait.Done()
			errChannel <- value.Serve(serveContext)
		}(server)
		return nil
	}
	defer func() {
		stopServers()
		for _, server := range servers {
			_ = server.Close()
		}
		wait.Wait()
	}()
	if err := startListener(bootstrapListener); err != nil {
		return stageError("bootstrap-listen")
	}
	clientConfig := workloadpki.ClientConfig{
		SocketPath:  config.ManagedVaultTLS.ControllerSocket,
		ExpectedUID: profile.CertificateController.UID, ExpectedGID: profile.CertificateController.GID,
		DirectoryGID: uint32(os.Getgid()), Policy: managedPolicy,
		AgentPrivateKey: ed25519.PrivateKey(requestPrivate), ControllerKeyID: config.ControllerKeyID,
		ControllerPublic: ed25519.PublicKey(controllerPublic),
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now}
	readyContext, readyCancel := context.WithTimeout(signalContext,
		time.Duration(config.ManagedVaultTLS.ControllerReadyTimeoutSeconds)*time.Second)
	managedClient, err := waitForManagedClient(readyContext, func() (*workloadpki.Client, error) {
		return workloadpki.NewProductionClient(clientConfig)
	})
	readyCancel()
	if err != nil {
		return stageError("managed-client")
	}
	defer managedClient.Close()
	manager, err := workloadtlsagent.NewProduction(workloadtlsagent.Config{Policy: managedPolicy, Client: managedClient,
		TTL:                    time.Duration(config.ManagedVaultTLS.CertificateTTLSeconds) * time.Second,
		RotateAfter:            time.Duration(config.ManagedVaultTLS.RotateAfterSeconds) * time.Second,
		Overlap:                time.Duration(config.ManagedVaultTLS.OverlapSeconds) * time.Second,
		CheckInterval:          time.Duration(config.ManagedVaultTLS.CheckIntervalMilliseconds) * time.Millisecond,
		RevocationPollInterval: time.Duration(config.ManagedVaultTLS.RevocationPollIntervalSeconds) * time.Second,
		RevocationMaxStaleness: time.Duration(config.ManagedVaultTLS.RevocationMaxStalenessSeconds) * time.Second,
		OperationTimeout:       time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("managed-manager")
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
		if closeErr := manager.Close(cleanupContext); closeErr != nil && runErr == nil {
			runErr = stageError("managed-close")
		}
		cleanupCancel()
	}()
	bootstrapContext, bootstrapCancel := context.WithTimeout(signalContext, time.Duration(config.OperationTimeoutSeconds)*time.Second)
	bootstrapErr := manager.Bootstrap(bootstrapContext)
	bootstrapCancel()
	if bootstrapErr != nil {
		return stageError("managed-bootstrap")
	}
	managedCertificate.Store(manager)
	tracked.Switch()
	transport.CloseIdleConnections()
	drainContext, drainCancel := context.WithTimeout(signalContext, time.Duration(config.OperationTimeoutSeconds)*time.Second)
	drainErr := tracked.WaitBootstrapDrain(drainContext)
	drainCancel()
	if drainErr != nil {
		return stageError("bootstrap-drain")
	}
	workloadtlsagent.DestroyTLSCertificate(&vaultPair)
	managerContext, stopManager := context.WithCancel(serveContext)
	managerDone := make(chan struct{})
	go func() {
		defer close(managerDone)
		errChannel <- manager.Run(managerContext)
	}()
	defer func() {
		stopManager()
		select {
		case <-managerDone:
		case <-time.After(time.Duration(config.OperationTimeoutSeconds) * time.Second):
			runErr = errors.Join(runErr, stageError("managed-run-drain"))
		}
	}()
	for _, listener := range config.Listeners {
		if listener.SocketPath != bootstrapListener.SocketPath {
			if err := startListener(listener); err != nil {
				return stageError("listen")
			}
		}
	}
	var firstErr error
	normalShutdown := false
	select {
	case <-signalContext.Done():
		normalShutdown = true
	case firstErr = <-errChannel:
	}
	stopManager()
	select {
	case <-managerDone:
	case <-time.After(time.Duration(config.OperationTimeoutSeconds) * time.Second):
		return stageError("managed-run-drain")
	}
	cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
	closeErr := manager.Close(cleanupContext)
	cleanupCancel()
	transport.CloseIdleConnections()
	if closeErr != nil {
		return stageError("managed-close")
	}
	if normalShutdown || errors.Is(firstErr, context.Canceled) && signalContext.Err() != nil {
		return nil
	}
	return stageError("serve")
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, workloadcredentialv2.ErrUnavailable)
}
