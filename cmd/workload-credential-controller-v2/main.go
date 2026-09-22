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
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
)

const (
	configProtocol = "sandbox-runtime.workload-credential-controller-config.v2"
	maxConfigBytes = 2 << 20
	bootstrapFD    = 3
)

type configDocument struct {
	Protocol                string             `json:"protocol"`
	LedgerPath              string             `json:"ledger_path"`
	ReapIntervalSeconds     int                `json:"reap_interval_seconds"`
	OverlapSeconds          int                `json:"overlap_seconds"`
	EnvironmentDigest       string             `json:"environment_digest"`
	ProfileDigest           string             `json:"profile_digest"`
	VaultEndpoint           string             `json:"vault_endpoint"`
	VaultCABundle           []byte             `json:"vault_ca_bundle"`
	VaultServerName         string             `json:"vault_server_name"`
	VaultBackendID          string             `json:"vault_backend_id"`
	OperationTimeoutSeconds int                `json:"operation_timeout_seconds"`
	Listeners               []listenerDocument `json:"listeners"`
	Policies                []policyDocument   `json:"policies"`
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

func run() error {
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
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return stageError("config-trailing")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol || len(config.Listeners) < 1 || len(config.Listeners) > 128 ||
		len(config.Policies) < 1 || len(config.Policies) > 128 || len(config.VaultCABundle) < 1 || config.VaultServerName == "" ||
		config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 || config.ReapIntervalSeconds < 1 || config.ReapIntervalSeconds > 60 {
		clear(canonical)
		return stageError("config-validate")
	}
	clear(canonical)

	registry, err := securityprincipal.NewRegistry(config.EnvironmentDigest, config.ProfileDigest, nil)
	if err != nil {
		return stageError("principal-registry")
	}
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
	if len(listenerPairs) != len(peerPairs) {
		return stageError("listener-coverage")
	}

	bootstrapFile := os.NewFile(bootstrapFD, "vault-operator-bootstrap")
	if bootstrapFile == nil {
		return stageError("bootstrap-open")
	}
	bootstrapToken, err := io.ReadAll(io.LimitReader(bootstrapFile, 8<<10+1))
	_ = bootstrapFile.Close()
	if err != nil || len(bootstrapToken) < 1 || len(bootstrapToken) > 8<<10 {
		clear(bootstrapToken)
		return stageError("bootstrap-read")
	}
	defer clear(bootstrapToken)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.VaultCABundle) {
		return stageError("vault-ca")
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: config.VaultServerName}}}
	issuer, err := workloadcredential.NewVaultIssuer(workloadcredential.VaultIssuerConfig{Endpoint: config.VaultEndpoint, BackendID: config.VaultBackendID,
		Policies: vaultPolicies, ManagementToken: bootstrapToken, OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now}, httpClient)
	if err != nil {
		return stageError("vault-issuer")
	}
	defer issuer.Close()
	controller, err := workloadcredentialv2.NewProductionController(workloadcredentialv2.ControllerConfig{LedgerPath: config.LedgerPath,
		Policies: policies, Issuer: issuer, Overlap: time.Duration(config.OverlapSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("controller")
	}
	servers := make([]*workloadcredentialv2.Server, 0, len(config.Listeners))
	for _, listener := range config.Listeners {
		server, listenErr := workloadcredentialv2.Listen(workloadcredentialv2.ServerConfig{SocketPath: listener.SocketPath,
			SocketUID: listener.SocketUID, SocketGID: listener.SocketGID, ExpectedClientUID: listener.ExpectedClientUID,
			ExpectedClientGID: listener.ExpectedClientGID, MaxConnections: listener.MaxConnections,
			ReapInterval: time.Duration(config.ReapIntervalSeconds) * time.Second}, controller)
		if listenErr != nil {
			for _, active := range servers {
				_ = active.Close()
			}
			return stageError("listen")
		}
		servers = append(servers, server)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errChannel := make(chan error, len(servers))
	var wait sync.WaitGroup
	for _, server := range servers {
		wait.Add(1)
		go func(value *workloadcredentialv2.Server) {
			defer wait.Done()
			errChannel <- value.Serve(ctx)
		}(server)
	}
	firstErr := <-errChannel
	cancel()
	for _, server := range servers {
		_ = server.Close()
	}
	wait.Wait()
	if errors.Is(firstErr, context.Canceled) {
		return nil
	}
	return stageError("serve")
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, workloadcredentialv2.ErrUnavailable)
}
