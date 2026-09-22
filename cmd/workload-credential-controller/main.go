// workload-credential-controller is the operator-owned issuer process. Its
// Vault management token is accepted only through an inherited anonymous file
// descriptor and is never exposed to workload-material or role processes.
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
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

const (
	configProtocol = "sandbox-runtime.workload-credential-controller-config.v1"
	maxConfigBytes = 2 << 20
	managementFD   = 3
)

type configDocument struct {
	Protocol                string             `json:"protocol"`
	SocketPath              string             `json:"socket_path"`
	LedgerPath              string             `json:"ledger_path"`
	SocketUID               uint32             `json:"socket_uid"`
	SocketGID               uint32             `json:"socket_gid"`
	ExpectedClientUID       uint32             `json:"expected_client_uid"`
	ExpectedClientGID       uint32             `json:"expected_client_gid"`
	MaxConnections          int                `json:"max_connections"`
	ReapIntervalSeconds     int                `json:"reap_interval_seconds"`
	OverlapSeconds          int                `json:"overlap_seconds"`
	VaultEndpoint           string             `json:"vault_endpoint"`
	VaultCABundle           []byte             `json:"vault_ca_bundle"`
	VaultServerName         string             `json:"vault_server_name"`
	OperationTimeoutSeconds int                `json:"operation_timeout_seconds"`
	Identities              []identityDocument `json:"identities"`
	Policies                []policyDocument   `json:"policies"`
}

type identityDocument struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
}

type policyDocument struct {
	ID            string            `json:"id"`
	AgentID       string            `json:"agent_id"`
	Role          secretref.Role    `json:"role"`
	Purpose       secretref.Purpose `json:"purpose"`
	BindingDigest string            `json:"binding_digest"`
	BackendID     string            `json:"backend_id"`
	VaultPolicy   string            `json:"vault_policy"`
	MaxTTLSeconds int               `json:"max_ttl_seconds"`
	Renewable     bool              `json:"renewable"`
	Migration     bool              `json:"migration"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "workload credential controller failed: %v\n", err)
		os.Exit(1)
	}
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, workloadcredential.ErrUnavailable)
}

func run() error {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) < 1 || len(document) > maxConfigBytes {
		clear(document)
		return workloadcredential.ErrUnavailable
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
		return workloadcredential.ErrUnavailable
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol || len(config.Identities) < 1 || len(config.Policies) < 1 ||
		len(config.VaultCABundle) < 1 || config.VaultServerName == "" || config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 {
		clear(canonical)
		return stageError("config-validate")
	}
	clear(canonical)

	managementFile := os.NewFile(managementFD, "vault-management-token")
	if managementFile == nil {
		return stageError("management-open")
	}
	managementToken, err := io.ReadAll(io.LimitReader(managementFile, 8<<10+1))
	_ = managementFile.Close()
	if err != nil || len(managementToken) < 1 || len(managementToken) > 8<<10 {
		clear(managementToken)
		return stageError("management-read")
	}
	defer clear(managementToken)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.VaultCABundle) {
		return stageError("vault-ca")
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: config.VaultServerName}}}
	identities := make(map[string]ed25519.PublicKey, len(config.Identities))
	for _, identity := range config.Identities {
		key, decodeErr := base64.RawURLEncoding.DecodeString(identity.PublicKey)
		if decodeErr != nil || len(key) != ed25519.PublicKeySize {
			clear(key)
			return stageError("identity-key")
		}
		if _, duplicate := identities[identity.AgentID]; duplicate {
			clear(key)
			return stageError("identity-duplicate")
		}
		identities[identity.AgentID] = ed25519.PublicKey(key)
	}
	policies := make([]workloadcredential.Policy, 0, len(config.Policies))
	vaultPolicies := make(map[string]string, len(config.Policies))
	backendID := ""
	for _, configured := range config.Policies {
		if backendID == "" {
			backendID = configured.BackendID
		}
		if configured.BackendID != backendID {
			return stageError("backend-mismatch")
		}
		policies = append(policies, workloadcredential.Policy{ID: configured.ID, AgentID: configured.AgentID, Role: configured.Role,
			Purpose: configured.Purpose, BindingDigest: configured.BindingDigest, BackendID: configured.BackendID,
			MaxTTL: time.Duration(configured.MaxTTLSeconds) * time.Second, Renewable: configured.Renewable, Migration: configured.Migration})
		vaultPolicies[configured.ID] = configured.VaultPolicy
	}
	issuer, err := workloadcredential.NewVaultIssuer(workloadcredential.VaultIssuerConfig{Endpoint: config.VaultEndpoint, BackendID: backendID,
		Policies: vaultPolicies, ManagementToken: managementToken, OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second,
		Now: time.Now}, httpClient)
	if err != nil {
		return stageError("vault-issuer")
	}
	defer issuer.Close()
	controller, err := workloadcredential.NewProductionController(workloadcredential.ControllerConfig{LedgerPath: config.LedgerPath,
		Identities: identities, Policies: policies, Issuer: issuer, Overlap: time.Duration(config.OverlapSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("controller")
	}
	server, err := workloadcredential.Listen(workloadcredential.ServerConfig{SocketPath: config.SocketPath, SocketUID: config.SocketUID, SocketGID: config.SocketGID,
		ExpectedClientUID: config.ExpectedClientUID, ExpectedClientGID: config.ExpectedClientGID, MaxConnections: config.MaxConnections,
		ReapInterval: time.Duration(config.ReapIntervalSeconds) * time.Second}, controller)
	if err != nil {
		return stageError("listen")
	}
	defer server.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = server.Serve(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return stageError("serve")
}
