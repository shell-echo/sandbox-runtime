// workload-material-agent is an operator-owned role-specific Vault KV agent.
// It obtains a short-lived token from the independent credential controller;
// role processes can access only its restricted material Unix socket.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/vaultkv"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

const (
	configProtocol = "sandbox-runtime.workload-material-agent-config.v1"
	maxConfigBytes = 2 << 20
	identityFD     = 3
)

type configDocument struct {
	Protocol                   string              `json:"protocol"`
	SocketPath                 string              `json:"socket_path"`
	SocketUID                  uint32              `json:"socket_uid"`
	SocketGID                  uint32              `json:"socket_gid"`
	ExpectedClientUID          uint32              `json:"expected_client_uid"`
	ExpectedClientGID          uint32              `json:"expected_client_gid"`
	Role                       secretref.Role      `json:"role"`
	MaxConnections             int                 `json:"max_connections"`
	MaxResolutions             int                 `json:"max_resolutions"`
	Migration                  bool                `json:"migration"`
	CredentialControllerSocket string              `json:"credential_controller_socket"`
	CredentialControllerUID    uint32              `json:"credential_controller_uid"`
	CredentialControllerGID    uint32              `json:"credential_controller_gid"`
	CredentialAgentID          string              `json:"credential_agent_id"`
	CredentialPolicyID         string              `json:"credential_policy_id"`
	CredentialBackendID        string              `json:"credential_backend_id"`
	CredentialTTLSeconds       int                 `json:"credential_ttl_seconds"`
	CredentialBinding          secretref.Binding   `json:"credential_binding"`
	VaultEndpoint              string              `json:"vault_endpoint"`
	VaultCABundle              []byte              `json:"vault_ca_bundle"`
	VaultServerName            string              `json:"vault_server_name"`
	VaultMount                 string              `json:"vault_mount"`
	VaultReferenceAuthority    string              `json:"vault_reference_authority"`
	OperationTimeoutSeconds    int                 `json:"operation_timeout_seconds"`
	Bindings                   []secretref.Binding `json:"bindings"`
	BreakGlassSocket           string              `json:"break_glass_socket"`
	BreakGlassControllerSocket string              `json:"break_glass_controller_socket"`
	BreakGlassControllerUID    uint32              `json:"break_glass_controller_uid"`
	BreakGlassControllerGID    uint32              `json:"break_glass_controller_gid"`
	ExpectedOperatorUID        uint32              `json:"expected_operator_uid"`
	ExpectedOperatorGID        uint32              `json:"expected_operator_gid"`
}

type leaseTokenProvider struct {
	mu      sync.Mutex
	binding secretref.Binding
	lease   workloadcredential.Lease
}

func (p *leaseTokenProvider) ResolveSecret(ctx context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	if ctx == nil || ctx.Err() != nil || binding != p.binding {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	if len(p.lease.Credential) < 1 || !p.lease.ExpiresAt.After(now) {
		return secretref.SecretMaterial{}, secretref.ErrExpired
	}
	credential := append([]byte(nil), p.lease.Credential...)
	digest := sha256.Sum256(credential)
	return secretref.SecretMaterial{Binding: binding, Bytes: credential, Digest: "sha256:" + hex.EncodeToString(digest[:]),
		Window:   secretref.RotationWindow{NotBefore: p.lease.IssuedAt, NotAfter: p.lease.ExpiresAt, State: secretref.KeyActive},
		Revision: fmt.Sprintf("credential-%d", p.lease.Revision)}, nil
}

func (p *leaseTokenProvider) replace(lease workloadcredential.Lease) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lease.Destroy()
	p.lease = lease
}

func (p *leaseTokenProvider) destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lease.Destroy()
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "workload material agent failed: %v\n", err)
		os.Exit(1)
	}
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, secretref.ErrUnavailable)
}

func run() error { //nolint:maintidx
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) < 1 || len(document) > maxConfigBytes {
		clear(document)
		return secretref.ErrUnavailable
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
		return secretref.ErrUnavailable
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol || len(config.Bindings) < 1 || len(config.Bindings) > 32 ||
		len(config.VaultCABundle) < 1 || config.VaultServerName == "" || config.CredentialTTLSeconds < 5 || config.CredentialTTLSeconds > 900 ||
		config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 || (config.Migration && config.MaxResolutions != 1) ||
		(!config.Migration && config.MaxResolutions != 0) || (config.Migration && (config.BreakGlassSocket != "" || config.BreakGlassControllerSocket != "")) ||
		(!config.Migration && (config.BreakGlassSocket == "" || config.BreakGlassControllerSocket == "")) {
		clear(canonical)
		return stageError("config-validate")
	}
	clear(canonical)
	if config.CredentialBinding.Validate() != nil || config.CredentialBinding.Kind != secretref.KindSecret ||
		config.CredentialBinding.Role != config.Role || config.CredentialBinding.Purpose != secretref.PurposeWorkloadCredential ||
		config.CredentialBinding.TenantID != secretref.SystemTenant {
		return stageError("credential-binding")
	}

	identityFile := os.NewFile(identityFD, "workload-agent-identity")
	if identityFile == nil {
		return stageError("identity-open")
	}
	privateKey, err := io.ReadAll(io.LimitReader(identityFile, ed25519.PrivateKeySize+1))
	_ = identityFile.Close()
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		clear(privateKey)
		return stageError("identity-read")
	}
	defer clear(privateKey)
	credentialClient, err := workloadcredential.NewProductionClient(workloadcredential.ClientConfig{
		SocketPath: config.CredentialControllerSocket, ExpectedUID: config.CredentialControllerUID, ExpectedGID: config.CredentialControllerGID,
		AgentID: config.CredentialAgentID, Role: config.Role, Purpose: secretref.PurposeWorkloadCredential,
		PolicyID: config.CredentialPolicyID, BindingDigest: config.CredentialBinding.Digest(), BackendID: config.CredentialBackendID,
		PrivateKey: ed25519.PrivateKey(privateKey), OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now,
	})
	if err != nil {
		return stageError("credential-client")
	}
	defer credentialClient.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	lease, err := credentialClient.Issue(ctx, time.Duration(config.CredentialTTLSeconds)*time.Second)
	if err != nil || lease.Renewable == config.Migration {
		lease.Destroy()
		return stageError("credential-issue")
	}
	revoke := func() {
		revokeContext, revokeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = credentialClient.Revoke(revokeContext, lease)
		revokeCancel()
	}
	defer revoke()
	tokenProvider := &leaseTokenProvider{binding: config.CredentialBinding, lease: lease}
	defer tokenProvider.destroy()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.VaultCABundle) {
		return stageError("vault-ca")
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: config.VaultServerName}}}
	purposes := make([]secretref.Purpose, 0, len(config.Bindings))
	seenPurposes := make(map[secretref.Purpose]struct{})
	for _, binding := range config.Bindings {
		if binding.Validate() != nil || binding.Role != config.Role || binding.Kind != secretref.KindSecret || binding.Purpose == secretref.PurposeWorkloadCredential {
			return stageError("material-binding")
		}
		if _, ok := seenPurposes[binding.Purpose]; !ok {
			seenPurposes[binding.Purpose] = struct{}{}
			purposes = append(purposes, binding.Purpose)
		}
	}
	vault, err := vaultkv.New(vaultkv.Config{Endpoint: config.VaultEndpoint, Mount: config.VaultMount,
		ReferenceAuthority: config.VaultReferenceAuthority, Role: config.Role, AllowedPurposes: purposes,
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now}, httpClient, tokenProvider, config.CredentialBinding)
	if err != nil {
		return stageError("vault-client")
	}
	var breakGlassServer *breakglass.AgentServer
	var breakGlassDone chan error
	if !config.Migration {
		breakGlassServer, err = breakglass.ListenAgent(breakglass.AgentServerConfig{
			SocketPath: config.BreakGlassSocket, SocketUID: config.SocketUID, SocketGID: config.SocketGID,
			ExpectedOperatorUID: config.ExpectedOperatorUID, ExpectedOperatorGID: config.ExpectedOperatorGID,
			ControllerSocketPath: config.BreakGlassControllerSocket, ControllerUID: config.BreakGlassControllerUID, ControllerGID: config.BreakGlassControllerGID,
			AgentID: config.CredentialAgentID, PrivateKey: ed25519.PrivateKey(privateKey),
			OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, MaxConnections: 4, Now: time.Now,
			Use: func(useContext context.Context, capability breakglass.Capability) error {
				if capability.Role != config.Role || capability.TenantID != secretref.SystemTenant || capability.Operation != "material.resolve" {
					return secretref.ErrUnavailable
				}
				for _, binding := range config.Bindings {
					if binding.Digest() == capability.BindingDigest && binding.Purpose == capability.Purpose {
						material, resolveErr := vault.ResolveSecret(useContext, binding)
						material.Destroy()
						return resolveErr
					}
				}
				return secretref.ErrUnavailable
			},
		})
		if err != nil {
			return stageError("break-glass-listen")
		}
		defer breakGlassServer.Close()
		breakGlassDone = make(chan error, 1)
		go func() { breakGlassDone <- breakGlassServer.Serve(ctx) }()
	}
	server, err := workloadagent.Listen(workloadagent.ServerConfig{SocketPath: config.SocketPath, SocketUID: config.SocketUID, SocketGID: config.SocketGID,
		ExpectedClientUID: config.ExpectedClientUID, ExpectedClientGID: config.ExpectedClientGID, Role: config.Role,
		AllowedPurposes: purposes, Bindings: config.Bindings, MaxConnections: config.MaxConnections,
		MaxResolutions: config.MaxResolutions, Now: time.Now}, vault)
	if err != nil {
		return stageError("material-listen")
	}
	defer server.Close()

	renewDone := make(chan struct{})
	if !config.Migration {
		go func() {
			defer close(renewDone)
			interval := max(time.Second, time.Duration(config.CredentialTTLSeconds)*time.Second/4)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if time.Until(lease.ExpiresAt) > time.Duration(config.CredentialTTLSeconds)*time.Second/2 {
						continue
					}
					renewed, renewErr := credentialClient.Renew(ctx, lease, time.Duration(config.CredentialTTLSeconds)*time.Second)
					if renewErr != nil {
						if !time.Now().UTC().Before(lease.ExpiresAt) {
							cancel()
							return
						}
						continue
					}
					lease.Destroy()
					lease = renewed
					tokenProvider.replace(renewed)
				}
			}
		}()
	} else {
		close(renewDone)
	}
	err = server.Serve(ctx)
	cancel()
	<-renewDone
	if breakGlassDone != nil {
		breakGlassErr := <-breakGlassDone
		if !errors.Is(breakGlassErr, context.Canceled) && breakGlassErr != nil {
			return breakGlassErr
		}
	}
	if errors.Is(err, context.Canceled) || err == nil {
		return nil
	}
	return stageError("material-serve")
}
