// workload-tls-agent is the only owner of a workload's TLS private keys. It
// obtains short-lived certificates from the certificate controller and offers
// the role process a peer-bound signing socket; private keys never cross the
// process boundary.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

const (
	configProtocol    = "sandbox-runtime.workload-tls-agent-config.v2"
	maxConfigBytes    = 256 << 10
	requestSigningFD  = 3
	maximumPolicyTTL  = 3600
	maximumSocketLoad = 256
)

type configDocument struct {
	Protocol                      string                      `json:"protocol"`
	SecurityProfilePath           string                      `json:"security_profile_path"`
	SecurityProfileDigest         string                      `json:"security_profile_digest"`
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

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "workload TLS agent failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error { //nolint:gocyclo
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) < 1 || len(document) > maxConfigBytes {
		return workloadtlsagent.ErrUnavailable
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
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol ||
		config.MaxTTLSeconds < 60 || config.MaxTTLSeconds > maximumPolicyTTL || config.CertificateTTLSeconds < 60 ||
		int64(config.CertificateTTLSeconds) > config.MaxTTLSeconds || config.RotateAfterSeconds < 1 ||
		config.RotateAfterSeconds > config.CertificateTTLSeconds*2/3 || config.OverlapSeconds < 0 ||
		config.OverlapSeconds >= config.RotateAfterSeconds || config.CheckIntervalMilliseconds < 100 ||
		config.CheckIntervalMilliseconds > 60000 || config.RevocationPollIntervalSeconds < 1 ||
		config.RevocationPollIntervalSeconds > 60 || config.RevocationMaxStalenessSeconds < 1 ||
		config.RevocationMaxStalenessSeconds > 300 || config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 ||
		config.MaxConnections < 1 || config.MaxConnections > maximumSocketLoad || config.ReplayCapacity < 16 || config.ReplayCapacity > 65536 ||
		config.AgentUID == 0 || config.AgentGID == 0 || config.ExpectedRoleUID == 0 || config.ExpectedRoleGID == 0 ||
		config.AgentUID == config.ExpectedRoleUID || config.AgentGID == config.ExpectedRoleGID ||
		config.SignerSocketUID != config.AgentUID || config.SignerSocketGID != config.ExpectedRoleGID ||
		config.AgentUID != uint32(os.Getuid()) || config.AgentGID != uint32(os.Getgid()) {
		clear(canonical)
		return stageError("config-validate")
	}
	clear(canonical)
	groups, err := os.Getgroups()
	if err != nil {
		return stageError("supplementary-groups")
	}
	for _, group := range groups {
		if uint32(group) != config.AgentGID {
			return stageError("supplementary-groups")
		}
	}
	if !filepath.IsAbs(config.SecurityProfilePath) {
		return stageError("security-profile-path")
	}
	profile, err := phase6security.VerifyFile(config.SecurityProfilePath)
	if err != nil || !validateProfileBinding(profile, config) {
		return stageError("security-profile-binding")
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil || registry.Validate(config.Requester) != nil || registry.Validate(config.Subject) != nil {
		return stageError("principal-registry")
	}
	requestPrivate, err := readExactKey(requestSigningFD, "certificate-request-signing-key", ed25519.PrivateKeySize)
	if err != nil {
		return stageError("request-key")
	}
	defer clear(requestPrivate)
	agentPublic, err := base64.RawURLEncoding.DecodeString(config.AgentPublicKey)
	if err != nil || len(agentPublic) != ed25519.PublicKeySize ||
		!ed25519.PrivateKey(requestPrivate).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(agentPublic)) {
		clear(agentPublic)
		return stageError("request-identity")
	}
	defer clear(agentPublic)
	controllerPublic, err := base64.RawURLEncoding.DecodeString(config.CertificateControllerPublic)
	if err != nil || len(controllerPublic) != ed25519.PublicKeySize {
		clear(controllerPublic)
		return stageError("controller-identity")
	}
	defer clear(controllerPublic)
	policy := workloadpki.Policy{ID: config.PolicyID, Registry: registry, Requester: config.Requester, Subject: config.Subject,
		TrustDomain: config.TrustDomain, URI: config.URI, DNSNames: config.DNSNames, Usages: config.Usages, VaultRole: config.VaultRole,
		MaxTTLSeconds: config.MaxTTLSeconds, ExpectedUID: config.AgentUID, ExpectedGID: config.AgentGID, PublicKey: ed25519.PublicKey(agentPublic)}
	if policy.Validate() != nil {
		return stageError("certificate-policy")
	}
	client, err := workloadpki.NewProductionClient(workloadpki.ClientConfig{SocketPath: config.CertificateControllerSocket,
		ExpectedUID: config.CertificateControllerUID, ExpectedGID: config.CertificateControllerGID,
		DirectoryGID: config.AgentGID, Policy: policy,
		AgentPrivateKey: ed25519.PrivateKey(requestPrivate), ControllerKeyID: config.CertificateControllerKeyID,
		ControllerPublic: ed25519.PublicKey(controllerPublic), OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("certificate-client")
	}
	defer client.Close()
	manager, err := workloadtlsagent.NewProduction(workloadtlsagent.Config{Policy: policy, Client: client,
		TTL: time.Duration(config.CertificateTTLSeconds) * time.Second, RotateAfter: time.Duration(config.RotateAfterSeconds) * time.Second,
		Overlap: time.Duration(config.OverlapSeconds) * time.Second, CheckInterval: time.Duration(config.CheckIntervalMilliseconds) * time.Millisecond,
		RevocationPollInterval: time.Duration(config.RevocationPollIntervalSeconds) * time.Second,
		RevocationMaxStaleness: time.Duration(config.RevocationMaxStalenessSeconds) * time.Second,
		OperationTimeout:       time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("manager")
	}
	bootstrapContext, bootstrapCancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
	if err := manager.Bootstrap(bootstrapContext); err != nil {
		bootstrapCancel()
		return stageError("bootstrap")
	}
	bootstrapCancel()
	syscall.Umask(0o077)
	server, err := workloadtlsagent.Listen(workloadtlsagent.ServerConfig{SocketPath: config.SignerSocket,
		SocketUID: config.SignerSocketUID, SocketGID: config.SignerSocketGID, AgentGID: config.AgentGID, ExpectedClientUID: config.ExpectedRoleUID,
		ExpectedClientGID: config.ExpectedRoleGID, MaxConnections: config.MaxConnections, ReplayCapacity: config.ReplayCapacity, Now: time.Now}, manager)
	if err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
		defer cancel()
		_ = manager.Close(cleanupContext)
		return stageError("listen")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errChannel := make(chan error, 2)
	go func() { errChannel <- manager.Run(ctx) }()
	go func() { errChannel <- server.Serve(ctx) }()
	firstErr := <-errChannel
	cancel()
	_ = server.Close()
	<-errChannel
	cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(config.OperationTimeoutSeconds)*time.Second)
	defer cleanupCancel()
	if err := manager.Close(cleanupContext); err != nil {
		return stageError("certificate-revoke")
	}
	if errors.Is(firstErr, context.Canceled) {
		return nil
	}
	return stageError("serve")
}

func validateProfileBinding(profile phase6security.Profile, config configDocument) bool {
	binding, agent, subject, err := profile.TLSAgentForSubject(config.SubjectDeployment)
	return err == nil && matchesProfileBinding(profile, binding, agent, subject, config)
}

func matchesProfileBinding(profile phase6security.Profile, binding phase6security.TLSAgentBinding,
	agent, subject phase6security.Principal, config configDocument) bool {
	if config.SecurityProfileDigest != profile.ProfileDigest || config.EnvironmentDigest != profile.EnvironmentDigest ||
		config.ProfileDigest != profile.PrincipalProfileDigest || config.AgentDeployment == "" || config.SubjectDeployment == "" {
		return false
	}
	controllerPublic, controllerErr := base64.RawURLEncoding.DecodeString(config.CertificateControllerPublic)
	requestPublic, requestErr := base64.RawURLEncoding.DecodeString(config.AgentPublicKey)
	defer clear(controllerPublic)
	defer clear(requestPublic)
	if controllerErr != nil || requestErr != nil || binding.AgentDeployment != config.AgentDeployment || binding.SubjectDeployment != config.SubjectDeployment ||
		agent.Name != binding.AgentDeployment || subject.Name != binding.SubjectDeployment ||
		agent.PrincipalDigest != binding.AgentPrincipalDigest || subject.PrincipalDigest != binding.SubjectPrincipalDigest ||
		binding.ControllerDeployment != profile.CertificateController.DeploymentName ||
		config.CertificateControllerSocket != binding.ControllerSocketPath ||
		config.CertificateControllerUID != binding.ControllerUID || config.CertificateControllerGID != binding.ControllerGID ||
		config.CertificateControllerKeyID != profile.CertificateController.ResponseKeyID ||
		phase6security.CertificateControllerPublicKeyDigest(controllerPublic) != profile.CertificateController.ResponsePublicKeyDigest ||
		config.AgentRequestKeyID != binding.AgentRequestKeyID ||
		phase6security.TLSAgentRequestPublicKeyDigest(requestPublic) != binding.AgentRequestKeyDigest ||
		agent.AuthorizationPrincipal == nil ||
		subject.AuthorizationPrincipal == nil || subject.TLS == nil ||
		config.Requester != *agent.AuthorizationPrincipal || config.Subject != *subject.AuthorizationPrincipal ||
		config.PolicyID != binding.IssuerPolicyID || config.VaultRole != binding.IssuerVaultRole ||
		config.AgentUID != binding.AgentUID || config.AgentGID != binding.AgentGID ||
		config.ExpectedRoleUID != binding.SubjectUID || config.ExpectedRoleGID != binding.SubjectGID ||
		config.SignerSocket != binding.SocketPath || config.SignerSocketUID != binding.AgentUID ||
		config.SignerSocketGID != binding.SubjectGID || config.TrustDomain != subject.TLS.TrustDomain ||
		config.URI != subject.TLS.URI || !slices.Equal(config.DNSNames, subject.TLS.DNSNames) ||
		!slices.Equal(config.Usages, subject.TLS.Usages) ||
		config.MaxTTLSeconds != subject.TLS.TTLSeconds || int64(config.CertificateTTLSeconds) != subject.TLS.TTLSeconds ||
		int64(config.RotateAfterSeconds) != subject.TLS.RotateAfterSeconds || int64(config.OverlapSeconds) != subject.TLS.OverlapSeconds ||
		int64(config.RevocationMaxStalenessSeconds) != subject.TLS.RevocationMaxStalenessSeconds {
		return false
	}
	return true
}

func readExactKey(fd uintptr, name string, size int) ([]byte, error) {
	file := os.NewFile(fd, name)
	if file == nil {
		return nil, workloadtlsagent.ErrUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(size+1)))
	_ = file.Close()
	if err != nil || len(value) != size {
		clear(value)
		return nil, workloadtlsagent.ErrUnavailable
	}
	return value, nil
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, workloadtlsagent.ErrUnavailable)
}
