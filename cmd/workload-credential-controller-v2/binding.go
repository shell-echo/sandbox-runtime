package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func validateProfileConfig(profile phase6security.Profile, config configDocument, requestPublic, controllerPublic ed25519.PublicKey) bool {
	if uint32(os.Getuid()) == 0 || uint32(os.Getgid()) == 0 || len(requestPublic) != ed25519.PublicKeySize ||
		len(controllerPublic) != ed25519.PublicKeySize ||
		config.ControllerKeyID != profile.CertificateController.ResponseKeyID ||
		phase6security.CertificateControllerPublicKeyDigest(controllerPublic) != profile.CertificateController.ResponsePublicKeyDigest ||
		phase6security.TLSAgentRequestPublicKeyDigest(requestPublic) != profile.CertificateController.CredentialController.RequestKeyDigest ||
		config.ManagedVaultTLS.PolicyID != profile.CertificateController.CredentialController.PolicyID ||
		config.ManagedVaultTLS.ControllerSocket != profile.CertificateController.CredentialController.SocketPath ||
		len(config.Policies) != len(profile.CredentialIssuerSockets) ||
		len(config.Listeners) != len(profile.CredentialIssuerSockets) ||
		!validateCredentialListenerBindings(profile, config.Listeners) {
		return false
	}
	var credential, certificate phase6security.Principal
	for _, principal := range profile.Principals {
		switch principal.Name {
		case "workload-credential-controller":
			credential = principal
		case "certificate-controller":
			certificate = principal
		}
	}
	if credential.AuthorizationPrincipal == nil || credential.TLS == nil || certificate.AuthorizationPrincipal == nil ||
		uint32(os.Getuid()) != credential.UID || uint32(os.Getgid()) != credential.GID ||
		int64(config.ManagedVaultTLS.CertificateTTLSeconds) != credential.TLS.TTLSeconds ||
		int64(config.ManagedVaultTLS.RotateAfterSeconds) != credential.TLS.RotateAfterSeconds ||
		int64(config.ManagedVaultTLS.OverlapSeconds) != credential.TLS.OverlapSeconds ||
		int64(config.ManagedVaultTLS.RevocationMaxStalenessSeconds) != credential.TLS.RevocationMaxStalenessSeconds {
		return false
	}
	matched, pairs := 0, make(map[[2]uint32]bool, len(config.Policies))
	for _, policy := range config.Policies {
		matchedPrincipal := false
		for _, binding := range profile.CredentialIssuerSockets {
			_, _, principal, err := profile.CredentialIssuerSocketForClient(binding.ClientDeployment)
			if err == nil && principal.AuthorizationPrincipal != nil && policy.Principal == *principal.AuthorizationPrincipal &&
				policy.ExpectedUID == principal.UID && policy.ExpectedGID == principal.GID {
				matchedPrincipal = true
				break
			}
		}
		if !matchedPrincipal || pairs[[2]uint32{policy.ExpectedUID, policy.ExpectedGID}] {
			return false
		}
		pairs[[2]uint32{policy.ExpectedUID, policy.ExpectedGID}] = true
		if policy.Principal == *certificate.AuthorizationPrincipal {
			matched++
			if policy.BackendPolicy != "certificate-controller-pki" || policy.Purpose != secretref.PurposeWorkloadCredential ||
				!policy.Renewable || policy.MaxTTLSeconds < 60 {
				return false
			}
		}
	}
	return matched == 1
}

// validateMaterialPolicyBindings prevents the operator controller JSON from
// selecting a different Vault policy than the closed v3 material inventory.
// The certificate-controller policy is intentionally a separate PKI domain.
func validateMaterialPolicyBindings(profile phase6security.Profile, policies []policyDocument,
	plan []phase6security.Slice6MaterialAccess) bool {
	if len(plan) != 11 || len(policies) != len(plan)+1 {
		return false
	}
	byAgent := make(map[string]phase6security.Slice6MaterialAccess, len(plan))
	principals := make(map[string]phase6security.Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		principals[principal.Name] = principal
	}
	for _, entry := range plan {
		if entry.SecurityProfileDigest != profile.ProfileDigest || byAgent[entry.Agent].Agent != "" {
			return false
		}
		byAgent[entry.Agent] = entry
	}
	seen := make(map[string]bool, len(plan))
	certificateCount := 0
	for _, policy := range policies {
		if policy.BackendPolicy == "certificate-controller-pki" {
			certificateCount++
			continue
		}
		matched := false
		for _, entry := range plan {
			if policy.ID != entry.CredentialPolicyID {
				continue
			}
			agent := principals[entry.Agent]
			if seen[entry.Agent] || agent.AuthorizationPrincipal == nil ||
				policy.Principal != *agent.AuthorizationPrincipal ||
				policy.BackendPolicy != entry.BackendPolicy ||
				policy.Purpose != secretref.PurposeWorkloadCredential ||
				policy.ExpectedUID != entry.AgentUID || policy.ExpectedGID != entry.AgentGID ||
				policy.Renewable == entry.Migration || policy.MaxTTLSeconds < 5 || policy.MaxTTLSeconds > 900 {
				return false
			}
			seen[entry.Agent], matched = true, true
			break
		}
		if !matched {
			return false
		}
	}
	return certificateCount == 1 && len(seen) == len(plan)
}

func validateCredentialListenerBindings(profile phase6security.Profile, listeners []listenerDocument) bool {
	if len(listeners) != len(profile.CredentialIssuerSockets) {
		return false
	}
	seen := make(map[string]bool, len(listeners))
	for _, binding := range profile.CredentialIssuerSockets {
		_, server, client, err := profile.CredentialIssuerSocketForClient(binding.ClientDeployment)
		if err != nil {
			return false
		}
		matched := false
		for _, listener := range listeners {
			if listener.SocketPath != binding.SocketPath {
				continue
			}
			if seen[listener.SocketPath] || listener.SocketUID != server.UID || listener.SocketGID != client.GID ||
				listener.ExpectedClientUID != client.UID || listener.ExpectedClientGID != client.GID ||
				listener.MaxConnections < 1 || listener.MaxConnections > 256 {
				return false
			}
			seen[listener.SocketPath], matched = true, true
		}
		if !matched {
			return false
		}
	}
	return len(seen) == len(listeners)
}

func managedPolicyForProfile(profile phase6security.Profile, registry *securityprincipal.Registry,
	config configDocument, requestPrivate []byte, controllerPublic []byte) (workloadpki.Policy, error) {
	if registry == nil || len(requestPrivate) != ed25519.PrivateKeySize ||
		!validateProfileConfig(profile, config, ed25519.PrivateKey(requestPrivate).Public().(ed25519.PublicKey), controllerPublic) {
		return workloadpki.Policy{}, workloadpki.ErrUnavailable
	}
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == "workload-credential-controller" {
			principal = candidate
			break
		}
	}
	policy := workloadpki.Policy{ID: profile.CertificateController.CredentialController.PolicyID, Registry: registry,
		Requester: *principal.AuthorizationPrincipal, Subject: *principal.AuthorizationPrincipal,
		TrustDomain: principal.TLS.TrustDomain, URI: principal.TLS.URI, DNSNames: principal.TLS.DNSNames,
		Usages: principal.TLS.Usages, VaultRole: profile.CertificateController.CredentialController.VaultRole,
		MaxTTLSeconds: principal.TLS.TTLSeconds, ExpectedUID: principal.UID, ExpectedGID: principal.GID,
		PublicKey: ed25519.PrivateKey(requestPrivate).Public().(ed25519.PublicKey)}
	if policy.Validate() != nil || len(controllerPublic) != ed25519.PublicKeySize {
		return workloadpki.Policy{}, workloadpki.ErrUnavailable
	}
	return policy, nil
}

func vaultTrustEdgeMatches(profile phase6security.Profile, endpoint, serverName string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() != serverName ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.String() != endpoint {
		return false
	}
	for _, service := range profile.External {
		if service.Name == "vault" && len(service.DNSNames) == 1 && service.DNSNames[0] == serverName {
			for _, edge := range profile.TrustEdges {
				if edge.ID == "credential-controller-vault" && edge.From == "workload-credential-controller" && edge.To == "vault" &&
					edge.Protocol == "https" && edge.Authentication == "mtls" && edge.ToURI == service.URI &&
					parsed.Port() == strconv.Itoa(edge.Port) {
					return true
				}
			}
		}
	}
	return false
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, workloadpki.ErrUnavailable
	}
	return ed25519.PublicKey(decoded), nil
}

func readPrivateFD(fd uintptr, name string, maximum int) ([]byte, error) {
	file := os.NewFile(fd, name)
	if file == nil {
		return nil, workloadpki.ErrUnavailable
	}
	defer file.Close()
	info, statErr := file.Stat()
	offset, seekErr := file.Seek(0, io.SeekCurrent)
	if statErr != nil || seekErr != nil || offset != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > int64(maximum) ||
		maximum < 1 || maximum > 64<<10 {
		return nil, workloadpki.ErrUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if err != nil || len(value) < 1 || len(value) > maximum {
		clear(value)
		return nil, workloadpki.ErrUnavailable
	}
	return value, nil
}

// waitForManagedClient keeps the bootstrap credential listener available while
// the certificate controller starts. It retries only the exact prevalidated
// socket and remains bounded by the caller's startup deadline.
func waitForManagedClient(ctx context.Context, open func() (*workloadpki.Client, error)) (*workloadpki.Client, error) {
	if ctx == nil || open == nil {
		return nil, workloadpki.ErrUnavailable
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil, workloadpki.ErrUnavailable
		}
		client, err := open()
		if err == nil && client != nil {
			return client, nil
		}
		select {
		case <-ctx.Done():
			return nil, workloadpki.ErrUnavailable
		case <-ticker.C:
		}
	}
}
