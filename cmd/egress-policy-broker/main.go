// egress-policy-broker is the sole external uplink for one Phase 6 principal.
// Callers select only a profile-defined alias; the broker owns authenticated
// DNS, address policy checks and the numeric dial.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egressbroker"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

const (
	configProtocol = "sandbox-runtime.egress-policy-broker-config.v1"
	maxConfigBytes = 512 << 10
)

type configDocument struct {
	Protocol                string `json:"protocol"`
	SecurityProfilePath     string `json:"security_profile_path"`
	PolicyID                string `json:"policy_id"`
	ListenAddress           string `json:"listen_address"`
	ClientCABundle          []byte `json:"client_ca_bundle"`
	TLSAgentSocket          string `json:"tls_agent_socket"`
	TLSAgentExpectedUID     uint32 `json:"tls_agent_expected_uid"`
	TLSAgentExpectedGID     uint32 `json:"tls_agent_expected_gid"`
	DNSAddress              string `json:"dns_address"`
	DNSServerName           string `json:"dns_server_name"`
	DNSCABundle             []byte `json:"dns_ca_bundle"`
	MaxConnections          int    `json:"max_connections"`
	ReplayCapacity          int    `json:"replay_capacity"`
	OperationTimeoutSeconds int    `json:"operation_timeout_seconds"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "egress policy broker failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error { //nolint:gocyclo
	document, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil || len(document) < 1 || len(document) > maxConfigBytes {
		return egressbroker.ErrUnavailable
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
		!filepath.IsAbs(config.SecurityProfilePath) || config.PolicyID == "" || config.ListenAddress == "" ||
		config.DNSAddress == "" || net.ParseIP(config.DNSServerName) != nil || config.DNSServerName == "" ||
		config.MaxConnections < 1 || config.MaxConnections > 1024 || config.ReplayCapacity < 16 || config.ReplayCapacity > 65536 ||
		config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 {
		clear(canonical)
		return stageError("config-validate")
	}
	clear(canonical)
	profile, err := phase6security.VerifyFile(config.SecurityProfilePath)
	if err != nil {
		return stageError("security-profile")
	}
	var profilePolicy phase6security.EgressPolicy
	for _, policy := range profile.EgressPolicies {
		if policy.ID == config.PolicyID {
			profilePolicy = policy
		}
	}
	if profilePolicy.ID == "" {
		return stageError("policy")
	}
	principal, principalOK := deploymentPrincipal(profile, profilePolicy.Principal)
	broker, brokerOK := deploymentPrincipal(profile, profilePolicy.Broker)
	if !principalOK || !brokerOK || principal.AuthorizationPrincipal == nil || broker.AuthorizationPrincipal == nil ||
		principal.PrincipalDigest != profilePolicy.PrincipalDigest || broker.PrincipalDigest != profilePolicy.BrokerDigest ||
		principal.TLS == nil || broker.TLS == nil {
		return stageError("policy-principal")
	}
	registry, err := principalRegistry(profile)
	if err != nil {
		return stageError("principal-registry")
	}
	targets := make([]egressbroker.Target, len(profilePolicy.Targets))
	for index, target := range profilePolicy.Targets {
		targets[index] = egressbroker.Target{Alias: target.Alias, Host: target.Host, Port: target.Port, Protocol: target.Protocol}
	}
	policy, err := egressbroker.NewPolicy(profilePolicy.ID, profilePolicy.Revision, registry, *principal.AuthorizationPrincipal,
		*broker.AuthorizationPrincipal, time.Duration(profilePolicy.LeaseSeconds)*time.Second, profilePolicy.DNSMaxAnswers, targets)
	if err != nil {
		return stageError("broker-policy")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{SocketPath: config.TLSAgentSocket,
		ExpectedUID: config.TLSAgentExpectedUID, ExpectedGID: config.TLSAgentExpectedGID,
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("tls-agent")
	}
	clientRoots, err := strictCertPool(config.ClientCABundle)
	if err != nil {
		return stageError("client-ca")
	}
	dnsRoots, err := strictCertPool(config.DNSCABundle)
	if err != nil {
		return stageError("dns-ca")
	}
	dnsService, ok := validateDNSConfig(profile, profilePolicy.Broker, config.DNSServerName, config.DNSAddress)
	if !ok {
		return stageError("dns-binding")
	}
	dnsTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: dnsRoots, ServerName: config.DNSServerName}
	dnsTLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		certificate, certificateErr := agentClient.Certificate(context.Background())
		return &certificate, certificateErr
	}
	dnsResolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	dnsResolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		connectionValue, dialErr := (&tls.Dialer{Config: dnsTLS}).DialContext(ctx, "tcp", config.DNSAddress)
		if dialErr != nil {
			return nil, egressbroker.ErrUnavailable
		}
		connection, tlsOK := connectionValue.(*tls.Conn)
		if !tlsOK || egressbroker.ValidateTLSIdentity(connection.ConnectionState(), dnsService.URI,
			[]string{config.DNSServerName}, []string{"server_auth"}) != nil {
			_ = connectionValue.Close()
			return nil, egressbroker.ErrDenied
		}
		return connection, nil
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots, NextProtos: []string{egressbroker.ProtocolID}}
	serverTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		certificate, certificateErr := agentClient.Certificate(context.Background())
		return &certificate, certificateErr
	}
	server, err := egressbroker.Listen(egressbroker.ServerConfig{Address: config.ListenAddress, TLSConfig: serverTLS, Policy: policy,
		PrincipalURI: principal.TLS.URI, PrincipalDNSNames: principal.TLS.DNSNames, PrincipalUsages: principal.TLS.Usages,
		Resolver: dnsResolver, Dialer: &net.Dialer{}, MaxConnections: config.MaxConnections, ReplayCapacity: config.ReplayCapacity, Now: time.Now})
	if err != nil {
		return stageError("listen")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErr := server.Serve(ctx)
	_ = server.Close()
	if errors.Is(serveErr, context.Canceled) {
		return nil
	}
	return stageError("serve")
}

func deploymentPrincipal(profile phase6security.Profile, name string) (phase6security.Principal, bool) {
	for _, principal := range profile.Principals {
		if principal.Name == name {
			return principal, true
		}
	}
	return phase6security.Principal{}, false
}

func principalRegistry(profile phase6security.Profile) (*securityprincipal.Registry, error) {
	egress := make(map[string]securityprincipal.Role)
	for _, principal := range profile.Principals {
		if principal.AuthorizationPrincipal != nil && principal.AuthorizationPrincipal.Kind == securityprincipal.KindEgressBroker {
			egress[principal.AuthorizationPrincipal.Name] = principal.AuthorizationPrincipal.Role
		}
	}
	return securityprincipal.NewRegistry(profile.EnvironmentDigest, profile.PrincipalProfileDigest, egress)
}

func dnsBinding(profile phase6security.Profile, broker string) (phase6security.ExternalService, phase6security.TrustEdge, bool) {
	var service phase6security.ExternalService
	for _, external := range profile.External {
		if external.Name == "dns" {
			service = external
		}
	}
	for _, edge := range profile.TrustEdges {
		if edge.From == broker && edge.To == "dns" && edge.CrossDomain && edge.ExternalIdentityDigest == service.IdentityDigest &&
			edge.Protocol == "dns_tcp" && edge.Authentication == "mtls" {
			return service, edge, true
		}
	}
	return phase6security.ExternalService{}, phase6security.TrustEdge{}, false
}

func validateDNSConfig(profile phase6security.Profile, broker, serverName, address string) (phase6security.ExternalService, bool) {
	service, edge, ok := dnsBinding(profile, broker)
	if !ok || len(service.DNSNames) != 1 || service.DNSNames[0] != serverName {
		return phase6security.ExternalService{}, false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || port != fmt.Sprint(edge.Port) {
		return phase6security.ExternalService{}, false
	}
	return service, true
}

func strictCertPool(document []byte) (*x509.CertPool, error) {
	if len(document) < 1 || len(document) > 256<<10 {
		return nil, egressbroker.ErrInvalid
	}
	pool := x509.NewCertPool()
	remaining, count := document, 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, trailing := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || count >= 16 {
			return nil, egressbroker.ErrInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return nil, egressbroker.ErrInvalid
		}
		pool.AddCert(certificate)
		count++
		remaining = trailing
	}
	if count == 0 {
		return nil, egressbroker.ErrInvalid
	}
	return pool, nil
}

func stageError(stage string) error {
	return fmt.Errorf("stage %s: %w", stage, egressbroker.ErrUnavailable)
}
