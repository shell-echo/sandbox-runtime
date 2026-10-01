// egress-policy-broker is the sole external uplink for one Phase 6 principal.
// Callers select only a profile-defined alias; the broker owns authenticated
// DNS, address policy checks and the numeric dial.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egressbroker"
	"github.com/shell-echo/sandbox-runtime/internal/egresspolicystate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

const (
	configProtocol = "sandbox-runtime.egress-policy-broker-config.v3"
	maxConfigBytes = 512 << 10
)

type configDocument struct {
	Protocol                   string `json:"protocol"`
	SecurityProfilePath        string `json:"security_profile_path"`
	PeerCRLRoleFile            string `json:"peer_crl_role_file"`
	PeerCRLRoleDigest          string `json:"peer_crl_role_digest"`
	PeerCRLSourceMappingDigest string `json:"peer_crl_source_mapping_digest"`
	PolicyID                   string `json:"policy_id"`
	ListenAddress              string `json:"listen_address"`
	TLSAgentSocket             string `json:"tls_agent_socket"`
	TLSAgentExpectedUID        uint32 `json:"tls_agent_expected_uid"`
	TLSAgentExpectedGID        uint32 `json:"tls_agent_expected_gid"`
	DNSAddress                 string `json:"dns_address"`
	DNSServerName              string `json:"dns_server_name"`
	MaxConnections             int    `json:"max_connections"`
	ReplayCapacity             int    `json:"replay_capacity"`
	OperationTimeoutSeconds    int    `json:"operation_timeout_seconds"`
	PolicyStateKeyID           string `json:"policy_state_key_id"`
	PolicyStatePublicKey       []byte `json:"policy_state_public_key"`
	PolicyCurrentPollMillis    int    `json:"policy_current_poll_millis"`
	PolicyAuthoritySocket      string `json:"policy_authority_socket"`
	PolicyAuthorityUID         uint32 `json:"policy_authority_uid"`
	PolicyAuthorityGID         uint32 `json:"policy_authority_gid"`
	PolicyBrokerGID            uint32 `json:"policy_broker_gid"`
	PolicyAuthorityTimeoutMS   int    `json:"policy_authority_timeout_ms"`
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
	config, err := decodeConfig(document)
	if err != nil {
		return err
	}
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
	if phase6security.VerifySlice6PrivateConfigPath(profile, profilePolicy.Broker,
		phase6security.Slice6ProfileConfigFile, config.SecurityProfilePath) != nil ||
		phase6security.VerifySlice6PrivateConfigPath(profile, profilePolicy.Broker,
			phase6security.Slice6PeerCRLRoleFile, config.PeerCRLRoleFile) != nil {
		return stageError("private-config")
	}
	principal, principalOK := deploymentPrincipal(profile, profilePolicy.Principal)
	broker, brokerOK := deploymentPrincipal(profile, profilePolicy.Broker)
	if !principalOK || !brokerOK || principal.AuthorizationPrincipal == nil || broker.AuthorizationPrincipal == nil ||
		principal.PrincipalDigest != profilePolicy.PrincipalDigest || broker.PrincipalDigest != profilePolicy.BrokerDigest ||
		principal.TLS == nil || broker.TLS == nil {
		return stageError("policy-principal")
	}
	if !validatePolicyAuthorityConfig(profile, profilePolicy, broker, config) {
		return stageError("policy-authority-binding")
	}
	if !validateTLSAgentConfig(profile, broker, config) {
		return stageError("tls-agent-binding")
	}
	roleDocument, err := phase6security.VerifyPeerCRLRoleFile(config.PeerCRLRoleFile, profile,
		config.PeerCRLSourceMappingDigest, config.PeerCRLRoleDigest)
	if err != nil || roleDocument.LocalPrincipalDigest != broker.PrincipalDigest {
		return stageError("peer-crl-role")
	}
	if uint32(os.Getuid()) != broker.UID || uint32(os.Getgid()) != broker.GID {
		return stageError("broker-process-identity")
	}
	if !validateBrokerListenConfig(broker, config.ListenAddress) {
		return stageError("broker-listener-binding")
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
	stateBinding, err := egresspolicystate.NewBinding(egresspolicystate.BindingConfig{
		EnvironmentDigest: profile.EnvironmentDigest, ProfileDigest: profile.ProfileDigest, Policy: profilePolicy,
		OperatorKeyID: config.PolicyStateKeyID, OperatorPublicKey: config.PolicyStatePublicKey,
		MaxAge: time.Duration(profilePolicy.Authority.StateMaxAgeSeconds) * time.Second})
	if err != nil {
		return stageError("policy-state-binding")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{SocketPath: config.TLSAgentSocket,
		ExpectedUID: config.TLSAgentExpectedUID, ExpectedGID: config.TLSAgentExpectedGID, RoleGID: uint32(os.Getgid()),
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now})
	if err != nil {
		return stageError("tls-agent")
	}
	inboundEdge, boundCaller, boundBroker, _, err := profile.BrokerBoundaryForPolicy(profilePolicy.ID)
	if err != nil || boundCaller.Name != principal.Name || boundBroker.Name != broker.Name ||
		inboundEdge.TargetAddress != config.ListenAddress {
		return stageError("broker-inbound-edge")
	}
	_, clientAnchor, err := profile.EdgeTrustAnchors(inboundEdge.ID)
	if err != nil {
		return stageError("broker-client-anchor")
	}
	clientBundle, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return stageError("broker-client-anchor")
	}
	clientRoots, err := strictCertPool(clientBundle)
	clear(clientBundle)
	if err != nil {
		return stageError("client-ca")
	}
	dnsService, ok := validateDNSConfig(profile, profilePolicy.Broker, config.DNSServerName, config.DNSAddress)
	if !ok {
		return stageError("dns-binding")
	}
	_, dnsEdge, ok := dnsBinding(profile, broker.Name)
	if !ok {
		return stageError("dns-edge")
	}
	dnsAnchor, _, err := profile.EdgeTrustAnchors(dnsEdge.ID)
	if err != nil {
		return stageError("dns-anchor")
	}
	dnsBundle, err := trustanchor.Load(dnsAnchor, time.Now())
	if err != nil {
		return stageError("dns-anchor")
	}
	dnsRoots, err := strictCertPool(dnsBundle)
	clear(dnsBundle)
	if err != nil {
		return stageError("dns-ca")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	inboundGuard, err := phase6tls.NewPeerCRLGuard(profile, roleDocument, inboundEdge.ID, broker.PrincipalDigest,
		"inbound", agentClient, time.Duration(config.OperationTimeoutSeconds)*time.Second, time.Now)
	if err != nil {
		return stageError("inbound-peer-guard")
	}
	defer inboundGuard.Close()
	dnsGuard, err := phase6tls.NewPeerCRLGuard(profile, roleDocument, dnsEdge.ID, broker.PrincipalDigest,
		"outbound", agentClient, time.Duration(config.OperationTimeoutSeconds)*time.Second, time.Now)
	if err != nil {
		return stageError("dns-peer-guard")
	}
	defer dnsGuard.Close()
	bootstrapCtx, stopBootstrap := context.WithTimeout(ctx, time.Duration(config.OperationTimeoutSeconds)*time.Second)
	bootstrapErr := dnsGuard.Bootstrap(bootstrapCtx)
	stopBootstrap()
	if bootstrapErr != nil || !dnsGuard.Ready() {
		return stageError("dns-peer-bootstrap")
	}
	bootstrapCtx, stopBootstrap = context.WithTimeout(ctx, time.Duration(config.OperationTimeoutSeconds)*time.Second)
	bootstrapErr = inboundGuard.Bootstrap(bootstrapCtx)
	stopBootstrap()
	if bootstrapErr != nil || !inboundGuard.Ready() {
		return stageError("inbound-peer-bootstrap")
	}
	dnsTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: dnsRoots, ServerName: config.DNSServerName}
	dnsTLS.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		certificate, certificateErr := agentClient.Certificate(info.Context())
		return &certificate, certificateErr
	}
	dnsResolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	dnsResolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if ctx == nil || !dnsGuard.Ready() {
			return nil, egressbroker.ErrUnavailable
		}
		connectionValue, dialErr := (&tls.Dialer{Config: dnsTLS}).DialContext(ctx, "tcp", config.DNSAddress)
		if dialErr != nil {
			return nil, egressbroker.ErrUnavailable
		}
		connection, tlsOK := connectionValue.(*tls.Conn)
		if !tlsOK {
			_ = connectionValue.Close()
			return nil, egressbroker.ErrDenied
		}
		state := connection.ConnectionState()
		if egressbroker.ValidateTLSIdentity(state, dnsService.URI,
			[]string{config.DNSServerName}, []string{"server_auth"}) != nil ||
			dnsGuard.CheckHandshake(ctx, state) != nil || dnsGuard.Track(connection, state) != nil {
			_ = connectionValue.Close()
			return nil, egressbroker.ErrDenied
		}
		expiresAt := time.Now().Add(time.Duration(dnsEdge.MaxConnectionSeconds) * time.Second)
		if connection.SetDeadline(expiresAt) != nil {
			dnsGuard.Forget(connection)
			_ = connection.Close()
			return nil, egressbroker.ErrUnavailable
		}
		return &guardedDNSConn{Conn: connection, guard: dnsGuard, expiresAt: expiresAt}, nil
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots, NextProtos: []string{egressbroker.ProtocolID}}
	serverTLS.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certificate, certificateErr := agentClient.Certificate(info.Context())
		return &certificate, certificateErr
	}
	authorityClient, err := egresspolicystate.NewAuthorityClient(egresspolicystate.AuthorityClientConfig{
		SocketPath: config.PolicyAuthoritySocket, ExpectedAuthorityUID: config.PolicyAuthorityUID,
		ExpectedAuthorityGID: config.PolicyAuthorityGID, BrokerGID: config.PolicyBrokerGID,
		Binding: stateBinding, Timeout: time.Duration(config.PolicyAuthorityTimeoutMS) * time.Millisecond, Now: time.Now})
	if err != nil {
		return stageError("policy-authority-client")
	}
	current, err := authorityClient.Current(ctx)
	currentTracker := new(egresspolicystate.CurrentTracker)
	if err != nil || currentTracker.Accept(current, time.Now().UTC()) != nil {
		return stageError("policy-authority-current")
	}
	server, err := egressbroker.Listen(egressbroker.ServerConfig{Address: config.ListenAddress, TLSConfig: serverTLS, Policy: policy,
		PrincipalURI: principal.TLS.URI, PrincipalDNSNames: principal.TLS.DNSNames, PrincipalUsages: principal.TLS.Usages,
		Resolver: dnsResolver, Dialer: &net.Dialer{}, MaxConnections: config.MaxConnections, ReplayCapacity: config.ReplayCapacity,
		Now: time.Now, PeerRevocation: inboundGuard})
	if err != nil {
		return stageError("listen")
	}
	stopDNSPoll, err := dnsGuard.StartPolling(ctx)
	if err != nil {
		_ = server.Close()
		return stageError("dns-peer-poll")
	}
	defer stopDNSPoll()
	stopInboundPoll, err := inboundGuard.StartPolling(ctx)
	if err != nil {
		_ = server.Close()
		return stageError("inbound-peer-poll")
	}
	defer stopInboundPoll()
	var peerFailed atomic.Bool
	dnsMonitorDone := make(chan struct{})
	go func() {
		defer close(dnsMonitorDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !dnsGuard.Ready() || !inboundGuard.Ready() {
					peerFailed.Store(true)
					_ = server.RevokePolicy(policy.Revision)
					cancel()
					return
				}
			}
		}
	}()
	monitorDone := make(chan error, 1)
	go func() {
		monitorErr := egresspolicystate.PollCurrent(ctx, authorityClient, currentTracker,
			time.Duration(config.PolicyCurrentPollMillis)*time.Millisecond, time.Now)
		if monitorErr != nil && !errors.Is(monitorErr, context.Canceled) {
			_ = server.RevokePolicy(policy.Revision)
			cancel()
		}
		monitorDone <- monitorErr
	}()
	serveErr := server.Serve(ctx)
	cancel()
	<-dnsMonitorDone
	monitorErr := <-monitorDone
	_ = server.Close()
	if peerFailed.Load() {
		return stageError("peer-revocation")
	}
	if monitorErr != nil && !errors.Is(monitorErr, context.Canceled) {
		return stageError("policy-state")
	}
	if errors.Is(serveErr, context.Canceled) {
		return nil
	}
	return stageError("serve")
}

func decodeConfig(document []byte) (configDocument, error) {
	var config configDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return configDocument{}, stageError("config-decode")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return configDocument{}, stageError("config-trailing")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, document) || config.Protocol != configProtocol ||
		!filepath.IsAbs(config.SecurityProfilePath) || config.PolicyID == "" || config.ListenAddress == "" ||
		!filepath.IsAbs(config.PeerCRLRoleFile) || filepath.Clean(config.PeerCRLRoleFile) != config.PeerCRLRoleFile ||
		config.PeerCRLRoleFile == config.SecurityProfilePath ||
		!validDigest(config.PeerCRLRoleDigest) || !validDigest(config.PeerCRLSourceMappingDigest) ||
		config.DNSAddress == "" || net.ParseIP(config.DNSServerName) != nil || config.DNSServerName == "" ||
		config.MaxConnections < 1 || config.MaxConnections > 1024 || config.ReplayCapacity < 16 || config.ReplayCapacity > 65536 ||
		config.OperationTimeoutSeconds < 1 || config.OperationTimeoutSeconds > 60 ||
		config.PolicyStateKeyID == "" || len(config.PolicyStatePublicKey) != ed25519.PublicKeySize ||
		config.PolicyCurrentPollMillis < 50 || config.PolicyCurrentPollMillis > 1000 ||
		!filepath.IsAbs(config.PolicyAuthoritySocket) || filepath.Clean(config.PolicyAuthoritySocket) != config.PolicyAuthoritySocket ||
		config.PolicyAuthorityTimeoutMS < 100 || config.PolicyAuthorityTimeoutMS > 5000 {
		clear(canonical)
		return configDocument{}, stageError("config-validate")
	}
	clear(canonical)
	return config, nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, digit := range value[len("sha256:"):] {
		if digit < '0' || digit > '9' {
			if digit < 'a' || digit > 'f' {
				return false
			}
		}
	}
	return true
}

// Resolver closes this wrapper after each DNS exchange. The guard tracks the
// underlying TLS connection so a CRL failure can close it immediately.
type guardedDNSConn struct {
	net.Conn
	guard     *phase6tls.PeerCRLGuard
	expiresAt time.Time
	once      sync.Once
}

func (c *guardedDNSConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.guard.Forget(c.Conn) })
	return err
}

func (c *guardedDNSConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() || deadline.After(c.expiresAt) {
		deadline = c.expiresAt
	}
	return c.Conn.SetDeadline(deadline)
}

func (c *guardedDNSConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() || deadline.After(c.expiresAt) {
		deadline = c.expiresAt
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *guardedDNSConn) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() || deadline.After(c.expiresAt) {
		deadline = c.expiresAt
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func validatePolicyAuthorityConfig(profile phase6security.Profile, policy phase6security.EgressPolicy,
	broker phase6security.Principal, config configDocument) bool {
	authority, found := deploymentPrincipal(profile, policy.Authority.DeploymentName)
	return found && authority.Kind == "controller" && authority.PrincipalDigest == policy.Authority.PrincipalDigest &&
		config.PolicyAuthoritySocket == filepath.Join(policy.Authority.SocketDirectory, "current.sock") &&
		config.PolicyStateKeyID == policy.Authority.KeyID &&
		phase6security.OperatorPublicKeyDigest(config.PolicyStatePublicKey) == policy.Authority.PublicKeyDigest &&
		config.PolicyAuthorityUID == authority.UID && config.PolicyAuthorityGID == authority.GID &&
		config.PolicyBrokerGID == broker.GID &&
		config.PolicyCurrentPollMillis == policy.Authority.PollMillis &&
		config.PolicyAuthorityTimeoutMS == policy.Authority.CurrentTimeoutMS
}

func validateTLSAgentConfig(profile phase6security.Profile, broker phase6security.Principal, config configDocument) bool {
	binding, agent, subject, err := profile.TLSAgentForSubject(broker.Name)
	return err == nil && matchesTLSAgentConfig(binding, agent, subject, broker, config)
}

func matchesTLSAgentConfig(binding phase6security.TLSAgentBinding, agent, subject,
	broker phase6security.Principal, config configDocument) bool {
	return subject.PrincipalDigest == broker.PrincipalDigest && subject.Name == broker.Name && subject.GID == binding.SubjectGID &&
		agent.Name == binding.AgentDeployment && agent.PrincipalDigest == binding.AgentPrincipalDigest &&
		agent.UID == binding.AgentUID && agent.GID == binding.AgentGID &&
		binding.SubjectDeployment == broker.Name && binding.SubjectPrincipalDigest == broker.PrincipalDigest && agent.Kind == "tls_agent" &&
		config.TLSAgentSocket == binding.SocketPath && config.TLSAgentExpectedUID == binding.AgentUID &&
		config.TLSAgentExpectedGID == binding.AgentGID && broker.GID == binding.SubjectGID
}

func validateBrokerListenConfig(broker phase6security.Principal, address string) bool {
	target, err := netip.ParseAddrPort(address)
	if err != nil || !target.Addr().Is4() || !target.Addr().IsPrivate() || target.String() != address ||
		len(broker.Listeners) != 1 {
		return false
	}
	listener := broker.Listeners[0]
	return listener.Name == "egress" && listener.Protocol == "tcp" &&
		listener.Exposure == "trust_edge" && listener.Port == int(target.Port())
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
	matched := false
	for _, path := range phase6security.Slice6DesiredExternalTransports() {
		if path.Dialer != broker || path.Service != "dns" || len(path.EdgeIDs) != 1 || path.EdgeIDs[0] != edge.ID {
			continue
		}
		expected, endpointErr := phase6security.Slice6DesiredServiceEndpointAddress(path.Network, "dns")
		if endpointErr != nil || host != expected || matched {
			return phase6security.ExternalService{}, false
		}
		matched = true
	}
	if !matched {
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
