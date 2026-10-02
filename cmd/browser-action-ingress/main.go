// browser-action-ingress is the independent, action-fenced Browser CDP write
// boundary. It owns neither Product business truth nor Provider runtime state.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/rolematerials"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

const authorityProtocol = "sandbox-runtime.browser-action-ingress-authority.v1"

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	accountPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$`)
)

type materialProviderDocument struct {
	Type                    string `json:"type"`
	Alias                   string `json:"alias"`
	SocketPath              string `json:"socket_path"`
	ExpectedUID             int64  `json:"expected_uid"`
	ExpectedGID             int64  `json:"expected_gid"`
	OperationTimeoutSeconds int    `json:"operation_timeout_seconds"`
	CacheSeconds            int    `json:"cache_seconds"`
}

type materialBindingDocument struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Document string `json:"document"`
}

type authority struct {
	Protocol                   string                    `json:"protocol"`
	SecurityProfilePath        string                    `json:"security_profile_path"`
	SecurityProfileDigest      string                    `json:"security_profile_digest"`
	PeerCRLRoleFile            string                    `json:"peer_crl_role_file"`
	PeerCRLRoleDigest          string                    `json:"peer_crl_role_digest"`
	PeerCRLSourceMappingDigest string                    `json:"peer_crl_source_mapping_digest"`
	ListenAddress              string                    `json:"listen_address"`
	ProviderOrigin             string                    `json:"provider_origin"`
	ProviderAudience           string                    `json:"provider_audience"`
	TLSAgentSocket             string                    `json:"tls_agent_socket"`
	TLSAgentUID                uint32                    `json:"tls_agent_uid"`
	TLSAgentGID                uint32                    `json:"tls_agent_gid"`
	MaterialProvider           materialProviderDocument  `json:"material_provider"`
	MaterialBindings           []materialBindingDocument `json:"material_bindings"`
	CapacityBindingID          string                    `json:"capacity_binding_id"`
	WitnessBindingID           string                    `json:"witness_binding_id"`
	ExpectedCapacityUser       string                    `json:"expected_capacity_user"`
	WitnessDatabase            string                    `json:"witness_database"`
	WitnessUser                string                    `json:"witness_user"`
	CapacityNamespace          string                    `json:"capacity_namespace"`
	CapacityMaxTotal           int                       `json:"capacity_max_total"`
	CapacityMaxPerTenant       int                       `json:"capacity_max_per_tenant"`
	LeaseTTLMillis             int                       `json:"lease_ttl_millis"`
	RenewIntervalMillis        int                       `json:"renew_interval_millis"`
	RenewalSafetyMillis        int                       `json:"renewal_safety_millis"`
	OperationTimeoutMillis     int                       `json:"operation_timeout_millis"`
	ActionTimeoutMillis        int                       `json:"action_timeout_millis"`
	CredentialPollMillis       int                       `json:"credential_poll_millis"`
	MaxSessions                int                       `json:"max_sessions"`
	MaxActionBytes             int64                     `json:"max_action_bytes"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "browser-action-ingress failed")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 2 || arguments[0] != "serve" || !filepath.IsAbs(arguments[1]) {
		return errors.New("usage: browser-action-ingress serve /absolute/path/to/authority.json")
	}
	document, err := secretfile.Read(arguments[1], executorprotocol.MaxDocumentBytes)
	if err != nil {
		return errors.New("read Browser action ingress authority")
	}
	defer clear(document)
	value, err := decodeAuthority(document)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return serve(ctx, value, arguments[1])
}

func decodeAuthority(document []byte) (authority, error) {
	var value authority
	if executorprotocol.Decode(document, &value) != nil {
		return authority{}, errors.New("invalid Browser action ingress authority")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) || value.Protocol != authorityProtocol ||
		!filepath.IsAbs(value.SecurityProfilePath) || !filepath.IsAbs(value.PeerCRLRoleFile) ||
		!filepath.IsAbs(value.TLSAgentSocket) || filepath.Clean(value.SecurityProfilePath) != value.SecurityProfilePath ||
		filepath.Clean(value.PeerCRLRoleFile) != value.PeerCRLRoleFile ||
		filepath.Clean(value.TLSAgentSocket) != value.TLSAgentSocket ||
		!digestPattern.MatchString(value.SecurityProfileDigest) ||
		!digestPattern.MatchString(value.PeerCRLRoleDigest) || !digestPattern.MatchString(value.PeerCRLSourceMappingDigest) ||
		value.SecurityProfilePath == value.PeerCRLRoleFile || value.TLSAgentUID == 0 || value.TLSAgentGID == 0 ||
		value.CapacityBindingID == "" || value.WitnessBindingID == "" || value.CapacityBindingID == value.WitnessBindingID ||
		!accountPattern.MatchString(value.ExpectedCapacityUser) || value.ExpectedCapacityUser == "default" ||
		!accountPattern.MatchString(value.WitnessDatabase) || !accountPattern.MatchString(value.WitnessUser) ||
		!identifierPattern.MatchString(value.ProviderAudience) ||
		value.CapacityMaxTotal < 1 || value.CapacityMaxTotal > 10000 ||
		value.CapacityMaxPerTenant < 1 || value.CapacityMaxPerTenant > value.CapacityMaxTotal ||
		value.LeaseTTLMillis < 1000 || value.LeaseTTLMillis > 300000 ||
		value.RenewIntervalMillis < 100 || value.RenewIntervalMillis > value.LeaseTTLMillis/2 ||
		value.RenewalSafetyMillis < 100 || value.RenewalSafetyMillis >= value.LeaseTTLMillis ||
		value.OperationTimeoutMillis < 1000 || value.OperationTimeoutMillis > 5000 ||
		value.ActionTimeoutMillis < 1000 || value.ActionTimeoutMillis > 30000 ||
		value.ActionTimeoutMillis < 2*value.MaterialProvider.OperationTimeoutSeconds*1000+2*value.OperationTimeoutMillis+1000 ||
		value.CredentialPollMillis < 100 || value.CredentialPollMillis > 5000 ||
		value.MaxSessions < 1 || value.MaxSessions > 256 || value.MaxActionBytes < 1 || value.MaxActionBytes > 65536 ||
		len(value.MaterialBindings) != 2 || value.MaterialProvider.CacheSeconds != 0 ||
		value.MaterialProvider.OperationTimeoutSeconds < 1 || value.MaterialProvider.OperationTimeoutSeconds > 5 {
		return authority{}, errors.New("Browser action ingress authority is not canonical or bounded")
	}
	if !validNumericAddress(value.ListenAddress) || !validNumericAddressFromOrigin(value.ProviderOrigin) {
		return authority{}, errors.New("Browser action ingress network address is invalid")
	}
	return value, nil
}

func validNumericAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	portValue, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && portValue >= 1 && portValue <= 65535 &&
		port == strconv.Itoa(portValue) && ip != nil && ip.To4() != nil &&
		!ip.IsUnspecified() && !ip.IsLoopback() && address == net.JoinHostPort(ip.String(), port)
}

func validNumericAddressFromOrigin(origin string) bool {
	const suffix = "/private/browser"
	if len(origin) <= len("wss://")+len(suffix) || origin[:6] != "wss://" || origin[len(origin)-len(suffix):] != suffix {
		return false
	}
	return validNumericAddress(origin[6 : len(origin)-len(suffix)])
}

func (a authority) materials(profile phase6security.Profile) (config.RoleMaterialsConfig, error) {
	bound, err := ingressMaterialBinding(profile)
	if err != nil {
		return config.RoleMaterialsConfig{}, errors.New("Browser action ingress material socket is unavailable")
	}
	provider := a.MaterialProvider
	bindings := make([]config.RoleMaterialBindingConfig, len(a.MaterialBindings))
	for index, value := range a.MaterialBindings {
		bindings[index] = config.RoleMaterialBindingConfig{ID: value.ID, Provider: value.Provider, Document: value.Document}
	}
	return config.RoleMaterialsConfig{Provider: config.RoleMaterialProviderConfig{
		Type: provider.Type, Alias: provider.Alias, SocketPath: provider.SocketPath,
		ExpectedUID: provider.ExpectedUID, ExpectedGID: provider.ExpectedGID,
		DirectoryGID:            int64(bound.OwnerGID),
		OperationTimeoutSeconds: provider.OperationTimeoutSeconds, CacheSeconds: provider.CacheSeconds,
	}, Bindings: bindings}, nil
}

func serve(ctx context.Context, a authority, authorityPath string) error { //nolint:cyclop
	profile, err := phase6security.VerifySlice6ProfileForDeployment(a.SecurityProfilePath, "browser-action-ingress-runtime")
	if err != nil || profile.ProfileDigest != a.SecurityProfileDigest ||
		phase6security.VerifySlice6PrivateConfigPath(profile, "browser-action-ingress-runtime",
			phase6security.Slice6StartupAuthorityFile, authorityPath) != nil ||
		phase6security.VerifySlice6PrivateConfigPath(profile, "browser-action-ingress-runtime",
			phase6security.Slice6PeerCRLRoleFile, a.PeerCRLRoleFile) != nil {
		return errors.New("Browser action ingress security profile mismatch")
	}
	role, err := phase6security.VerifyPeerCRLRoleFile(a.PeerCRLRoleFile, profile,
		a.PeerCRLSourceMappingDigest, a.PeerCRLRoleDigest)
	if err != nil {
		return errors.New("Browser action ingress peer revocation role mismatch")
	}
	if err := validateMaterialBoundary(profile, a); err != nil {
		return err
	}
	materials, err := a.materials(profile)
	if err != nil {
		return err
	}
	registry, err := rolematerials.NewSlice6ForDeployment(materials, "browser-action-ingress-runtime", profile, secretref.RoleGateway,
		[]secretref.Purpose{secretref.PurposeCapacityValkeyCredentials, secretref.PurposeActionHistoryWitnessDSN}, false, time.Now)
	if err != nil {
		return errors.New("Browser action ingress material registry unavailable")
	}
	defer registry.Close()
	timeout := time.Duration(a.OperationTimeoutMillis) * time.Millisecond
	serverTLS, serverProbe, gatewayURI, inboundGuard, err := phase6tls.BrowserActionIngressServer(profile,
		phase6tls.ProviderServerAuthority{EdgeID: phase6security.GatewayBrowserActionIngressEdgeID,
			ListenAddress: a.ListenAddress, PeerCRLRole: role, AgentSocket: a.TLSAgentSocket,
			AgentUID: a.TLSAgentUID, AgentGID: a.TLSAgentGID, OperationTimeout: timeout})
	if err != nil {
		return errors.New("Browser action ingress server TLS unavailable")
	}
	defer inboundGuard.Close()
	providerTransport, providerGuard, err := phase6tls.BrowserActionIngressProviderClient(profile,
		phase6tls.GatewayProviderClientAuthority{Origin: a.ProviderOrigin, PeerCRLRole: role,
			AgentSocket: a.TLSAgentSocket, AgentUID: a.TLSAgentUID, AgentGID: a.TLSAgentGID, OperationTimeout: timeout})
	if err != nil {
		return errors.New("Browser action ingress Provider TLS unavailable")
	}
	defer providerGuard.Close()
	defer providerTransport.CloseIdleConnections()
	broker, brokerGuard, err := phase6egress.NewBrokerClient(profile, phase6egress.BrokerClientAuthority{
		PolicyID: "browser-action-ingress-egress", PeerCRLRole: role,
		AgentSocket: a.TLSAgentSocket, AgentUID: a.TLSAgentUID,
		AgentGID: a.TLSAgentGID, OperationTimeout: timeout})
	if err != nil {
		return errors.New("Browser action ingress broker TLS unavailable")
	}
	defer brokerGuard.Close()
	if serverProbe(ctx) != nil || providerGuard.Bootstrap(ctx) != nil || brokerGuard.Bootstrap(ctx) != nil {
		return errors.New("Browser action ingress trust evidence unavailable")
	}
	principal, agent, err := ingressTLSPrincipals(profile)
	if err != nil {
		return err
	}
	certificateSource, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: a.TLSAgentSocket, ExpectedUID: a.TLSAgentUID, ExpectedGID: a.TLSAgentGID,
		RoleGID: principal.GID, OperationTimeout: timeout, Now: time.Now})
	if err != nil || agent.UID != a.TLSAgentUID || agent.GID != a.TLSAgentGID {
		return errors.New("Browser action ingress TLS signer unavailable")
	}
	certificate := func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if request == nil {
			return nil, phase6egress.ErrUnavailable
		}
		value, certErr := certificateSource.CertificateForHandshake(request.Context())
		return &value, certErr
	}
	clients, err := phase6egress.NewBrowserExternalClients(ctx, phase6egress.BrowserExternalOptions{
		Profile: profile, Broker: broker, BrokerGuard: brokerGuard, Certificate: certificate,
		Resolver: registry, CapacityBindingID: a.CapacityBindingID, WitnessBindingID: a.WitnessBindingID,
		ExpectedCapacityUser: a.ExpectedCapacityUser, WitnessDatabase: a.WitnessDatabase,
		WitnessUser: a.WitnessUser, CapacityNamespace: a.CapacityNamespace,
		MaxTotal: a.CapacityMaxTotal, MaxPerTenant: a.CapacityMaxPerTenant,
		LeaseTTL:            time.Duration(a.LeaseTTLMillis) * time.Millisecond,
		RenewInterval:       time.Duration(a.RenewIntervalMillis) * time.Millisecond,
		RenewalSafetyMargin: time.Duration(a.RenewalSafetyMillis) * time.Millisecond,
		OperationTimeout:    timeout, CredentialPollInterval: time.Duration(a.CredentialPollMillis) * time.Millisecond})
	if err != nil {
		return errors.New("Browser action ingress external authority unavailable")
	}
	defer clients.Close()
	ingress, err := cdpfence.New(cdpfence.Options{Authority: phase6egress.WitnessRoleGatedAuthority{
		Role: clients.Role, Next: phase6egress.CredentialGatedAuthority{Guard: clients.Guard, Next: clients.Fencer}},
		ActionTimeout: time.Duration(a.ActionTimeoutMillis) * time.Millisecond,
		CloseTimeout:  timeout, MaxSessions: a.MaxSessions, MaxActionBytes: a.MaxActionBytes})
	if err != nil {
		return errors.New("Browser action ingress fence unavailable")
	}
	providerClient, err := cdpfence.NewV2ProviderClient(cdpfence.V2ProviderClientOptions{
		Origin: a.ProviderOrigin, HTTPClient: &http.Client{Transport: providerTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("private redirect denied") }},
		MaxMessageBytes: a.MaxActionBytes})
	if err != nil {
		return errors.New("Browser action ingress Provider client unavailable")
	}
	handler, err := cdpfence.NewV2NetworkHandler(cdpfence.V2NetworkOptions{Ingress: ingress,
		Provider: providerClient, ExpectedHost: a.ListenAddress, ExpectedProviderAudience: a.ProviderAudience,
		OperationTimeout: timeout, MaxMessageBytes: a.MaxActionBytes,
		PeerAuthorizer: cdpfence.PeerAuthorizerFunc(func(peerCtx context.Context, state tls.ConnectionState) error {
			if !inboundGuard.Ready() || !state.HandshakeComplete || len(state.PeerCertificates) == 0 ||
				len(state.VerifiedChains) != 1 || state.PeerCertificates[0] == nil ||
				len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != gatewayURI {
				return phase6tls.ErrPeerCRLUnavailable
			}
			return inboundGuard.CheckHandshake(peerCtx, state)
		})})
	if err != nil {
		return errors.New("Browser action ingress route unavailable")
	}
	server, err := newPrivateServer(ctx, profile, a, serverTLS, inboundGuard, gatewayURI, handler)
	if err != nil {
		return err
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopProvider, err := providerGuard.StartPolling(runtimeCtx)
	if err != nil {
		return errors.New("Browser Provider peer revocation monitor unavailable")
	}
	defer stopProvider()
	stopBroker, err := brokerGuard.StartPolling(runtimeCtx)
	if err != nil {
		return errors.New("Browser broker peer revocation monitor unavailable")
	}
	defer stopBroker()
	dependencyFailed := make(chan struct{})
	var failOnce sync.Once
	fail := func() { failOnce.Do(func() { close(dependencyFailed); cancel() }) }
	roleDone, err := clients.Role.StartPolling(runtimeCtx, fail)
	if err != nil {
		return errors.New("Browser witness role monitor unavailable")
	}
	defer func() { cancel(); <-roleDone }()
	credentialDone, err := clients.Guard.StartPolling(runtimeCtx, fail)
	if err != nil {
		return errors.New("Browser external credential monitor unavailable")
	}
	defer func() { cancel(); <-credentialDone }()
	go monitorTrust(runtimeCtx, fail, inboundGuard, providerGuard, brokerGuard)
	serveErr := server.Startup(runtimeCtx)
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), timeout)
	defer shutdownCancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	select {
	case <-dependencyFailed:
		return errors.New("Browser action ingress dependency lost")
	default:
	}
	if serveErr != nil || shutdownErr != nil {
		return errors.New("Browser action ingress serve or cleanup failed")
	}
	return nil
}

func validateMaterialBoundary(profile phase6security.Profile, a authority) error {
	bound, boundErr := ingressMaterialBinding(profile)
	var agent phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == "browser-action-ingress-agent" {
			agent = candidate
		}
	}
	if boundErr != nil || bound.AgentDeployment != agent.Name || agent.Name != "browser-action-ingress-agent" ||
		a.MaterialProvider.Type != config.UnixWorkloadMaterialProviderV2 ||
		a.MaterialProvider.SocketPath != bound.SocketPath ||
		a.MaterialProvider.ExpectedUID != int64(bound.AgentUID) ||
		a.MaterialProvider.ExpectedGID != int64(bound.AgentGID) ||
		a.MaterialProvider.OperationTimeoutSeconds > bound.MaxOperationSeconds ||
		a.MaterialProvider.ExpectedUID != int64(agent.UID) ||
		a.MaterialProvider.ExpectedGID != int64(agent.GID) {
		return errors.New("Browser action ingress material agent principal mismatch")
	}
	materials, err := a.materials(profile)
	if err != nil {
		return err
	}
	bindings, err := materials.DecodeBindings(secretref.RoleGateway)
	if err != nil || len(bindings) != 2 ||
		bindings[a.CapacityBindingID].Purpose != secretref.PurposeCapacityValkeyCredentials ||
		bindings[a.WitnessBindingID].Purpose != secretref.PurposeActionHistoryWitnessDSN ||
		bindings[a.CapacityBindingID].TenantID != secretref.SystemTenant ||
		bindings[a.WitnessBindingID].TenantID != secretref.SystemTenant {
		return errors.New("Browser action ingress material bindings are invalid")
	}
	return nil
}

// This local projection is used only after serve has verified the complete
// Profile; the production registry independently repeats full validation.
func ingressMaterialBinding(profile phase6security.Profile) (phase6security.Slice6MaterialSocketBinding, error) {
	var found phase6security.Slice6MaterialSocketBinding
	for _, binding := range profile.MaterialSockets {
		if binding.OwnerDeployment != "browser-action-ingress-runtime" {
			continue
		}
		if found.OwnerDeployment != "" || binding.AgentDeployment != "browser-action-ingress-agent" ||
			binding.SocketPath == "" || binding.OwnerGID == binding.AgentGID {
			return phase6security.Slice6MaterialSocketBinding{}, errors.New("Browser action ingress material socket is invalid")
		}
		found = binding
	}
	if found.OwnerDeployment == "" {
		return phase6security.Slice6MaterialSocketBinding{}, errors.New("Browser action ingress material socket is missing")
	}
	return found, nil
}

func ingressTLSPrincipals(profile phase6security.Profile) (phase6security.Principal, phase6security.Principal, error) {
	var runtime, agent phase6security.Principal
	for _, candidate := range profile.Principals {
		switch candidate.Name {
		case "browser-action-ingress-runtime":
			runtime = candidate
		case "browser-action-ingress-tls-agent":
			agent = candidate
		}
	}
	if runtime.Name == "" || agent.Name == "" {
		return phase6security.Principal{}, phase6security.Principal{}, errors.New("Browser ingress TLS principals are missing")
	}
	return runtime, agent, nil
}

func newPrivateServer(ctx context.Context, profile phase6security.Profile, a authority, serverTLS *tls.Config,
	guard *phase6tls.PeerCRLGuard, gatewayURI string, handler http.Handler) (*providerapi.PrivateServer, error) {
	edge, _, _, _, _, err := profile.GatewayBrowserActionIngressBoundary("wss://" + a.ListenAddress + cdpfence.BrowserActionV2Path)
	host, portText, splitErr := net.SplitHostPort(a.ListenAddress)
	port, portErr := strconv.Atoi(portText)
	if err != nil || splitErr != nil || portErr != nil || edge.MaxConnectionSeconds < 1 ||
		gatewayURI != edge.FromURI {
		return nil, errors.New("Browser action ingress server edge mismatch")
	}
	server, err := providerapi.NewPrivateServer(ctx, providerapi.PrivateTransportOptions{
		Address: option.HTTP{Host: host, Port: port}, TLSConfig: serverTLS,
		AllowedClientURIIdentities: []string{gatewayURI}, Handler: handler,
		PeerRevocationMonitor: guard, ConnectionMaxAge: time.Duration(edge.MaxConnectionSeconds) * time.Second,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10, MaxBodyBytes: executorprotocol.MaxDocumentBytes,
	})
	if err != nil {
		return nil, errors.New("Browser action ingress private server unavailable")
	}
	return server, nil
}

func monitorTrust(ctx context.Context, fail func(), guards ...*phase6tls.PeerCRLGuard) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, guard := range guards {
				if guard == nil || !guard.Ready() {
					fail()
					return
				}
			}
		}
	}
}
