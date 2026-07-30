// Package providerapi implements the versioned Sandbox Provider HTTP transport.
// It is intentionally separate from the local management API and its envelope.
package providerapi

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	maxTLSFileBytes   = 1 << 20
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 64 << 10
)

type TLSOptions struct {
	CertificateFile        string
	PrivateKeyFile         string
	ClientCAFile           string
	AllowedClientSPIFFEIDs []string
}

type Options struct {
	Listen option.HTTP
	TLS    TLSOptions
}

type Server struct {
	http *http.Server
}

// NewServer validates all TLS material and identity policy before returning a
// server. An enabled Provider listener therefore cannot defer unsafe
// configuration failure until the first request.
func NewServer(options Options, capabilities provider.CapabilityService) (*Server, error) {
	if capabilities == nil {
		return nil, errors.New("Provider capability service is required")
	}
	if err := options.Listen.Validate(); err != nil {
		return nil, fmt.Errorf("Provider listener: %w", err)
	}
	tlsConfig, admitter, err := loadTLSConfig(options.TLS)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	handler := capabilityHandler{service: capabilities}
	mux.HandleFunc("GET /v1/capabilities", handler.get)

	return &Server{http: &http.Server{
		Addr:              options.Listen.Addr(),
		Handler:           admitter.wrap(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}}, nil
}

func (s *Server) Startup() error {
	if err := s.http.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("start Provider API server: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func loadTLSConfig(options TLSOptions) (*tls.Config, *identityAdmitter, error) {
	certificatePEM, err := readBoundedFile(options.CertificateFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read Provider TLS certificate: %w", err)
	}
	privateKeyPEM, err := readBoundedFile(options.PrivateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read Provider TLS private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load Provider TLS key pair: %w", err)
	}
	clientCAPEM, err := readBoundedFile(options.ClientCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read Provider client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, nil, errors.New("Provider client CA contains no certificate")
	}
	admitter, err := newIdentityAdmitter(options.AllowedClientSPIFFEIDs)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, admitter, nil
}

func readBoundedFile(name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("file path is required")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxTLSFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxTLSFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxTLSFileBytes)
	}
	return data, nil
}

type identityAdmitter struct {
	allowed map[string]struct{}
}

func newIdentityAdmitter(identities []string) (*identityAdmitter, error) {
	if len(identities) == 0 {
		return nil, errors.New("at least one allowed Provider client SPIFFE ID is required")
	}
	if len(identities) > 64 {
		return nil, errors.New("at most 64 Provider client SPIFFE IDs are supported")
	}
	allowed := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		parsed, err := parseSPIFFEID(identity)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed Provider client identity: %w", err)
		}
		if _, duplicate := allowed[parsed]; duplicate {
			return nil, fmt.Errorf("duplicate allowed Provider client identity %q", parsed)
		}
		allowed[parsed] = struct{}{}
	}
	return &identityAdmitter{allowed: allowed}, nil
}

func parseSPIFFEID(value string) (string, error) {
	if value == "" || len(value) > 500 || strings.TrimSpace(value) != value {
		return "", errors.New("SPIFFE ID must be between 1 and 500 bytes without surrounding whitespace")
	}
	identity, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if identity.Scheme != "spiffe" || identity.Host == "" || identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" || !strings.HasPrefix(identity.Path, "/") {
		return "", errors.New("SPIFFE ID must contain a trust domain and path without user info, query, or fragment")
	}
	if identity.String() != value {
		return "", errors.New("SPIFFE ID must use its canonical URI form")
	}
	return value, nil
}

var (
	errMissingIdentity    = errors.New("verified client workload identity is missing")
	errUnadmittedIdentity = errors.New("client workload identity is not admitted")
)

func (a *identityAdmitter) admit(request *http.Request) error {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.VerifiedChains) == 0 {
		return errMissingIdentity
	}
	leaf := request.TLS.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return errUnadmittedIdentity
	}
	identity, err := parseSPIFFEID(leaf.URIs[0].String())
	if err != nil {
		return errUnadmittedIdentity
	}
	if _, ok := a.allowed[identity]; !ok {
		return errUnadmittedIdentity
	}
	return nil
}

func (a *identityAdmitter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch err := a.admit(request); {
		case errors.Is(err, errMissingIdentity):
			writeProviderError(writer, http.StatusUnauthorized, "SANDBOX_UNAUTHORIZED", "authenticated workload identity is required", false)
			return
		case errors.Is(err, errUnadmittedIdentity):
			writeProviderError(writer, http.StatusForbidden, "SANDBOX_POLICY_DENIED", "workload identity is not admitted", false)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

type capabilityHandler struct {
	service provider.CapabilityService
}

func (h capabilityHandler) get(writer http.ResponseWriter, request *http.Request) {
	capabilities, err := h.service.Capabilities(request.Context())
	if err != nil {
		if errors.Is(err, provider.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeProviderError(writer, http.StatusServiceUnavailable, "SANDBOX_UNAVAILABLE", "Provider capabilities are temporarily unavailable", true)
			return
		}
		writeProviderError(writer, http.StatusInternalServerError, "SANDBOX_INTERNAL_ERROR", "Provider capability discovery failed", false)
		return
	}
	document, err := projectCapabilities(capabilities)
	if err != nil {
		writeProviderError(writer, http.StatusInternalServerError, "SANDBOX_INTERNAL_ERROR", "Provider capability discovery failed", false)
		return
	}
	writeJSON(writer, http.StatusOK, document)
}

func projectCapabilities(source provider.Capabilities) (providerv1.Capabilities, error) {
	if err := source.Validate(); err != nil {
		return providerv1.Capabilities{}, err
	}
	result := providerv1.Capabilities{
		ProviderRevisionID:     source.ProviderRevisionID,
		APIVersion:             providerv1.APIVersion(source.APIVersion),
		Capabilities:           make([]providerv1.Capability, len(source.Capabilities)),
		RuntimeProfiles:        make([]providerv1.RuntimeProfile, len(source.RuntimeProfiles)),
		SnapshotRestoreProfile: make([]providerv1.SnapshotRestoreProfile, len(source.SnapshotRestoreProfile)),
		Limits: providerv1.ProviderLimits{
			MaxCPUMillis:             source.Limits.MaxCPUMillis,
			MaxMemoryBytes:           source.Limits.MaxMemoryBytes,
			MaxEphemeralStorageBytes: source.Limits.MaxEphemeralStorageBytes,
			MaxWorkspaceBytes:        cloneInt64(source.Limits.MaxWorkspaceBytes),
			MaxGPUCount:              cloneInt64(source.Limits.MaxGPUCount),
			MaxLeaseSeconds:          source.Limits.MaxLeaseSeconds,
			MaxExecSeconds:           source.Limits.MaxExecSeconds,
		},
	}
	for i, capability := range source.Capabilities {
		result.Capabilities[i] = providerv1.Capability{
			ID:       providerv1.CapabilityID(capability.ID),
			Versions: append([]string(nil), capability.Versions...),
			Profiles: append([]string(nil), capability.Profiles...),
		}
	}
	for i, profile := range source.RuntimeProfiles {
		architectures := make([]providerv1.Architecture, len(profile.Architectures))
		for j, architecture := range profile.Architectures {
			architectures[j] = providerv1.Architecture(architecture)
		}
		result.RuntimeProfiles[i] = providerv1.RuntimeProfile{
			ID:               profile.ID,
			IsolationClass:   providerv1.IsolationClass(profile.IsolationClass),
			RuntimeClassName: profile.RuntimeClassName,
			Architecture:     architectures,
		}
	}
	for i, profile := range source.SnapshotRestoreProfile {
		result.SnapshotRestoreProfile[i] = providerv1.SnapshotRestoreProfile{
			ProfileID:    profile.ProfileID,
			Level:        providerv1.SnapshotLevel(profile.Level),
			SuiteID:      providerv1.SandboxSuiteID(profile.SuiteID),
			SuiteVersion: profile.SuiteVersion,
			SuiteDigest:  providerv1.SHA256Digest(profile.SuiteDigest),
		}
	}
	return result, nil
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func writeProviderError(writer http.ResponseWriter, status int, code, message string, retryable bool) {
	writeJSON(writer, status, providerv1.StandardError{
		Code: code, Message: message, Retryable: retryable, TraceID: newTraceID(),
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	document, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		document = []byte(`{"code":"SANDBOX_INTERNAL_ERROR","message":"Provider response encoding failed","retryable":false,"trace_id":"trace-unavailable"}`)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(document)
}

func newTraceID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "trace-unavailable"
	}
	return "trace-" + hex.EncodeToString(bytes[:])
}
