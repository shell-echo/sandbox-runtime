package roleprocess

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
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const (
	guestAuthorityVersion = 1
	maxGuestAuthoritySize = 64 << 10
	maxGuestKeySize       = ed25519.PrivateKeySize
)

// GuestCredentialAuthority is the versioned, role-specific identity input for
// an outbound Guest. The private key remains in a separate mode-0600 file.
type GuestCredentialAuthority struct {
	Version           int    `json:"version"`
	Role              string `json:"role"`
	GuestID           string `json:"guest_id"`
	BindingGeneration int64  `json:"binding_generation"`
	PrivateKeyFile    string `json:"private_key_file"`
}

// GuestDependencyAuthority contains only bounded local Guest runtime inputs.
// Product owns the binding and capability truth; the Guest receives the
// resulting identity and handler policy through this explicit document.
type GuestDependencyAuthority struct {
	Version       int                          `json:"version"`
	Role          string                       `json:"role"`
	WorkspaceRoot string                       `json:"workspace_root"`
	StateRoot     string                       `json:"state_root"`
	Mounts        []guestdevelopment.Mount     `json:"mounts"`
	Toolchains    []guestdevelopment.Toolchain `json:"toolchains"`
}

// GuestPolicyAuthority freezes reconnect behavior at startup. There is no
// allow-all capability switch: handlers are exactly those created by the
// validated dependency document.
type GuestPolicyAuthority struct {
	Version                int    `json:"version"`
	Role                   string `json:"role"`
	ReconnectBackoffMillis int    `json:"reconnect_backoff_millis"`
}

// GuestAuthority is the fully validated, private construction input for one
// outbound Guest application graph.
type GuestAuthority struct {
	Credential GuestCredentialAuthority
	Dependency GuestDependencyAuthority
	Policy     GuestPolicyAuthority
	PrivateKey ed25519.PrivateKey
	HTTPClient *http.Client
}

// LoadGuestAuthority reads and validates the three role-owned authority files
// referenced by the process configuration. Unknown JSON fields, wrong roles,
// path aliasing, broad permissions, and malformed keys are rejected.
func LoadGuestAuthority(cfg *config.DataPlaneProcessConfig) (GuestAuthority, error) {
	if cfg == nil || cfg.Role != config.DataPlaneGuest || !cfg.Enabled {
		return GuestAuthority{}, errors.New("enabled Guest configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return GuestAuthority{}, err
	}
	var credential GuestCredentialAuthority
	if err := readAuthority(cfg.Authority.CredentialFile, &credential); err != nil {
		return GuestAuthority{}, fmt.Errorf("load Guest credential authority: %w", err)
	}
	var dependency GuestDependencyAuthority
	if err := readAuthority(cfg.Authority.DependencyFile, &dependency); err != nil {
		return GuestAuthority{}, fmt.Errorf("load Guest dependency authority: %w", err)
	}
	var policy GuestPolicyAuthority
	if err := readAuthority(cfg.Authority.PolicyFile, &policy); err != nil {
		return GuestAuthority{}, fmt.Errorf("load Guest policy authority: %w", err)
	}
	if credential.Version != guestAuthorityVersion || credential.Role != string(config.DataPlaneGuest) || credential.GuestID == "" || credential.BindingGeneration < 1 || !filepath.IsAbs(credential.PrivateKeyFile) {
		return GuestAuthority{}, errors.New("invalid Guest credential authority")
	}
	if dependency.Version != guestAuthorityVersion || dependency.Role != string(config.DataPlaneGuest) || !filepath.IsAbs(dependency.WorkspaceRoot) || !filepath.IsAbs(dependency.StateRoot) || filepath.Clean(dependency.WorkspaceRoot) == filepath.Clean(dependency.StateRoot) {
		return GuestAuthority{}, errors.New("invalid Guest dependency authority")
	}
	if policy.Version != guestAuthorityVersion || policy.Role != string(config.DataPlaneGuest) || policy.ReconnectBackoffMillis < 10 || policy.ReconnectBackoffMillis > 30_000 {
		return GuestAuthority{}, errors.New("invalid Guest policy authority")
	}
	privateKey, err := secretfile.Read(credential.PrivateKeyFile, maxGuestKeySize)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		clear(privateKey)
		return GuestAuthority{}, errors.New("invalid Guest private key")
	}
	key := ed25519.PrivateKey(append([]byte(nil), privateKey...))
	clear(privateKey)
	client, err := guestHTTPClient(cfg)
	if err != nil {
		clear(key)
		return GuestAuthority{}, err
	}
	return GuestAuthority{Credential: credential, Dependency: dependency, Policy: policy, PrivateKey: key, HTTPClient: client}, nil
}

// NewGuestApplicationGraph constructs the actual outbound Guest application
// from the typed authority contract. It returns no inbound handler and never
// invents Product identity or capabilities.
func NewGuestApplicationGraph(ctx context.Context, cfg *config.DataPlaneProcessConfig) (ApplicationGraph, error) {
	if ctx == nil {
		return ApplicationGraph{}, errors.New("Guest construction context is required")
	}
	authority, err := LoadGuestAuthority(cfg)
	if err != nil {
		return ApplicationGraph{}, err
	}
	service, err := guestdevelopment.New(guestdevelopment.Options{
		WorkspaceRoot: authority.Dependency.WorkspaceRoot,
		StateRoot:     authority.Dependency.StateRoot,
		Mounts:        authority.Dependency.Mounts,
		Toolchains:    authority.Dependency.Toolchains,
	})
	if err != nil {
		clear(authority.PrivateKey)
		return ApplicationGraph{}, fmt.Errorf("construct Guest development service: %w", err)
	}
	agent, err := guestagent.NewAgent(guestagent.AgentOptions{
		URL: cfg.OutboundURL, GuestID: authority.Credential.GuestID,
		BindingGeneration: authority.Credential.BindingGeneration,
		PrivateKey:        authority.PrivateKey, Handlers: service.Handlers(),
		ReconnectBackoff: time.Duration(authority.Policy.ReconnectBackoffMillis) * time.Millisecond,
		HTTPClient:       authority.HTTPClient,
	})
	clear(authority.PrivateKey)
	if err != nil {
		return ApplicationGraph{}, fmt.Errorf("construct Guest agent: %w", err)
	}
	// The development service owns no goroutine or external handle. Agent.Run
	// owns the only independent lifecycle and is stopped by graph Shutdown.
	return ApplicationGraph{
		Ready:    func(checkContext context.Context) error { return agent.Ready(checkContext) },
		Start:    func(startContext context.Context) error { return agent.Run(startContext) },
		Shutdown: func(context.Context) error { return nil },
	}, nil
}

func readAuthority(path string, value any) error {
	document, err := secretfile.Read(path, maxGuestAuthoritySize)
	if err != nil {
		return err
	}
	defer clear(document)
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("authority document is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("authority document contains trailing data")
	}
	return nil
}

func guestHTTPClient(cfg *config.DataPlaneProcessConfig) (*http.Client, error) {
	if cfg == nil || cfg.TLS.ClientCABundleFile == "" || cfg.TLS.ClientCertificateFile == "" || cfg.TLS.ClientPrivateKeyFile == "" {
		return nil, errors.New("Guest TLS client identity is required")
	}
	caDocument, err := secretfile.Read(cfg.TLS.ClientCABundleFile, 256<<10)
	if err != nil {
		return nil, errors.New("load Guest TLS trust bundle")
	}
	defer clear(caDocument)
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(caDocument)
	certificates := 0
	for len(remaining) > 0 {
		block, rest := pemDecode(remaining)
		if block == nil {
			return nil, errors.New("Guest TLS trust bundle is invalid")
		}
		certificate, parseErr := x509.ParseCertificate(block)
		if parseErr != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("Guest TLS trust bundle contains an invalid CA")
		}
		pool.AddCert(certificate)
		certificates++
		remaining = bytes.TrimSpace(rest)
	}
	if certificates == 0 {
		return nil, errors.New("Guest TLS trust bundle is empty")
	}
	certificatePEM, err := secretfile.Read(cfg.TLS.ClientCertificateFile, 64<<10)
	if err != nil {
		return nil, errors.New("load Guest TLS client certificate")
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := secretfile.Read(cfg.TLS.ClientPrivateKeyFile, 64<<10)
	if err != nil {
		return nil, errors.New("load Guest TLS client key")
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("load Guest TLS client identity")
	}
	parsed, err := url.Parse(cfg.OutboundURL)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("Guest outbound URL is invalid")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}, ServerName: parsed.Hostname()}}, Timeout: time.Duration(cfg.Drain.DependencyTimeouts) * time.Second}, nil
}

// pemDecode keeps the parser local to this package so the authority loader
// accepts only certificate PEM blocks, never arbitrary key material.
func pemDecode(document []byte) ([]byte, []byte) {
	block, rest := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, nil
	}
	return block.Bytes, rest
}
