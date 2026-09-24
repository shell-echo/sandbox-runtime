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
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/rolematerials"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/tlsmaterial"
)

const (
	guestAuthorityVersion   = 1
	guestAuthorityVersionV2 = 2
	guestAuthorityVersionV3 = 3
	maxGuestAuthoritySize   = 64 << 10
	maxGuestKeySize         = ed25519.PrivateKeySize
)

// GuestCredentialAuthority is the versioned, role-specific identity input for
// an outbound Guest. The private key remains in a separate mode-0600 file.
type GuestCredentialAuthority struct {
	Version             int    `json:"version"`
	Role                string `json:"role"`
	GuestID             string `json:"guest_id"`
	BindingGeneration   int64  `json:"binding_generation"`
	PrivateKeyFile      string `json:"private_key_file"`
	PrivateKeyBindingID string `json:"private_key_binding_id"`
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
	Registry   *secretref.Registry
	Peer       *phase6tls.PeerCRLGuard
}

// LoadGuestAuthority reads and validates the three role-owned authority files
// referenced by the process configuration. Unknown JSON fields, wrong roles,
// path aliasing, broad permissions, and malformed keys are rejected.
func LoadGuestAuthority(cfg *config.DataPlaneProcessConfig) (GuestAuthority, error) {
	return loadGuestAuthority(context.Background(), cfg)
}

func loadGuestAuthority(ctx context.Context, cfg *config.DataPlaneProcessConfig) (GuestAuthority, error) {
	if ctx == nil || cfg == nil || cfg.Role != config.DataPlaneGuest || !cfg.Enabled {
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
	productionV3 := cfg.SchemaVersion == config.DataPlaneProductionSchemaV3
	production := cfg.SchemaVersion == config.DataPlaneProductionSchemaV2 || productionV3
	expectedVersion := guestAuthorityVersion
	if productionV3 {
		expectedVersion = guestAuthorityVersionV3
	} else if production {
		expectedVersion = guestAuthorityVersionV2
	}
	if credential.Version != expectedVersion || credential.Role != string(config.DataPlaneGuest) || credential.GuestID == "" || credential.BindingGeneration < 1 {
		return GuestAuthority{}, errors.New("invalid Guest credential authority")
	}
	if production {
		if credential.PrivateKeyFile != "" || credential.PrivateKeyBindingID == "" {
			return GuestAuthority{}, errors.New("invalid Guest credential authority")
		}
	} else if !filepath.IsAbs(credential.PrivateKeyFile) || credential.PrivateKeyBindingID != "" {
		return GuestAuthority{}, errors.New("invalid Guest credential authority")
	}
	dependencyVersion, policyVersion := guestAuthorityVersion, guestAuthorityVersion
	if productionV3 {
		dependencyVersion, policyVersion = guestAuthorityVersionV3, guestAuthorityVersionV3
	}
	if dependency.Version != dependencyVersion || dependency.Role != string(config.DataPlaneGuest) || !filepath.IsAbs(dependency.WorkspaceRoot) || !filepath.IsAbs(dependency.StateRoot) || filepath.Clean(dependency.WorkspaceRoot) == filepath.Clean(dependency.StateRoot) {
		return GuestAuthority{}, errors.New("invalid Guest dependency authority")
	}
	if policy.Version != policyVersion || policy.Role != string(config.DataPlaneGuest) || policy.ReconnectBackoffMillis < 10 || policy.ReconnectBackoffMillis > 30_000 {
		return GuestAuthority{}, errors.New("invalid Guest policy authority")
	}
	var registry *secretref.Registry
	var privateKey []byte
	var client *http.Client
	var peer *phase6tls.PeerCRLGuard
	var err error
	if production {
		purposes := []secretref.Purpose{secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey,
			secretref.PurposeCABundle, secretref.PurposeGuestSigningKey}
		if productionV3 {
			purposes = []secretref.Purpose{secretref.PurposeGuestSigningKey}
		}
		registry, err = rolematerials.New(cfg.Materials, secretref.RoleGuest, purposes, true, time.Now)
		if err != nil {
			return GuestAuthority{}, errors.New("construct Guest material registry")
		}
		closeRegistry := true
		defer func() {
			if closeRegistry {
				registry.Close()
			}
		}()
		bindings, decodeErr := cfg.Materials.DecodeBindings(secretref.RoleGuest)
		expectedBindings := 4
		if productionV3 {
			expectedBindings = 1
		}
		if decodeErr != nil || len(bindings) != expectedBindings {
			return GuestAuthority{}, errors.New("Guest material registry has unexpected authority")
		}
		material, resolveErr := registry.Resolve(ctx, credential.PrivateKeyBindingID, secretref.PurposeGuestSigningKey, secretref.SystemTenant)
		if resolveErr != nil {
			material.Destroy()
			return GuestAuthority{}, errors.New("Guest signing key material is unavailable")
		}
		privateKey = append([]byte(nil), material.Bytes...)
		material.Destroy()
		if len(privateKey) != ed25519.PrivateKeySize {
			clear(privateKey)
			return GuestAuthority{}, errors.New("invalid Guest private key")
		}
		if productionV3 {
			profile, profileErr := phase6security.VerifyFile(cfg.TLS.SecurityProfilePath)
			if profileErr != nil || profile.ProfileDigest != cfg.TLS.SecurityProfileDigest {
				clear(privateKey)
				return GuestAuthority{}, errors.New("Guest security profile mismatch")
			}
			peerRole, roleErr := phase6security.VerifyPeerCRLRoleFile(cfg.TLS.PeerCRLRoleFile, profile,
				cfg.TLS.PeerCRLSourceMappingDigest, cfg.TLS.PeerCRLRoleDigest)
			if roleErr != nil {
				clear(privateKey)
				return GuestAuthority{}, errors.New("Guest peer CRL role binding mismatch")
			}
			transport, guard, tlsErr := phase6tls.GuestProductClient(profile,
				phase6tls.GuestProductClientAuthority{Origin: cfg.OutboundURL, PeerCRLRole: peerRole,
					AgentSocket: cfg.TLS.AgentSocket, AgentUID: cfg.TLS.AgentUID, AgentGID: cfg.TLS.AgentGID,
					OperationTimeout: time.Duration(cfg.TLS.OperationTimeoutMillis) * time.Millisecond})
			if tlsErr != nil {
				clear(privateKey)
				return GuestAuthority{}, errors.New("Guest Product live TLS unavailable")
			}
			peer = guard
			client = &http.Client{Transport: transport, Timeout: time.Duration(cfg.Drain.DependencyTimeouts) * time.Second}
		} else {
			parsed, _ := url.Parse(cfg.OutboundURL)
			clientTLS, tlsErr := tlsmaterial.ResolveClient(ctx, registry,
				cfg.TLS.ClientCABundleBindingID, cfg.TLS.ClientCertificateBindingID, cfg.TLS.ClientPrivateKeyBindingID,
				parsed.Hostname(), time.Now)
			if tlsErr != nil {
				clear(privateKey)
				return GuestAuthority{}, errors.New("load Guest TLS client material")
			}
			client = &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: time.Duration(cfg.Drain.DependencyTimeouts) * time.Second}
		}
		closeRegistry = false
	} else {
		privateKey, err = secretfile.Read(credential.PrivateKeyFile, maxGuestKeySize)
		if err != nil || len(privateKey) != ed25519.PrivateKeySize {
			clear(privateKey)
			return GuestAuthority{}, errors.New("invalid Guest private key")
		}
		client, err = guestHTTPClient(cfg)
		if err != nil {
			clear(privateKey)
			return GuestAuthority{}, err
		}
	}
	key := ed25519.PrivateKey(append([]byte(nil), privateKey...))
	clear(privateKey)
	return GuestAuthority{Credential: credential, Dependency: dependency, Policy: policy, PrivateKey: key,
		HTTPClient: client, Registry: registry, Peer: peer}, nil
}

// NewGuestApplicationGraph constructs the actual outbound Guest application
// from the typed authority contract. It returns no inbound handler and never
// invents Product identity or capabilities.
func NewGuestApplicationGraph(ctx context.Context, cfg *config.DataPlaneProcessConfig) (ApplicationGraph, error) {
	if ctx == nil {
		return ApplicationGraph{}, errors.New("Guest construction context is required")
	}
	authority, err := loadGuestAuthority(ctx, cfg)
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
		if authority.Peer != nil {
			authority.Peer.Close()
		}
		if authority.Registry != nil {
			authority.Registry.Close()
		}
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
		if authority.Peer != nil {
			authority.Peer.Close()
		}
		if authority.Registry != nil {
			authority.Registry.Close()
		}
		return ApplicationGraph{}, fmt.Errorf("construct Guest agent: %w", err)
	}
	// The development service owns no goroutine or external handle. Agent.Run
	// owns the only independent lifecycle and is stopped by graph Shutdown.
	return ApplicationGraph{
		Ready: func(checkContext context.Context) error {
			if authority.Registry != nil {
				if err := verifyGuestMaterials(checkContext, authority.Registry, cfg, authority.Credential.PrivateKeyBindingID); err != nil {
					return err
				}
			}
			if authority.Peer != nil {
				if err := authority.Peer.Poll(checkContext); err != nil || !authority.Peer.Ready() {
					return errors.New("Guest Product peer authority unavailable")
				}
			}
			return agent.Ready(checkContext)
		},
		Start: func(startContext context.Context) error {
			if authority.Peer != nil {
				stop, err := authority.Peer.StartPolling(startContext)
				if err != nil {
					return err
				}
				defer stop()
			}
			return agent.Run(startContext)
		},
		Shutdown: func(context.Context) error {
			if authority.Peer != nil {
				authority.Peer.Close()
			}
			if authority.Registry != nil {
				authority.Registry.Close()
			}
			return nil
		},
	}, nil
}

func verifyGuestMaterials(ctx context.Context, registry *secretref.Registry, cfg *config.DataPlaneProcessConfig, signingKeyID string) error {
	if cfg.SchemaVersion == config.DataPlaneProductionSchemaV3 {
		material, err := registry.Resolve(ctx, signingKeyID, secretref.PurposeGuestSigningKey, secretref.SystemTenant)
		material.Destroy()
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return errors.New("Guest signing-key dependency unavailable")
		}
		return nil
	}
	checks := []struct {
		id      string
		purpose secretref.Purpose
	}{
		{cfg.TLS.ClientCABundleBindingID, secretref.PurposeCABundle},
		{cfg.TLS.ClientCertificateBindingID, secretref.PurposeTLSCertificate},
		{cfg.TLS.ClientPrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
		{signingKeyID, secretref.PurposeGuestSigningKey},
	}
	for _, check := range checks {
		material, err := registry.Resolve(ctx, check.id, check.purpose, secretref.SystemTenant)
		material.Destroy()
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return errors.New("Guest material dependency is unavailable")
		}
	}
	return nil
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
