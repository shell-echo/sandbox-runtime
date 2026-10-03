package roleprocess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
	Version         int                          `json:"version"`
	Role            string                       `json:"role"`
	WorkspaceRoot   string                       `json:"workspace_root"`
	StateRoot       string                       `json:"state_root"`
	StorageIdentity string                       `json:"storage_identity,omitempty"`
	Mounts          []guestdevelopment.Mount     `json:"mounts"`
	Toolchains      []guestdevelopment.Toolchain `json:"toolchains"`
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
	if !productionV3 && dependency.StorageIdentity != "" {
		return GuestAuthority{}, errors.New("Guest storage identity requires the v3 profile")
	}
	if policy.Version != policyVersion || policy.Role != string(config.DataPlaneGuest) || policy.ReconnectBackoffMillis < 10 || policy.ReconnectBackoffMillis > 30_000 {
		return GuestAuthority{}, errors.New("invalid Guest policy authority")
	}
	var registry *secretref.Registry
	var privateKey []byte
	var client *http.Client
	var peer *phase6tls.PeerCRLGuard
	var err error
	var slice6Profile phase6security.Profile
	if productionV3 {
		slice6Profile, err = phase6security.VerifySlice6ProfileForDeployment(cfg.TLS.SecurityProfilePath, "guest-runtime")
		if err != nil || slice6Profile.ProfileDigest != cfg.TLS.SecurityProfileDigest {
			return GuestAuthority{}, errors.New("Guest security profile mismatch")
		}
		if phase6security.VerifySlice6GuestStorageMounts(slice6Profile) != nil ||
			verifyGuestV3DependencyShape(dependency) != nil || verifyGuestV3Toolchain(dependency.Toolchains[0]) != nil ||
			verifyGuestV3Directories() != nil || verifyGuestV3StorageReceipts(dependency.StorageIdentity) != nil ||
			guestdevelopment.VerifyClosedState(dependency.StateRoot) != nil {
			return GuestAuthority{}, errors.New("Guest storage or toolchain authority mismatch")
		}
		for _, input := range []struct{ filename, path string }{
			{phase6security.Slice6CredentialAuthorityFile, cfg.Authority.CredentialFile},
			{phase6security.Slice6DependencyAuthorityFile, cfg.Authority.DependencyFile},
			{phase6security.Slice6PolicyAuthorityFile, cfg.Authority.PolicyFile},
			{phase6security.Slice6PeerCRLRoleFile, cfg.TLS.PeerCRLRoleFile},
		} {
			if phase6security.VerifySlice6PrivateConfigPath(slice6Profile, "guest-runtime", input.filename, input.path) != nil {
				return GuestAuthority{}, errors.New("Guest private config path mismatch")
			}
		}
	}
	if production {
		purposes := []secretref.Purpose{secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey,
			secretref.PurposeCABundle, secretref.PurposeGuestSigningKey}
		if productionV3 {
			purposes = []secretref.Purpose{secretref.PurposeGuestSigningKey}
		}
		if productionV3 {
			registry, err = rolematerials.NewSlice6ForDeployment(cfg.Materials, "guest-runtime", slice6Profile,
				secretref.RoleGuest, purposes, true, time.Now)
		} else {
			registry, err = rolematerials.New(cfg.Materials, secretref.RoleGuest, purposes, true, time.Now)
		}
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
			peerRole, roleErr := phase6security.VerifyPeerCRLRoleFile(cfg.TLS.PeerCRLRoleFile, slice6Profile,
				cfg.TLS.PeerCRLSourceMappingDigest, cfg.TLS.PeerCRLRoleDigest)
			if roleErr != nil {
				clear(privateKey)
				return GuestAuthority{}, errors.New("Guest peer CRL role binding mismatch")
			}
			transport, guard, tlsErr := phase6tls.GuestProductClient(slice6Profile,
				phase6tls.GuestProductClientAuthority{Origin: cfg.OutboundURL, PeerCRLRole: peerRole,
					AgentSocket: cfg.TLS.AgentSocket, AgentUID: cfg.TLS.AgentUID, AgentGID: cfg.TLS.AgentGID,
					OperationTimeout: time.Duration(cfg.TLS.OperationTimeoutMillis) * time.Millisecond})
			if tlsErr != nil {
				clear(privateKey)
				return GuestAuthority{}, errors.New("Guest Product live TLS unavailable")
			}
			peer = guard
			client = &http.Client{Transport: transport, Timeout: time.Duration(cfg.Drain.DependencyTimeouts) * time.Second,
				CheckRedirect: rejectPrivateRedirect}
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

// The production Guest may not retarget its workspace/state into private
// configuration, sockets, trust anchors or a host path. The declared shell is
// the selected image's existing BusyBox executable, not a fixture digest.
func verifyGuestV3DependencyShape(dependency GuestDependencyAuthority) error {
	wantMounts := []guestdevelopment.Mount{
		{Path: phase6security.Slice6GuestInputsRoot, Mode: "ro"},
		{Path: phase6security.Slice6GuestWorkspaceRoot, Mode: "rw"},
		{Path: phase6security.Slice6GuestOutputsRoot, Mode: "rw"},
		{Path: phase6security.Slice6GuestTempRoot, Mode: "rw"},
	}
	if dependency.WorkspaceRoot != phase6security.Slice6GuestWorkspaceRoot ||
		dependency.StateRoot != phase6security.Slice6GuestStateRoot ||
		!slices.Equal(dependency.Mounts, wantMounts) || len(dependency.Toolchains) != 1 ||
		len(dependency.StorageIdentity) != 32 {
		return errors.New("Guest dependency paths do not match the security profile")
	}
	decoded, err := hex.DecodeString(dependency.StorageIdentity)
	if err != nil || hex.EncodeToString(decoded) != dependency.StorageIdentity {
		return errors.New("Guest storage identity is not canonical")
	}
	return nil
}

func verifyGuestV3Toolchain(toolchain guestdevelopment.Toolchain) error {
	if toolchain.ID != "posix-shell" || toolchain.Version != "1.37.0" ||
		toolchain.Executable != "/bin/sh" ||
		len(toolchain.Digest) != len("sha256:")+64 ||
		!strings.HasPrefix(toolchain.Digest, "sha256:") {
		return errors.New("Guest selected-image toolchain identity is invalid")
	}
	resolved, err := filepath.EvalSymlinks(toolchain.Executable)
	if err != nil || resolved != "/bin/busybox" {
		return errors.New("Guest selected-image shell link is invalid")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return errors.New("Guest selected-image shell is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return errors.New("Guest selected-image shell is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > 8<<20 || info.Mode().Perm() != 0o755 {
		return errors.New("Guest selected-image shell is not a bounded read-only executable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != toolchain.Digest {
		return errors.New("Guest selected-image shell digest mismatch")
	}
	return nil
}

func verifyGuestV3Directories() error {
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{
		{phase6security.Slice6GuestWorkspaceRoot, 0o700},
		{phase6security.Slice6GuestStateRoot, 0o700},
		{phase6security.Slice6GuestInputsRoot, 0o500},
		{phase6security.Slice6GuestOutputsRoot, 0o700},
		{phase6security.Slice6GuestTempRoot, 0o700},
	} {
		resolved, err := filepath.EvalSymlinks(entry.path)
		if err != nil || resolved != entry.path {
			return errors.New("Guest storage path was replaced")
		}
		info, err := os.Lstat(entry.path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != entry.mode {
			return errors.New("Guest storage directory mode drift")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
			return errors.New("Guest storage directory owner drift")
		}
	}
	return nil
}

func verifyGuestV3StorageReceipts(identity string) error {
	for _, entry := range []struct{ root, storageID string }{
		{phase6security.Slice6GuestWorkspaceRoot, "guest-workspace"},
		{phase6security.Slice6GuestStateRoot, "guest-state"},
		{phase6security.Slice6GuestInputsRoot, "guest-inputs"},
	} {
		name := filepath.Join(entry.root, guestdevelopment.StorageIdentityFileName)
		document, err := secretfile.Read(name, 256)
		if err != nil || phase6security.DecodeSlice6GuestStorageReceipt(document, identity, entry.storageID) != nil {
			clear(document)
			return errors.New("Guest persistent storage identity mismatch")
		}
		clear(document)
		info, err := os.Lstat(name)
		if err != nil {
			return errors.New("Guest persistent storage receipt unavailable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
			return errors.New("Guest persistent storage receipt owner mismatch")
		}
	}
	entries, err := os.ReadDir(phase6security.Slice6GuestInputsRoot)
	if err != nil || len(entries) != 2 || entries[0].Name() != guestdevelopment.StorageIdentityFileName ||
		entries[1].Name() != phase6security.Slice6GuestInputsManifestFileName {
		return errors.New("Guest read-only input inventory mismatch")
	}
	manifest := filepath.Join(phase6security.Slice6GuestInputsRoot, phase6security.Slice6GuestInputsManifestFileName)
	document, err := secretfile.Read(manifest, 1<<20)
	if err != nil || string(document) != phase6security.Slice6GuestInputsManifest {
		clear(document)
		return errors.New("Guest read-only input manifest mismatch")
	}
	clear(document)
	return nil
}

// NewGuestApplicationGraph constructs the actual outbound Guest application
// from the typed authority contract. It returns no inbound handler and never
// invents Product identity or capabilities.
func NewGuestApplicationGraph(ctx context.Context, cfg *config.DataPlaneProcessConfig) (ApplicationGraph, error) {
	return NewGuestApplicationGraphWithObservation(ctx, cfg, nil)
}

// NewGuestApplicationGraphWithObservation is the opt-in local-candidate
// evidence variant. The sink is pre-admitted by the command and must enqueue
// without I/O; it does not participate in Guest authority decisions.
func NewGuestApplicationGraphWithObservation(ctx context.Context, cfg *config.DataPlaneProcessConfig,
	observe guestagent.ObservationSink) (ApplicationGraph, error) {
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
		Observation:      observe,
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
