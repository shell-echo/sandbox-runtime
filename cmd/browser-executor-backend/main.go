// Command browser-executor-backend is the operator-owned private relay between
// a Browser executor role and the Provider-owned typed allocation mux.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/executorbackend"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

type authority struct {
	Version                    int    `json:"version"`
	Role                       string `json:"role"`
	ListenAddress              string `json:"listen_address"`
	UpstreamURL                string `json:"upstream_url"`
	MuxSocketPath              string `json:"mux_socket_path"`
	MuxDirectoryMode           uint32 `json:"mux_directory_mode"`
	MuxSocketMode              uint32 `json:"mux_socket_mode"`
	MuxOwnerUID                uint32 `json:"mux_owner_uid"`
	MuxDirectoryGID            uint32 `json:"mux_directory_gid"`
	SecurityProfilePath        string `json:"security_profile_path"`
	SecurityProfileDigest      string `json:"security_profile_digest"`
	PeerCRLRoleFile            string `json:"peer_crl_role_file"`
	PeerCRLRoleDigest          string `json:"peer_crl_role_digest"`
	PeerCRLSourceMappingDigest string `json:"peer_crl_source_mapping_digest"`
	TLSAgentSocket             string `json:"tls_agent_socket"`
	TLSAgentUID                uint32 `json:"tls_agent_uid"`
	TLSAgentGID                uint32 `json:"tls_agent_gid"`
	MaxSessions                int    `json:"max_sessions"`
	OperationTimeoutMillis     int    `json:"operation_timeout_millis"`
}

var fullDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var muxSocketPattern = regexp.MustCompile(`^browser-mux-[0-9a-f]{32}\.sock$`)

func fullDigest(value string) bool { return fullDigestPattern.MatchString(value) }

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "browser-executor-backend failed")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 2 || arguments[0] != "serve" || !filepath.IsAbs(arguments[1]) {
		return errors.New("usage: browser-executor-backend serve /absolute/path/to/authority.json")
	}
	document, err := secretfile.Read(arguments[1], 64<<10)
	if err != nil {
		return errors.New("read Browser executor backend authority")
	}
	defer clear(document)
	value, err := parseAuthority(document)
	if err != nil {
		return err
	}
	if err := validateAuthority(value); err != nil {
		return err
	}
	profile, err := phase6security.VerifySlice6ProfileForDeployment(value.SecurityProfilePath, "browser-executor-backend")
	if err != nil || profile.ProfileDigest != value.SecurityProfileDigest ||
		phase6security.VerifySlice6PrivateConfigPath(profile, "browser-executor-backend",
			phase6security.Slice6StartupAuthorityFile, arguments[1]) != nil ||
		phase6security.VerifySlice6PrivateConfigPath(profile, "browser-executor-backend",
			phase6security.Slice6PeerCRLRoleFile, value.PeerCRLRoleFile) != nil {
		return errors.New("Browser executor security profile mismatch")
	}
	if err := validateMuxProfile(profile, value); err != nil {
		return err
	}
	roleDocument, err := phase6security.VerifyPeerCRLRoleFile(value.PeerCRLRoleFile, profile,
		value.PeerCRLSourceMappingDigest, value.PeerCRLRoleDigest)
	if err != nil {
		return errors.New("Browser executor peer CRL role binding mismatch")
	}
	tlsEndpoint, err := executorbackend.ProductionServerTLS(profile, executorbackend.ProductionTLSAuthority{
		DeploymentName: "browser-executor-backend", ListenAddress: value.ListenAddress,
		PeerCRLRole: roleDocument,
		AgentSocket: value.TLSAgentSocket, AgentUID: value.TLSAgentUID, AgentGID: value.TLSAgentGID,
		OperationTimeout: time.Duration(value.OperationTimeoutMillis) * time.Millisecond})
	if err != nil {
		return err
	}
	backend, err := executorbackend.New(executorbackend.Config{
		Role: value.Role, ListenAddress: value.ListenAddress, MuxSocketPath: value.MuxSocketPath,
		MuxLayout: restrictedunix.Layout{DirectoryMode: os.FileMode(value.MuxDirectoryMode), SocketMode: os.FileMode(value.MuxSocketMode),
			OwnerUID: value.MuxOwnerUID, DirectoryGID: value.MuxDirectoryGID},
		RemoteTLSConfig: tlsEndpoint.Config, PeerRevocationMonitor: tlsEndpoint.Guard,
		SignerProbe: tlsEndpoint.SignerProbe, ConnectionMaxAge: tlsEndpoint.ConnectionMaxAge,
		MaxSessions: value.MaxSessions, OperationTimeout: time.Duration(value.OperationTimeoutMillis) * time.Millisecond,
	})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return backend.Serve(ctx)
}

func parseAuthority(document []byte) (authority, error) {
	var value authority
	if err := executorprotocol.Decode(document, &value); err != nil || value.Version != 3 || value.Role != executorprotocol.RoleBrowser {
		return authority{}, errors.New("invalid Browser executor backend authority")
	}
	return value, nil
}

func validateAuthority(value authority) error {
	if value.ListenAddress == "" {
		return errors.New("Browser executor backend listen address is required")
	}
	host, _, err := net.SplitHostPort(value.ListenAddress)
	if err != nil || net.ParseIP(host) == nil {
		return errors.New("Browser executor backend listen address must use an explicit IP")
	}
	if value.UpstreamURL != "" || !filepath.IsAbs(value.MuxSocketPath) || filepath.Clean(value.MuxSocketPath) != value.MuxSocketPath ||
		filepath.Dir(value.MuxSocketPath) != phase6security.BrowserMuxSocketDirectory ||
		!muxSocketPattern.MatchString(filepath.Base(value.MuxSocketPath)) ||
		value.MuxOwnerUID == 0 || value.MuxDirectoryGID == 0 ||
		!((value.MuxDirectoryMode == 0o700 && value.MuxSocketMode == 0o600) ||
			(value.MuxDirectoryMode == 0o710 && value.MuxSocketMode == 0o666)) {
		return errors.New("Browser executor backend requires a restricted Provider mux, not a static CDP URL")
	}
	for _, path := range []string{value.SecurityProfilePath, value.PeerCRLRoleFile, value.TLSAgentSocket} {
		if !filepath.IsAbs(path) {
			return errors.New("Browser executor backend TLS paths must be absolute")
		}
	}
	if !fullDigest(value.SecurityProfileDigest) || !fullDigest(value.PeerCRLRoleDigest) ||
		!fullDigest(value.PeerCRLSourceMappingDigest) || value.PeerCRLRoleFile == value.SecurityProfilePath ||
		value.PeerCRLRoleFile == value.TLSAgentSocket || value.TLSAgentUID == 0 || value.TLSAgentGID == 0 ||
		value.MaxSessions < 1 || value.MaxSessions > 256 || value.OperationTimeoutMillis < 1000 || value.OperationTimeoutMillis > 30_000 {
		return errors.New("Browser executor backend limits or identities are invalid")
	}
	return nil
}

func validateMuxProfile(profile phase6security.Profile, value authority) error {
	var provider, backend phase6security.Principal
	for _, principal := range profile.Principals {
		switch principal.Name {
		case "provider-browser-runtime":
			provider = principal
		case "browser-executor-backend":
			backend = principal
		}
	}
	if provider.UID == 0 || backend.UID == 0 ||
		filepath.Dir(value.MuxSocketPath) != phase6security.BrowserMuxSocketDirectory ||
		value.MuxDirectoryMode != 0o710 || value.MuxSocketMode != 0o666 ||
		value.MuxOwnerUID != provider.UID || value.MuxDirectoryGID != backend.GID {
		return errors.New("Browser executor mux ownership does not match profile")
	}
	return nil
}
