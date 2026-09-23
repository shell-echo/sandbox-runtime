// Command desktop-executor-backend is the operator-owned private relay
// between a Desktop executor role and the pinned in-sandbox Unix broker.
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
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

type authority struct {
	Version                    int    `json:"version"`
	Role                       string `json:"role"`
	ListenAddress              string `json:"listen_address"`
	BrokerSocketPath           string `json:"broker_socket_path"`
	ExecutorIdentity           string `json:"executor_identity"`
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

var socketPattern = regexp.MustCompile(`^desktop-broker-[0-9a-f]{32}\.sock$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "desktop-executor-backend failed")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 2 || arguments[0] != "serve" || !filepath.IsAbs(arguments[1]) {
		return errors.New("usage: desktop-executor-backend serve /absolute/path/to/authority.json")
	}
	document, err := secretfile.Read(arguments[1], 64<<10)
	if err != nil {
		return errors.New("read Desktop executor backend authority")
	}
	defer clear(document)
	value, err := parseAuthority(document)
	if err != nil {
		return err
	}
	if err := validateAuthority(value); err != nil {
		return err
	}
	profile, err := phase6security.VerifyFile(value.SecurityProfilePath)
	if err != nil || profile.ProfileDigest != value.SecurityProfileDigest {
		return errors.New("Desktop executor security profile mismatch")
	}
	roleDocument, err := phase6security.VerifyPeerCRLRoleFile(value.PeerCRLRoleFile, profile,
		value.PeerCRLSourceMappingDigest, value.PeerCRLRoleDigest)
	if err != nil {
		return errors.New("Desktop executor peer CRL role binding mismatch")
	}
	tlsEndpoint, err := executorbackend.ProductionServerTLS(profile, executorbackend.ProductionTLSAuthority{
		DeploymentName: "desktop-executor-backend", ListenAddress: value.ListenAddress,
		PeerCRLRole: roleDocument,
		AgentSocket: value.TLSAgentSocket, AgentUID: value.TLSAgentUID, AgentGID: value.TLSAgentGID,
		OperationTimeout: time.Duration(value.OperationTimeoutMillis) * time.Millisecond})
	if err != nil {
		return err
	}
	backend, err := executorbackend.NewDesktop(executorbackend.DesktopConfig{
		Role: value.Role, ListenAddress: value.ListenAddress, BrokerSocketPath: value.BrokerSocketPath, ExecutorIdentity: value.ExecutorIdentity,
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
	if err := executorprotocol.Decode(document, &value); err != nil || value.Version != 2 || value.Role != executorprotocol.RoleDesktop {
		return authority{}, errors.New("invalid Desktop executor backend authority")
	}
	return value, nil
}

func validateAuthority(value authority) error {
	host, _, err := net.SplitHostPort(value.ListenAddress)
	if err != nil || net.ParseIP(host) == nil || !filepath.IsAbs(value.BrokerSocketPath) || filepath.Clean(value.BrokerSocketPath) != value.BrokerSocketPath || !socketPattern.MatchString(filepath.Base(value.BrokerSocketPath)) || value.ExecutorIdentity == "" {
		return errors.New("Desktop executor backend listener or broker socket is invalid")
	}
	for _, path := range []string{value.SecurityProfilePath, value.PeerCRLRoleFile, value.TLSAgentSocket} {
		if !filepath.IsAbs(path) {
			return errors.New("Desktop executor backend TLS paths must be absolute")
		}
	}
	if !fullDigest(value.SecurityProfileDigest) || !fullDigest(value.PeerCRLRoleDigest) ||
		!fullDigest(value.PeerCRLSourceMappingDigest) || value.PeerCRLRoleFile == value.SecurityProfilePath ||
		value.PeerCRLRoleFile == value.TLSAgentSocket || value.TLSAgentUID == 0 || value.TLSAgentGID == 0 ||
		value.MaxSessions < 1 || value.MaxSessions > 256 || value.OperationTimeoutMillis < 1000 || value.OperationTimeoutMillis > 30_000 {
		return errors.New("Desktop executor backend limits or identities are invalid")
	}
	return nil
}

var fullDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func fullDigest(value string) bool { return fullDigestPattern.MatchString(value) }
