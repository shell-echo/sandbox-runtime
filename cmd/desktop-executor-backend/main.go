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
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

type authority struct {
	Version                 int      `json:"version"`
	Role                    string   `json:"role"`
	ListenAddress           string   `json:"listen_address"`
	BrokerSocketPath        string   `json:"broker_socket_path"`
	ExecutorIdentity        string   `json:"executor_identity"`
	ServerCertificateFile   string   `json:"server_certificate_file"`
	ServerPrivateKeyFile    string   `json:"server_private_key_file"`
	ClientCABundleFile      string   `json:"client_ca_bundle_file"`
	AllowedClientIdentities []string `json:"allowed_client_identities"`
	MaxSessions             int      `json:"max_sessions"`
	OperationTimeoutMillis  int      `json:"operation_timeout_millis"`
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
	var value authority
	if err := executorprotocol.Decode(document, &value); err != nil || value.Version != 1 || value.Role != executorprotocol.RoleDesktop {
		return errors.New("invalid Desktop executor backend authority")
	}
	if err := validateAuthority(value); err != nil {
		return err
	}
	backend, err := executorbackend.NewDesktop(executorbackend.DesktopConfig{
		Role: value.Role, ListenAddress: value.ListenAddress, BrokerSocketPath: value.BrokerSocketPath, ExecutorIdentity: value.ExecutorIdentity,
		ServerCertificateFile: value.ServerCertificateFile, ServerPrivateKeyFile: value.ServerPrivateKeyFile,
		ClientCABundleFile: value.ClientCABundleFile, AllowedClientIdentities: value.AllowedClientIdentities,
		MaxSessions: value.MaxSessions, OperationTimeout: time.Duration(value.OperationTimeoutMillis) * time.Millisecond,
	})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return backend.Serve(ctx)
}

func validateAuthority(value authority) error {
	host, _, err := net.SplitHostPort(value.ListenAddress)
	if err != nil || net.ParseIP(host) == nil || !filepath.IsAbs(value.BrokerSocketPath) || filepath.Clean(value.BrokerSocketPath) != value.BrokerSocketPath || !socketPattern.MatchString(filepath.Base(value.BrokerSocketPath)) || value.ExecutorIdentity == "" {
		return errors.New("Desktop executor backend listener or broker socket is invalid")
	}
	for _, path := range []string{value.ServerCertificateFile, value.ServerPrivateKeyFile, value.ClientCABundleFile} {
		if !filepath.IsAbs(path) {
			return errors.New("Desktop executor backend TLS paths must be absolute")
		}
	}
	if len(value.AllowedClientIdentities) == 0 || len(value.AllowedClientIdentities) > 32 || value.MaxSessions < 1 || value.MaxSessions > 256 || value.OperationTimeoutMillis < 100 || value.OperationTimeoutMillis > 30_000 {
		return errors.New("Desktop executor backend limits or identities are invalid")
	}
	return nil
}
