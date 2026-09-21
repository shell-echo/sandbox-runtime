// Command browser-executor-backend is the operator-owned private relay between
// a Browser executor role and one pinned Chromium CDP endpoint.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
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
	UpstreamURL             string   `json:"upstream_url"`
	ServerCertificateFile   string   `json:"server_certificate_file"`
	ServerPrivateKeyFile    string   `json:"server_private_key_file"`
	ClientCABundleFile      string   `json:"client_ca_bundle_file"`
	AllowedClientIdentities []string `json:"allowed_client_identities"`
	MaxSessions             int      `json:"max_sessions"`
	OperationTimeoutMillis  int      `json:"operation_timeout_millis"`
}

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
	var value authority
	if err := executorprotocol.Decode(document, &value); err != nil || value.Version != 1 || value.Role != executorprotocol.RoleBrowser {
		return errors.New("invalid Browser executor backend authority")
	}
	if err := validateAuthority(value); err != nil {
		return err
	}
	backend, err := executorbackend.New(executorbackend.Config{
		Role: value.Role, ListenAddress: value.ListenAddress, UpstreamURL: value.UpstreamURL,
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
	if value.ListenAddress == "" {
		return errors.New("Browser executor backend listen address is required")
	}
	host, _, err := net.SplitHostPort(value.ListenAddress)
	if err != nil || net.ParseIP(host) == nil {
		return errors.New("Browser executor backend listen address must use an explicit IP")
	}
	parsed, err := url.Parse(value.UpstreamURL)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("Browser executor backend upstream URL is invalid")
	}
	for _, path := range []string{value.ServerCertificateFile, value.ServerPrivateKeyFile, value.ClientCABundleFile} {
		if !filepath.IsAbs(path) {
			return errors.New("Browser executor backend TLS paths must be absolute")
		}
	}
	if len(value.AllowedClientIdentities) == 0 || len(value.AllowedClientIdentities) > 32 || value.MaxSessions < 1 || value.MaxSessions > 256 || value.OperationTimeoutMillis < 100 || value.OperationTimeoutMillis > 30_000 {
		return errors.New("Browser executor backend limits or identities are invalid")
	}
	return nil
}
