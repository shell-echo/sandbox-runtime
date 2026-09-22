// workload-material-agent-fixture is an integration-only operator-agent
// harness. It is not a production deployment profile and deliberately accepts
// its isolated Vault bootstrap token only from a test environment variable.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/vaultkv"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
)

const fixtureTokenEnvironment = "SANDBOX_RUNTIME_FIXTURE_VAULT_TOKEN"

type fixtureTokenProvider struct {
	binding secretref.Binding
	value   []byte
	digest  string
	window  secretref.RotationWindow
}

func (p fixtureTokenProvider) ResolveSecret(ctx context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	if ctx == nil || ctx.Err() != nil || binding != p.binding {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	return secretref.SecretMaterial{Binding: binding, Bytes: append([]byte(nil), p.value...), Digest: p.digest, Window: p.window, Revision: "fixture-token-1"}, nil
}

func main() {
	if run() != nil {
		_, _ = fmt.Fprintln(os.Stderr, "workload material fixture failed")
		os.Exit(1)
	}
}

func run() error {
	var socketPath, endpoint, caPath, certificateReference, certificateVersion, privateKeyReference, privateKeyVersion string
	var expectedClientUID, expectedClientGID uint
	flag.StringVar(&socketPath, "socket", "", "role-specific Unix socket")
	flag.StringVar(&endpoint, "vault-endpoint", "", "fixture Vault HTTPS endpoint")
	flag.StringVar(&caPath, "vault-ca", "", "fixture Vault CA file")
	flag.StringVar(&certificateReference, "certificate-reference", "", "certificate binding reference")
	flag.StringVar(&certificateVersion, "certificate-version", "", "certificate binding version")
	flag.StringVar(&privateKeyReference, "private-key-reference", "", "private-key binding reference")
	flag.StringVar(&privateKeyVersion, "private-key-version", "", "private-key binding version")
	flag.UintVar(&expectedClientUID, "expected-client-uid", uint(os.Getuid()), "expected client UID")
	flag.UintVar(&expectedClientGID, "expected-client-gid", uint(os.Getgid()), "expected client GID")
	flag.Parse()
	if flag.NArg() != 0 {
		return secretref.ErrUnavailable
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil || parsedEndpoint.Scheme != "https" || parsedEndpoint.Hostname() == "" {
		return secretref.ErrUnavailable
	}
	caDocument, err := secretfile.Read(caPath, 64<<10)
	if err != nil {
		return secretref.ErrUnavailable
	}
	defer clear(caDocument)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caDocument) {
		return secretref.ErrUnavailable
	}
	token := []byte(os.Getenv(fixtureTokenEnvironment))
	_ = os.Unsetenv(fixtureTokenEnvironment)
	defer clear(token)
	if len(token) < 1 {
		return secretref.ErrUnavailable
	}
	now := time.Now().UTC()
	tokenBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://fixture/vault-kv-token", Version: "v1",
		Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct,
	}
	tokenDigest := sha256.Sum256(token)
	tokenProvider := fixtureTokenProvider{
		binding: tokenBinding, value: token, digest: "sha256:" + hex.EncodeToString(tokenDigest[:]),
		window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(4 * time.Minute), State: secretref.KeyActive},
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: parsedEndpoint.Hostname(),
	}}}
	provider, err := vaultkv.New(vaultkv.Config{
		Endpoint: endpoint, Mount: "kv", ReferenceAuthority: "vault", Role: secretref.RoleProduct,
		AllowedPurposes:  []secretref.Purpose{secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey},
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return time.Now().UTC() },
	}, httpClient, tokenProvider, tokenBinding)
	if err != nil {
		return secretref.ErrUnavailable
	}
	certificateBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: secretref.Reference(certificateReference), Version: certificateVersion,
		Purpose: secretref.PurposeTLSCertificate, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct,
	}
	privateKeyBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: secretref.Reference(privateKeyReference), Version: privateKeyVersion,
		Purpose: secretref.PurposeTLSPrivateKey, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct,
	}
	server, err := workloadagent.Listen(workloadagent.ServerConfig{
		SocketPath: socketPath, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(expectedClientUID), ExpectedClientGID: uint32(expectedClientGID), Role: secretref.RoleProduct,
		AllowedPurposes: []secretref.Purpose{secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey},
		Bindings:        []secretref.Binding{certificateBinding, privateKeyBinding}, MaxConnections: 16, Now: func() time.Time { return time.Now().UTC() },
	}, provider)
	if err != nil {
		return secretref.ErrUnavailable
	}
	defer server.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = server.Serve(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
