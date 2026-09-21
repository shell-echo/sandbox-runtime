// Package remote adapts Provider Browser handoff records to a restricted
// executor process. Provider remains the owner of allocation/reference truth.
package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

type Options struct {
	URL              string
	HTTPClient       *http.Client
	OperationTimeout time.Duration
}

type Attacher struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

func NewHTTPClient(endpoint, caFile, certificateFile, privateKeyFile string) (*http.Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" {
		return nil, errors.New("invalid remote Browser executor endpoint")
	}
	caDocument, err := secretfile.Read(caFile, 256<<10)
	if err != nil {
		return nil, errors.New("load remote Browser executor CA")
	}
	defer clear(caDocument)
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(caDocument)
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid remote Browser executor CA")
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, errors.New("invalid remote Browser executor CA certificate")
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, errors.New("remote Browser executor CA is empty")
	}
	certificatePEM, err := secretfile.Read(certificateFile, 64<<10)
	if err != nil {
		return nil, errors.New("load remote Browser executor certificate")
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := secretfile.Read(privateKeyFile, 64<<10)
	if err != nil {
		return nil, errors.New("load remote Browser executor key")
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("load remote Browser executor identity")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}, ServerName: parsed.Hostname()}}}, nil
}

func New(options Options) (*Attacher, error) {
	parsed, err := url.Parse(options.URL)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || options.HTTPClient == nil || options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 30*time.Second {
		return nil, errors.New("invalid remote Browser executor options")
	}
	return &Attacher{url: options.URL, client: options.HTTPClient, timeout: options.OperationTimeout}, nil
}

func (a *Attacher) Attach(context.Context, providerbrowser.AllocationReceipt) (providerbrowser.Stream, error) {
	return nil, providerbrowser.ErrBrowserUnsupported
}

func (a *Attacher) AttachBound(ctx context.Context, record reference.Record) (providerbrowser.Stream, error) {
	if a == nil || ctx == nil || record.Validate() != nil || record.TenantBindingDigest == "" {
		return nil, providerbrowser.ErrBrowserUnsupported
	}
	requestID, err := randomID()
	if err != nil {
		return nil, providerbrowser.ErrBrowserUnsupported
	}
	open := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleBrowser, RequestID: requestID, TenantBindingDigest: record.TenantBindingDigest, ProviderRevisionID: record.ProviderRevisionID, SandboxID: record.SandboxID, RuntimeSessionID: record.BrowserSessionID, CapabilityProfileID: record.CapabilityProfileID, MediaProfileID: "browser-cdp-v1", ControlProfileID: "browser-control-v1", HandoffReference: record.Reference, HandoffDigest: executorprotocol.ReferenceDigest(record.Reference), ConnectionGeneration: record.ConnectionGeneration, ConnectionEpoch: "generation-" + formatInt(record.ConnectionGeneration), Fence: fence(), AuthorityExpiresAt: record.ExpiresAt.UTC().Format(time.RFC3339Nano), HandoffExpiresAt: record.ExpiresAt.UTC().Format(time.RFC3339Nano), Codec: "application/json"}
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	if err := open.Validate(time.Now().UTC()); err != nil {
		return nil, providerbrowser.ErrBrowserUnsupported
	}
	operationContext, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	connection, _, err := websocket.Dial(operationContext, a.url, &websocket.DialOptions{HTTPClient: a.client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		return nil, providerbrowser.ErrBrowserUnsupported
	}
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(operationContext, websocket.MessageText, document); err != nil {
		connection.CloseNow()
		return nil, providerbrowser.ErrBrowserUnsupported
	}
	kind, responseDocument, err := connection.Read(operationContext)
	var response executorprotocol.Response
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(responseDocument, &response) != nil || response.Validate() != nil || response.RequestID != requestID || response.Status != executorprotocol.StatusAccepted {
		connection.CloseNow()
		return nil, providerbrowser.ErrBrowserUnsupported
	}
	return &stream{connection: connection}, nil
}

type stream struct {
	connection *websocket.Conn
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

func (s *stream) Read(ctx context.Context, payload []byte) (int, error) {
	kind, value, err := s.connection.Read(ctx)
	if err != nil {
		return 0, err
	}
	if kind != websocket.MessageText || len(value) > len(payload) {
		return 0, providerbrowser.ErrBrowserUnsupported
	}
	return copy(payload, value), nil
}
func (s *stream) Write(ctx context.Context, payload []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.connection.Write(ctx, websocket.MessageText, append([]byte(nil), payload...)); err != nil {
		return 0, providerbrowser.ErrBrowserUnsupported
	}
	return len(payload), nil
}
func (s *stream) Close() error {
	if s == nil || s.connection == nil {
		return nil
	}
	s.closeOnce.Do(func() { _ = s.connection.CloseNow() })
	return nil
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "executor-" + hex.EncodeToString(value), nil
}
func fence() string {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "executor-fence-invalid"
	}
	return hex.EncodeToString(value)
}
func formatInt(value int64) string { return strconv.FormatInt(value, 10) }

var _ providerbrowser.Attacher = (*Attacher)(nil)
var _ reference.BoundAttacher = (*Attacher)(nil)
