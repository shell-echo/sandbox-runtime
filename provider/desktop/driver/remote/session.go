// Package remote adapts the Provider Desktop media authority to a restricted
// executor process. It carries only the opaque binding and never exposes the
// Provider allocation coordinate or Docker state.
package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
)

type Options struct {
	URL              string
	HTTPClient       *http.Client
	OperationTimeout time.Duration
	BridgeKeyID      string
	ExecutorIdentity string
	BridgePrivateKey ed25519.PrivateKey
}

type Driver struct {
	url              string
	client           *http.Client
	timeout          time.Duration
	bridgeKeyID      string
	executorIdentity string
	bridgePrivateKey ed25519.PrivateKey
}

func NewHTTPClient(endpoint, caFile, certificateFile, privateKeyFile string) (*http.Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" {
		return nil, errors.New("invalid remote Desktop executor endpoint")
	}
	caDocument, err := secretfile.Read(caFile, 256<<10)
	if err != nil {
		return nil, errors.New("load remote Desktop executor CA")
	}
	defer clear(caDocument)
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(caDocument)
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid remote Desktop executor CA")
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, errors.New("invalid remote Desktop executor CA certificate")
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, errors.New("remote Desktop executor CA is empty")
	}
	certificatePEM, err := secretfile.Read(certificateFile, 64<<10)
	if err != nil {
		return nil, errors.New("load remote Desktop executor certificate")
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := secretfile.Read(privateKeyFile, 64<<10)
	if err != nil {
		return nil, errors.New("load remote Desktop executor key")
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("load remote Desktop executor identity")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}, ServerName: parsed.Hostname()}}}, nil
}

func New(options Options) (*Driver, error) {
	parsed, err := url.Parse(options.URL)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || options.HTTPClient == nil || options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 30*time.Second {
		return nil, errors.New("invalid remote Desktop executor options")
	}
	if options.BridgeKeyID == "" || options.ExecutorIdentity == "" || len(options.BridgePrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid remote Desktop bridge signing authority")
	}
	return &Driver{url: options.URL, client: options.HTTPClient, timeout: options.OperationTimeout, bridgeKeyID: options.BridgeKeyID, executorIdentity: options.ExecutorIdentity, bridgePrivateKey: append(ed25519.PrivateKey(nil), options.BridgePrivateKey...)}, nil
}

func (d *Driver) OpenMedia(ctx context.Context, authority providerdesktop.MediaAuthority, attachment providerdesktop.Attachment, policy desktopmedia.MediaPolicy) (providerdesktop.MediaSession, error) {
	if d == nil || ctx == nil || authority.HandoffReference == "" || authority.HandoffReferenceDigest == "" || authority.ConnectionGeneration < 1 || attachment.DesktopSessionID != authority.DesktopSessionID || attachment.ConnectionGeneration != authority.ConnectionGeneration || attachment.MediaProfileID != providerdesktop.MediaProfileID || attachment.ControlProfileID != providerdesktop.ControlProfileID || !policy.Validate() {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	requestID, err := randomID()
	if err != nil {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	mediaPolicy := policy
	open := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleDesktop, RequestID: requestID, TenantBindingDigest: authority.TenantBindingDigest, ProviderRevisionID: authority.ProviderRevisionID, SandboxID: authority.SandboxID, RuntimeSessionID: authority.DesktopSessionID, CapabilityProfileID: providerdesktop.CapabilityProfileID, MediaProfileID: authority.MediaProfileID, ControlProfileID: authority.ControlProfileID, AllocationReference: authority.AllocationReference, MediaPolicy: &mediaPolicy, MediaPolicyDigest: executorprotocol.PolicyDigest(mediaPolicy), HandoffReference: authority.HandoffReference, HandoffDigest: authority.HandoffReferenceDigest, ConnectionGeneration: authority.ConnectionGeneration, ConnectionEpoch: authority.ConnectionEpoch, Fence: authority.ControllerFence, AuthorityExpiresAt: authority.AuthorityExpiresAt.UTC().Format(time.RFC3339Nano), HandoffExpiresAt: authority.HandoffExpiresAt.UTC().Format(time.RFC3339Nano), Codec: policy.VideoCodec}
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	statement := desktopbridge.Statement{Protocol: desktopbridge.ProtocolID, Version: desktopbridge.Version, KeyID: d.bridgeKeyID, ExecutorRole: executorprotocol.RoleDesktop, ExecutorIdentity: d.executorIdentity, ProviderRevisionID: open.ProviderRevisionID, TenantBindingDigest: open.TenantBindingDigest, SandboxID: open.SandboxID, RuntimeSessionID: open.RuntimeSessionID, HandoffReferenceDigest: open.HandoffDigest, AllocationReference: open.AllocationReference, MediaPolicy: mediaPolicy, ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch, Fence: open.Fence, AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt, NotBefore: time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: open.AuthorityDigest, ExecutorRequestDigest: open.RequestDigest, Nonce: requestID + "-bridge-nonce"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, signErr := desktopbridge.Sign(statement, d.bridgePrivateKey)
	if signErr != nil {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	open.Bridge = &bridge
	if err := open.Validate(time.Now().UTC()); err != nil {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	operationContext, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	connection, _, err := websocket.Dial(operationContext, d.url, &websocket.DialOptions{HTTPClient: d.client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(operationContext, websocket.MessageText, document); err != nil {
		connection.CloseNow()
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	kind, responseDocument, err := connection.Read(operationContext)
	var response executorprotocol.Response
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(responseDocument, &response) != nil || response.Validate() != nil || response.RequestID != requestID || response.Status != executorprotocol.StatusAccepted {
		connection.CloseNow()
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	lifecycleContext, lifecycleCancel := context.WithDeadline(context.Background(), authority.AuthorityExpiresAt)
	result := &session{connection: connection, frames: make(chan []byte, mediaPolicy.MaxQueuedFrames), done: make(chan struct{}), results: make(map[string]chan desktopbroker.SessionMessage), lifecycleContext: lifecycleContext, lifecycleCancel: lifecycleCancel}
	go result.readLoop()
	return result, nil
}

type session struct {
	connection       *websocket.Conn
	frames           chan []byte
	done             chan struct{}
	writeMu          sync.Mutex
	resultMu         sync.Mutex
	results          map[string]chan desktopbroker.SessionMessage
	sequence         atomic.Int64
	closeOnce        sync.Once
	lifecycleContext context.Context
	lifecycleCancel  context.CancelFunc
	termination      sessiontermination.First
}

func (s *session) readLoop() {
	defer func() {
		if _, ok := s.termination.Load(); !ok {
			s.termination.Observe(sessiontermination.StageExecutorTransport, sessiontermination.CauseTransportClosed)
		}
		if record, ok := s.termination.Load(); ok {
			log.Printf("desktop_remote_session_terminal %s", record.String())
		}
		if s.lifecycleCancel != nil {
			s.lifecycleCancel()
		}
		close(s.done)
	}()
	for {
		kind, payload, err := s.connection.Read(s.lifecycleContext)
		if err != nil {
			s.observeReadError(err)
			return
		}
		switch kind {
		case websocket.MessageBinary:
			if len(payload) == 0 || len(payload) > desktopbroker.SessionMaxFrame {
				s.termination.Observe(sessiontermination.StageMediaReader, sessiontermination.CauseProtocolViolation)
				return
			}
			frame := append([]byte(nil), payload...)
			select {
			case s.frames <- frame:
			default:
				s.termination.Observe(sessiontermination.StageMediaReader, sessiontermination.CauseBackpressure)
				return
			}
		case websocket.MessageText:
			var message desktopbroker.SessionMessage
			if len(payload) == 0 || len(payload) >= desktopbroker.SessionMaxDocument || bytes.ContainsAny(payload, "\r\n") {
				s.termination.Observe(sessiontermination.StageInputResultReader, sessiontermination.CauseProtocolViolation)
				return
			}
			document := append(append([]byte(nil), payload...), '\n')
			if desktopbroker.DecodeSession(document, &message) != nil || message.ValidateFor(desktopbroker.SessionProtocolV2ID) != nil {
				s.termination.Observe(sessiontermination.StageInputResultReader, sessiontermination.CauseProtocolViolation)
				return
			}
			if message.Type == desktopbroker.SessionClosedType {
				s.termination.Observe(sessiontermination.StageCloseOrdering, sessiontermination.CauseCleanClose)
				return
			}
			if message.Type != desktopbroker.SessionResultType && message.Type != desktopbroker.SessionErrorType {
				s.termination.Observe(sessiontermination.StageInputResultReader, sessiontermination.CauseProtocolViolation)
				return
			}
			s.resultMu.Lock()
			response := s.results[message.RequestID]
			s.resultMu.Unlock()
			if response != nil {
				select {
				case response <- message:
				default:
				}
			}
		default:
			s.termination.Observe(sessiontermination.StageExecutorTransport, sessiontermination.CauseProtocolViolation)
			return
		}
	}
}

func (s *session) observeReadError(err error) {
	cause := sessiontermination.CauseTransportClosed
	if errors.Is(s.lifecycleContext.Err(), context.DeadlineExceeded) {
		cause = sessiontermination.CauseExpiry
	} else if errors.Is(s.lifecycleContext.Err(), context.Canceled) {
		cause = sessiontermination.CauseCallerCancel
	} else if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
		cause = sessiontermination.CauseCleanClose
	}
	s.termination.Observe(sessiontermination.StageExecutorTransport, cause)
}

func (s *session) terminalError() error {
	if err := s.termination.Err(); err != nil {
		return err
	}
	return io.EOF
}

func (s *session) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	if s == nil || ctx == nil {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	select {
	case frame := <-s.frames:
		return frame, nil
	case <-s.done:
		return nil, s.terminalError()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *session) ReadAudioRTP(context.Context) ([]byte, error) {
	return nil, providerdesktop.ErrDesktopUnsupported
}
func (s *session) HandleInput(ctx context.Context, input desktopmedia.Input) (desktopmedia.InputResult, error) {
	return s.command(ctx, "input", input)
}
func (s *session) UpdateStream(ctx context.Context, display desktopmedia.DisplayPolicy, output string) error {
	_, err := s.command(ctx, "stream.configure", struct {
		Display desktopmedia.DisplayPolicy `json:"display"`
		Output  string                     `json:"output"`
	}{display, output})
	return err
}
func (s *session) Resynchronize(ctx context.Context) error {
	_, err := s.command(ctx, "stream.resync", nil)
	return err
}
func (s *session) RequestKeyframe(ctx context.Context) error {
	_, err := s.command(ctx, "keyframe", nil)
	return err
}

func (s *session) command(ctx context.Context, method string, value any) (desktopmedia.InputResult, error) {
	if s == nil || ctx == nil {
		return desktopmedia.InputResult{}, providerdesktop.ErrDesktopUnsupported
	}
	s.writeMu.Lock()
	sequence := s.sequence.Add(1)
	requestID := "desktop-command-" + strconv.FormatInt(sequence, 10)
	document, err := json.Marshal(struct {
		Protocol string `json:"protocol"`
		Method   string `json:"method"`
		Sequence int64  `json:"sequence"`
		Value    any    `json:"value,omitempty"`
	}{executorprotocol.ProtocolID, method, sequence, value})
	if err != nil || len(document) > executorprotocol.MaxDocumentBytes {
		s.writeMu.Unlock()
		return desktopmedia.InputResult{}, providerdesktop.ErrDesktopUnsupported
	}
	response := make(chan desktopbroker.SessionMessage, 1)
	s.resultMu.Lock()
	s.results[requestID] = response
	s.resultMu.Unlock()
	defer func() {
		s.resultMu.Lock()
		delete(s.results, requestID)
		s.resultMu.Unlock()
	}()
	err = s.connection.Write(ctx, websocket.MessageText, document)
	s.writeMu.Unlock()
	if err != nil {
		s.termination.Observe(sessiontermination.StageInputWriter, sessiontermination.CauseTransportClosed)
		return desktopmedia.InputResult{}, providerdesktop.ErrDesktopUnsupported
	}
	select {
	case result := <-response:
		if result.Type != desktopbroker.SessionResultType || !result.OK {
			s.termination.Observe(sessiontermination.StageInputResultReader, sessiontermination.CauseRuntimeFailure)
			return desktopmedia.InputResult{}, providerdesktop.ErrDesktopUnsupported
		}
		return desktopmedia.InputResult{Text: result.Text}, nil
	case <-s.done:
		select {
		case result := <-response:
			if result.Type == desktopbroker.SessionResultType && result.OK {
				return desktopmedia.InputResult{Text: result.Text}, nil
			}
		default:
		}
		return desktopmedia.InputResult{}, s.terminalError()
	case <-ctx.Done():
		return desktopmedia.InputResult{}, ctx.Err()
	}
}

func (s *session) Close() error {
	if s == nil || s.connection == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.termination.Observe(sessiontermination.StageCloseOrdering, sessiontermination.CauseCleanClose)
		if s.lifecycleCancel != nil {
			s.lifecycleCancel()
		}
		_ = s.connection.CloseNow()
	})
	return nil
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "executor-" + hex.EncodeToString(value), nil
}

var _ providerdesktop.MediaRuntime = (*Driver)(nil)
