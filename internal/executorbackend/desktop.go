package executorbackend

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

const desktopMaxSessions = 256

var desktopBrokerSocketPattern = regexp.MustCompile(`^desktop-broker-[0-9a-f]{32}\.sock$`)

// DesktopConfig describes the operator-owned Desktop executor boundary. The
// broker socket is the only runtime coordinate held by this process.
type DesktopConfig struct {
	Role                    string
	ListenAddress           string
	BrokerSocketPath        string
	ExecutorIdentity        string
	ServerCertificateFile   string
	ServerPrivateKeyFile    string
	ClientCABundleFile      string
	AllowedClientIdentities []string
	MaxSessions             int
	OperationTimeout        time.Duration
}

// DesktopBackend terminates executor mTLS and relays one short-lived Desktop
// session to the private Unix broker. It has no Provider or Docker access.
type DesktopBackend struct {
	config   DesktopConfig
	tls      *tls.Config
	server   *http.Server
	mu       sync.Mutex
	active   int
	replayMu sync.Mutex
	replayed map[string]time.Time
}

func NewDesktop(config DesktopConfig) (*DesktopBackend, error) {
	if config.Role != executorprotocol.RoleDesktop || config.ListenAddress == "" ||
		!validDesktopBrokerSocketPath(config.BrokerSocketPath) || config.ExecutorIdentity == "" || len(config.ExecutorIdentity) > 200 || strings.ContainsAny(config.ExecutorIdentity, " \t\r\n\x00") ||
		config.OperationTimeout < 100*time.Millisecond || config.OperationTimeout > 30*time.Second ||
		config.MaxSessions < 1 || config.MaxSessions > desktopMaxSessions {
		return nil, errors.New("invalid Desktop executor backend configuration")
	}
	if err := validateDesktopBrokerSocket(config.BrokerSocketPath); err != nil {
		return nil, err
	}
	tlsConfig, err := providerapi.LoadMTLSConfig(config.ServerCertificateFile, config.ServerPrivateKeyFile, config.ClientCABundleFile, config.AllowedClientIdentities)
	if err != nil {
		return nil, err
	}
	return &DesktopBackend{
		config: config,
		tls:    tlsConfig,
		server: &http.Server{Addr: config.ListenAddress, Handler: nil, TLSConfig: tlsConfig,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10},
		replayed: make(map[string]time.Time),
	}, nil
}

func (b *DesktopBackend) Ready(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("Desktop executor backend is unavailable")
	}
	probeContext, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	defer cancel()
	if err := validateDesktopBrokerSocket(b.config.BrokerSocketPath); err != nil {
		return errors.New("Desktop broker is unavailable")
	}
	connection, err := dialDesktopBroker(probeContext, b.config.BrokerSocketPath)
	if err != nil {
		return errors.New("Desktop broker is unavailable")
	}
	defer connection.Close()
	request, err := desktopbroker.EncodeSession(desktopbroker.Request{Protocol: desktopbroker.ProtocolID, RequestID: "executor-probe", Method: desktopbroker.BridgeProbeMethod})
	if err != nil {
		return errors.New("Desktop broker is unavailable")
	}
	if _, err := connection.Write(request); err != nil {
		return errors.New("Desktop broker is unavailable")
	}
	line, err := bufio.NewReaderSize(connection, desktopbroker.SessionMaxDocument).ReadBytes('\n')
	if err != nil {
		return errors.New("Desktop broker is unavailable")
	}
	var response desktopbroker.Response
	if desktopbroker.DecodeSession(line, &response) != nil || response.Validate() != nil || response.RequestID != "executor-probe" || response.Status != "ok" {
		return errors.New("Desktop broker is unavailable")
	}
	return nil
}

func (b *DesktopBackend) Serve(ctx context.Context) error {
	if b == nil || ctx == nil || b.server == nil {
		return errors.New("Desktop executor backend is not initialized")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", b.config.ListenAddress)
	if err != nil {
		return errors.New("bind Desktop executor backend")
	}
	defer listener.Close()
	b.server.Handler = http.HandlerFunc(b.handle)
	stop := context.AfterFunc(ctx, func() { _ = b.server.Shutdown(context.Background()) })
	defer stop()
	if err := b.server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		return errors.New("serve Desktop executor backend")
	}
	return nil
}

func (b *DesktopBackend) Close() error {
	if b != nil && b.server != nil {
		_ = b.server.Close()
	}
	return nil
}

func (b *DesktopBackend) handle(writer http.ResponseWriter, request *http.Request) {
	if request != nil && request.Method == http.MethodGet && request.URL.Path == "/readyz" && request.TLS != nil {
		writer.Header().Set("Cache-Control", "no-store")
		if err := b.Ready(request.Context()); err != nil {
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request == nil || request.Method != http.MethodGet || request.URL.Path != "/executor" || request.TLS == nil || request.Header.Get("Sec-WebSocket-Protocol") != executorprotocol.ProtocolID {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{executorprotocol.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(executorprotocol.MaxMessageBytes)

	openContext, cancelOpen := context.WithTimeout(request.Context(), b.config.OperationTimeout)
	defer cancelOpen()
	kind, document, err := connection.Read(openContext)
	var open executorprotocol.Open
	now := time.Now().UTC()
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(document, &open) != nil || open.Role != b.config.Role || open.Validate(now) != nil || open.Bridge == nil || open.Bridge.Statement.ExecutorIdentity != b.config.ExecutorIdentity || !b.claim(open.RequestID, now, openExpiry(open)) || !b.acquire() {
		b.reject(connection, "unavailable")
		return
	}
	defer b.release()
	if err := validateDesktopBrokerSocket(b.config.BrokerSocketPath); err != nil {
		b.reject(connection, "unavailable")
		return
	}
	broker, err := dialDesktopBroker(openContext, b.config.BrokerSocketPath)
	if err != nil {
		b.reject(connection, "unavailable")
		return
	}
	defer broker.Close()
	if err := writeDesktopOpen(broker, open); err != nil {
		b.reject(connection, "unavailable")
		return
	}
	brokerReader := bufio.NewReaderSize(broker, desktopbroker.SessionMaxDocument)
	accepted, err := readDesktopMessage(brokerReader, desktopbroker.SessionProtocolV2ID)
	if err != nil || accepted.Type != desktopbroker.SessionAcceptedType || accepted.RequestID != open.RequestID {
		b.reject(connection, "unavailable")
		return
	}
	response, _ := executorprotocol.Encode(executorprotocol.Accepted(open.RequestID))
	if err := connection.Write(request.Context(), websocket.MessageText, response); err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), openExpiry(open))
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- desktopToExecutor(ctx, brokerReader, connection) }()
	go func() { results <- executorToDesktop(ctx, connection, broker, open) }()
	<-results
	cancel()
	_ = connection.CloseNow()
	_ = broker.Close()
	<-results
}

func (b *DesktopBackend) reject(connection *websocket.Conn, code string) {
	response, _ := executorprotocol.Encode(executorprotocol.Rejected("invalid", code))
	_ = connection.Write(context.Background(), websocket.MessageText, response)
}

func (b *DesktopBackend) claim(requestID string, now, expires time.Time) bool {
	if requestID == "" || expires.IsZero() || !expires.After(now) {
		return false
	}
	b.replayMu.Lock()
	defer b.replayMu.Unlock()
	for id, until := range b.replayed {
		if !until.After(now) {
			delete(b.replayed, id)
		}
	}
	if _, exists := b.replayed[requestID]; exists {
		return false
	}
	b.replayed[requestID] = expires
	return true
}

func (b *DesktopBackend) acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active >= b.config.MaxSessions {
		return false
	}
	b.active++
	return true
}

func (b *DesktopBackend) release() {
	b.mu.Lock()
	if b.active > 0 {
		b.active--
	}
	b.mu.Unlock()
}

func dialDesktopBroker(ctx context.Context, socketPath string) (net.Conn, error) {
	if err := validateDesktopBrokerSocket(socketPath); err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	if _, ok := connection.(*net.UnixConn); !ok {
		_ = connection.Close()
		return nil, errors.New("Desktop broker is not a Unix socket")
	}
	return connection, nil
}

func validateDesktopBrokerSocket(path string) error {
	if !validDesktopBrokerSocketPath(path) {
		return errors.New("invalid Desktop broker socket path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm() != 0o700 {
		return errors.New("unsafe Desktop broker socket directory")
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || uint32(parentStat.Uid) != uint32(os.Getuid()) {
		return errors.New("Desktop broker socket directory owner mismatch")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("unsafe Desktop broker socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Getuid()) {
		return errors.New("Desktop broker socket owner mismatch")
	}
	return nil
}

func validDesktopBrokerSocketPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && desktopBrokerSocketPattern.MatchString(filepath.Base(path))
}

func writeDesktopOpen(connection net.Conn, open executorprotocol.Open) error {
	policy := desktopmedia.MediaPolicy{}
	if open.MediaPolicy != nil {
		policy = *open.MediaPolicy
	}
	value := desktopbroker.SessionOpen{
		BindingVersion: desktopbroker.SessionBindingV2, BindingIssuer: desktopbroker.SessionBindingIssuerV2, Protocol: desktopbroker.SessionProtocolV2ID,
		RequestID: open.RequestID, Method: desktopbroker.SessionMethod, TenantBindingDigest: open.TenantBindingDigest,
		ProviderRevisionID: open.ProviderRevisionID, SandboxID: open.SandboxID, DesktopSessionID: open.RuntimeSessionID,
		CapabilityProfileID: open.CapabilityProfileID, MediaProfileID: open.MediaProfileID, ControlProfileID: open.ControlProfileID,
		HandoffReferenceDigest: open.HandoffDigest, AllocationReference: open.AllocationReference,
		ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch, Fence: open.Fence,
		AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt,
		AuthorityDigest: open.AuthorityDigest, RequestDigest: open.RequestDigest, HandoffReference: open.HandoffReference,
		MediaPolicy: policy, Bridge: open.Bridge,
	}
	document, err := desktopbroker.EncodeSession(value)
	if err != nil {
		return err
	}
	written, err := connection.Write(document)
	if err != nil || written != len(document) {
		return errors.New("write Desktop broker open")
	}
	return nil
}

func readDesktopMessage(reader *bufio.Reader, protocol string) (desktopbroker.SessionMessage, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return desktopbroker.SessionMessage{}, err
	}
	var message desktopbroker.SessionMessage
	if desktopbroker.DecodeSession(line, &message) != nil || message.ValidateFor(protocol) != nil {
		return desktopbroker.SessionMessage{}, errors.New("invalid Desktop broker message")
	}
	return message, nil
}

func desktopToExecutor(ctx context.Context, reader *bufio.Reader, executor *websocket.Conn) error {
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return err
		}
		var message desktopbroker.SessionMessage
		if desktopbroker.DecodeSession(line, &message) != nil || message.ValidateFor(desktopbroker.SessionProtocolV2ID) != nil {
			return errors.New("invalid Desktop broker message")
		}
		switch message.Type {
		case desktopbroker.SessionFrameType:
			payload, err := decodeRTP(message.Payload)
			if err != nil {
				return err
			}
			if err := executor.Write(ctx, websocket.MessageBinary, payload); err != nil {
				return err
			}
		case desktopbroker.SessionResultType, desktopbroker.SessionErrorType, desktopbroker.SessionClosedType:
			if err := executor.Write(ctx, websocket.MessageText, bytes.TrimSuffix(line, []byte{'\n'})); err != nil {
				return err
			}
			if message.Type == desktopbroker.SessionClosedType {
				return io.EOF
			}
		default:
			return errors.New("unexpected Desktop broker message")
		}
	}
}

func executorToDesktop(ctx context.Context, executor *websocket.Conn, broker net.Conn, open executorprotocol.Open) error {
	var previousSequence int64
	for {
		kind, document, err := executor.Read(ctx)
		if err != nil {
			return err
		}
		if kind != websocket.MessageText || len(document) == 0 || len(document) > executorprotocol.MaxDocumentBytes {
			return errors.New("invalid Desktop executor command")
		}
		var command struct {
			Protocol string          `json:"protocol"`
			Method   string          `json:"method"`
			Sequence int64           `json:"sequence"`
			Value    json.RawMessage `json:"value,omitempty"`
		}
		if executorprotocol.Decode(document, &command) != nil || command.Protocol != executorprotocol.ProtocolID || command.Sequence <= previousSequence || command.Sequence > 1<<53-1 {
			return errors.New("invalid Desktop executor command")
		}
		brokerCommand, err := decodeExecutorCommand(command, open, command.Sequence)
		if err != nil {
			return err
		}
		previousSequence = command.Sequence
		encoded, err := desktopbroker.EncodeSession(brokerCommand)
		if err != nil {
			return err
		}
		written, err := broker.Write(encoded)
		if err != nil || written != len(encoded) {
			return errors.New("write Desktop broker command")
		}
		if brokerCommand.Type == "close" {
			<-ctx.Done()
			return ctx.Err()
		}
	}
}

func decodeExecutorCommand(command struct {
	Protocol string          `json:"protocol"`
	Method   string          `json:"method"`
	Sequence int64           `json:"sequence"`
	Value    json.RawMessage `json:"value,omitempty"`
}, open executorprotocol.Open, sequence int64) (desktopbroker.SessionCommand, error) {
	requestID := fmt.Sprintf("desktop-command-%d", sequence)
	result := desktopbroker.SessionCommand{Protocol: desktopbroker.SessionProtocolV2ID, RequestID: requestID, Sequence: sequence}
	switch command.Method {
	case "input":
		var input desktopmedia.Input
		if decodeRaw(command.Value, &input) != nil {
			return desktopbroker.SessionCommand{}, errors.New("invalid Desktop input command")
		}
		result.Type, result.Input = "input", &input
	case "stream.configure":
		var value struct {
			Display desktopmedia.DisplayPolicy `json:"display"`
			Output  string                     `json:"output,omitempty"`
		}
		if decodeRaw(command.Value, &value) != nil || value.Output != "" {
			return desktopbroker.SessionCommand{}, errors.New("invalid Desktop stream command")
		}
		result.Type, result.Display = "stream.configure", &value.Display
	case "stream.resync", "keyframe", "close":
		if len(bytes.TrimSpace(command.Value)) != 0 && string(bytes.TrimSpace(command.Value)) != "null" && string(bytes.TrimSpace(command.Value)) != "{}" {
			return desktopbroker.SessionCommand{}, errors.New("invalid Desktop control command")
		}
		result.Type = command.Method
	default:
		return desktopbroker.SessionCommand{}, errors.New("unknown Desktop executor command")
	}
	if result.Type == "close" {
		return result, nil
	}
	policy := desktopmedia.MediaPolicy{}
	if open.MediaPolicy != nil {
		policy = *open.MediaPolicy
	}
	if result.ValidateFor(policy, sequence-1, desktopbroker.SessionProtocolV2ID) != nil {
		return desktopbroker.SessionCommand{}, errors.New("Desktop command does not match policy")
	}
	return result, nil
}

func decodeRaw(document []byte, target any) error {
	if len(document) == 0 || target == nil {
		return errors.New("empty command value")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing command value")
	}
	return nil
}

func decodeRTP(payload string) ([]byte, error) {
	var message desktopbroker.SessionMessage
	_ = message
	// SessionMessage.Validate already decoded and bounded the base64 payload.
	// Reuse the standard decoder only after the closed message validation.
	decoded, err := io.ReadAll(base64Reader(payload))
	if err != nil || len(decoded) < 12 || len(decoded) > desktopbroker.SessionMaxFrame {
		return nil, errors.New("invalid Desktop RTP frame")
	}
	return decoded, nil
}

func base64Reader(value string) io.Reader {
	return base64.NewDecoder(base64.StdEncoding, strings.NewReader(value))
}
