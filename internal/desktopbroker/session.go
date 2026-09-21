package desktopbroker

// This file owns the private Desktop session protocol and runtime bridge.
// It is intentionally separate from the observation protocol in broker.go:
// probe/describe stay backwards compatible while media/control sessions use
// a closed, versioned, opaque-only stream.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
)

const (
	SessionProtocolID      = "sandbox.runtime/desktop-session/v1"
	SessionProtocolV2ID    = "sandbox.runtime/desktop-session.v2"
	SessionProtocolEnv     = "SANDBOX_RUNTIME_DESKTOP_SESSION_PROTOCOL"
	SessionBindingV2       = 2
	SessionBindingIssuerV2 = "provider-desktop"
	SessionMethod          = "session"
	SessionMaxDocument     = 64 << 10
	SessionMaxFrame        = 16 << 10
	SessionMaxQueue        = 32
	SessionMaxInput        = 64 << 10
	SessionFrameType       = "video.rtp"
	SessionResultType      = "result"
	SessionErrorType       = "error"
	SessionAcceptedType    = "accepted"
	SessionClosedType      = "closed"
	SessionTerminalType    = "session.terminal"
	SessionProtocolVersion = 1
	SessionTerminalVersion = 1
)

var (
	sessionReferencePattern    = regexp.MustCompile(`^ref:desktop-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	allocationReferencePattern = regexp.MustCompile(`^ref:desktop/[0-9a-f]{32}$`)
	sessionIdentifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	sessionFencePattern        = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{32,512}$`)
)

// SessionOpen is the first message on a session connection. All fields are
// opaque authority supplied by Provider/Gateway; the broker only validates
// shape and binds the values to this one runtime session.
type SessionOpen struct {
	BindingVersion         int                      `json:"binding_version"`
	BindingIssuer          string                   `json:"binding_issuer"`
	Protocol               string                   `json:"protocol"`
	RequestID              string                   `json:"request_id"`
	Method                 string                   `json:"method"`
	TenantBindingDigest    string                   `json:"tenant_binding_digest"`
	ProviderRevisionID     string                   `json:"provider_revision_id"`
	SandboxID              string                   `json:"sandbox_id"`
	DesktopSessionID       string                   `json:"desktop_session_id"`
	CapabilityProfileID    string                   `json:"capability_profile_id"`
	MediaProfileID         string                   `json:"media_profile_id"`
	ControlProfileID       string                   `json:"control_profile_id"`
	HandoffReferenceDigest string                   `json:"handoff_reference_digest"`
	AllocationReference    string                   `json:"allocation_reference"`
	ConnectionGeneration   int64                    `json:"connection_generation"`
	ConnectionEpoch        string                   `json:"connection_epoch"`
	Fence                  string                   `json:"fence"`
	AuthorityExpiresAt     string                   `json:"authority_expires_at"`
	HandoffExpiresAt       string                   `json:"handoff_expires_at"`
	AuthorityDigest        string                   `json:"authority_digest"`
	RequestDigest          string                   `json:"request_digest"`
	HandoffReference       string                   `json:"handoff_reference"`
	MediaPolicy            desktopmedia.MediaPolicy `json:"media_policy"`
	Bridge                 *desktopbridge.Envelope  `json:"bridge,omitempty"`
}

func (o SessionOpen) Validate(now time.Time) error {
	if o.Protocol != SessionProtocolID || o.Method != SessionMethod || o.Bridge != nil {
		return ErrInvalidSession
	}
	open := desktophandoff.OpenRequest{BindingVersion: o.BindingVersion, BindingIssuer: o.BindingIssuer, Protocol: desktophandoff.ProtocolID, RequestID: o.RequestID, Resource: desktophandoff.ResourceDesktop,
		TenantBindingDigest: o.TenantBindingDigest, ProviderRevisionID: o.ProviderRevisionID, SandboxID: o.SandboxID, DesktopSessionID: o.DesktopSessionID,
		CapabilityProfileID: o.CapabilityProfileID, MediaProfileID: o.MediaProfileID, ControlProfileID: o.ControlProfileID,
		HandoffReference: o.HandoffReference, HandoffDigest: o.HandoffReferenceDigest, ConnectionGeneration: o.ConnectionGeneration,
		ConnectionEpoch: o.ConnectionEpoch, AuthorityExpiresAt: o.AuthorityExpiresAt, HandoffExpiresAt: o.HandoffExpiresAt,
		ControllerFence: o.Fence, AuthorityDigest: o.AuthorityDigest, RequestDigest: o.RequestDigest, MediaPolicy: o.MediaPolicy}
	if open.Validate(now) != nil || !allocationReferencePattern.MatchString(o.AllocationReference) {
		return ErrInvalidSession
	}
	return nil
}

// ValidateV2 validates the broker-v2 route. Its bridge statement is the
// signed trust-boundary translation from executor.v2; v1 desktophandoff
// digests are deliberately not accepted here.
func (o SessionOpen) ValidateV2(now time.Time, keys map[string]ed25519.PublicKey) error {
	if o.BindingVersion != SessionBindingV2 || o.BindingIssuer != SessionBindingIssuerV2 || o.Protocol != SessionProtocolV2ID || o.Method != SessionMethod || o.Bridge == nil || o.Bridge.Verify(now, keys) != nil {
		return ErrInvalidSession
	}
	s := o.Bridge.Statement
	if !requestIDPattern.MatchString(o.RequestID) || o.TenantBindingDigest != s.TenantBindingDigest || o.ProviderRevisionID != s.ProviderRevisionID || o.SandboxID != s.SandboxID || o.DesktopSessionID != s.RuntimeSessionID || o.HandoffReferenceDigest != s.HandoffReferenceDigest || o.AllocationReference != s.AllocationReference || o.ConnectionGeneration != s.ConnectionGeneration || o.ConnectionEpoch != s.ConnectionEpoch || o.Fence != s.Fence || o.AuthorityExpiresAt != s.AuthorityExpiresAt || o.HandoffExpiresAt != s.HandoffExpiresAt || o.AuthorityDigest != s.ExecutorAuthorityDigest || o.RequestDigest != s.ExecutorRequestDigest || o.MediaPolicy != s.MediaPolicy || !allocationReferencePattern.MatchString(o.AllocationReference) {
		return ErrInvalidSession
	}
	if o.CapabilityProfileID != "desktop-v1" || o.MediaProfileID != "desktop-media-v1" || o.ControlProfileID != "desktop-control-v1" || !sessionReferencePattern.MatchString(o.HandoffReference) || referenceDigest(o.HandoffReference) != o.HandoffReferenceDigest {
		return ErrInvalidSession
	}
	return nil
}

func referenceDigest(reference string) string {
	digest := sha256.Sum256([]byte(reference))
	return fmt.Sprintf("sha256:%x", digest[:])
}

type SessionMessage struct {
	Protocol  string                   `json:"protocol"`
	Version   int                      `json:"version,omitempty"`
	Type      string                   `json:"type"`
	RequestID string                   `json:"request_id,omitempty"`
	Sequence  int64                    `json:"sequence,omitempty"`
	Timestamp int64                    `json:"timestamp_unix_nano,omitempty"`
	Payload   string                   `json:"payload,omitempty"`
	OK        bool                     `json:"ok,omitempty"`
	ErrorCode string                   `json:"error_code,omitempty"`
	Text      string                   `json:"text,omitempty"`
	Stage     sessiontermination.Stage `json:"stage,omitempty"`
	Cause     sessiontermination.Cause `json:"cause,omitempty"`
}

func (m SessionMessage) Validate() error {
	return m.ValidateFor(SessionProtocolID)
}

func (m SessionMessage) ValidateFor(protocol string) error {
	if m.Protocol != protocol || m.Type == "" || len(m.Type) > 32 || strings.ContainsAny(m.Type, "\r\n\x00") {
		return ErrInvalidSession
	}
	switch m.Type {
	case SessionAcceptedType:
		if m.Version != 0 || m.Stage != "" || m.Cause != "" {
			return ErrInvalidSession
		}
		return m.validateRequest()
	case SessionFrameType:
		if m.Version != 0 || m.Stage != "" || m.Cause != "" || m.Sequence < 1 || m.Timestamp < 1 || m.Payload == "" || len(m.Payload) > base64.StdEncoding.EncodedLen(SessionMaxFrame) {
			return ErrInvalidSession
		}
		decoded, err := base64.StdEncoding.DecodeString(m.Payload)
		if err != nil || len(decoded) < 12 || len(decoded) > SessionMaxFrame || decoded[0]>>6 != 2 {
			return ErrInvalidSession
		}
		return nil
	case SessionResultType:
		if m.Version != 0 || m.Stage != "" || m.Cause != "" || m.RequestID == "" || m.Sequence < 1 || !m.OK && m.ErrorCode == "" {
			return ErrInvalidSession
		}
		return nil
	case SessionErrorType:
		if m.Version != 0 || m.Stage != "" || m.Cause != "" || m.ErrorCode == "" || len(m.ErrorCode) > 64 || strings.ContainsAny(m.ErrorCode, "\r\n\x00") {
			return ErrInvalidSession
		}
		return nil
	case SessionClosedType:
		if m.Version != 0 || m.Stage != "" || m.Cause != "" {
			return ErrInvalidSession
		}
		return nil
	case SessionTerminalType:
		record := sessiontermination.Record{Stage: m.Stage, Cause: m.Cause}
		if protocol != SessionProtocolV2ID || m.Version != SessionTerminalVersion || !record.Valid() ||
			m.RequestID != "" || m.Sequence != 0 || m.Timestamp != 0 || m.Payload != "" || m.OK || m.ErrorCode != "" || m.Text != "" {
			return ErrInvalidSession
		}
		return nil
	default:
		return ErrInvalidSession
	}
}

func (m SessionMessage) validateRequest() error {
	if m.RequestID == "" || m.Sequence != 0 || m.Timestamp != 0 || m.Payload != "" || !m.OK {
		return ErrInvalidSession
	}
	return nil
}

// SessionCommand is sent after SessionOpen. It deliberately reuses the
// closed desktopmedia command shape but is parsed with duplicate-key checks.
type SessionCommand struct {
	Protocol  string                      `json:"protocol"`
	Type      string                      `json:"type"`
	RequestID string                      `json:"request_id"`
	Sequence  int64                       `json:"sequence"`
	Input     *desktopmedia.Input         `json:"input,omitempty"`
	Display   *desktopmedia.DisplayPolicy `json:"display,omitempty"`
}

func (c SessionCommand) Validate(policy desktopmedia.MediaPolicy, previous int64) error {
	return c.ValidateFor(policy, previous, SessionProtocolID)
}

func (c SessionCommand) ValidateFor(policy desktopmedia.MediaPolicy, previous int64, protocol string) error {
	if c.Protocol != protocol || !sessionIdentifierPattern.MatchString(c.Type) || !requestIDPattern.MatchString(c.RequestID) || c.Sequence <= previous || c.Sequence > 1<<53-1 {
		return ErrInvalidSession
	}
	switch c.Type {
	case "input":
		// The broker command sequence is transport-local and restarts for each
		// executor session. Input.Sequence is the controller event identity and
		// may continue across a reconnect; binding the two makes every resumed
		// session reject its first non-one input event.
		if c.Input == nil || !desktopmedia.ValidInput(*c.Input, policy) {
			return ErrInvalidSession
		}
	case "stream.configure":
		if c.Display == nil || c.Display.Width != policy.Width || c.Display.Height != policy.Height || c.Display.MaxFPS != policy.MaxFPS {
			return ErrInvalidSession
		}
	case "stream.resync", "keyframe", "close":
		if c.Input != nil || c.Display != nil {
			return ErrInvalidSession
		}
	default:
		return ErrInvalidSession
	}
	return nil
}

var (
	ErrInvalidSession      = errors.New("invalid Desktop session")
	ErrSessionClosed       = errors.New("Desktop session is closed")
	ErrSessionBackpressure = errors.New("Desktop session media backpressure")
)

func encodeSession(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > SessionMaxDocument {
		return nil, ErrInvalidSession
	}
	return append(data, '\n'), nil
}

func EncodeSession(value any) ([]byte, error) { return encodeSession(value) }

func decodeSession(data []byte, value any) error {
	if len(data) == 0 || len(data) > SessionMaxDocument || data[len(data)-1] != '\n' {
		return ErrInvalidSession
	}
	body := data[:len(data)-1]
	duplicateDecoder := json.NewDecoder(bytes.NewReader(body))
	if err := scanUniqueJSON(duplicateDecoder); err != nil {
		return ErrInvalidSession
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalidSession
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidSession
	}
	return nil
}

func DecodeSession(data []byte, value any) error { return decodeSession(data, value) }

func scanUniqueJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	var scan func(json.Token) error
	scan = func(value json.Token) error {
		delimiter, ok := value.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidSession
				}
				if _, exists := seen[key]; exists {
					return ErrInvalidSession
				}
				seen[key] = struct{}{}
				valueToken, err := decoder.Token()
				if err != nil {
					return err
				}
				if err := scan(valueToken); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				valueToken, err := decoder.Token()
				if err != nil {
					return err
				}
				if err := scan(valueToken); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrInvalidSession
		}
	}
	if err := scan(token); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidSession
	}
	return nil
}

type sessionRuntime struct {
	open        SessionOpen
	conn        net.Conn
	writerMu    sync.Mutex
	closeOnce   sync.Once
	closed      chan struct{}
	frames      chan []byte
	process     *exec.Cmd
	udp         *net.UDPConn
	termination sessiontermination.First
}

func (s *sessionRuntime) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.udp != nil {
			_ = s.udp.Close()
		}
		if s.process != nil && s.process.Process != nil {
			_ = s.process.Process.Kill()
			_, _ = s.process.Process.Wait()
		}
	})
}

func (s *sessionRuntime) write(value SessionMessage, protocol ...string) error {
	messageProtocol := SessionProtocolID
	if len(protocol) == 1 {
		messageProtocol = protocol[0]
	}
	return s.writeBatch(messageProtocol, value)
}

func (s *sessionRuntime) writeBatch(protocol string, values ...SessionMessage) error {
	documents := make([][]byte, 0, len(values))
	for _, value := range values {
		if err := value.ValidateFor(protocol); err != nil {
			return err
		}
		data, err := encodeSession(value)
		if err != nil {
			return err
		}
		documents = append(documents, data)
	}
	s.writerMu.Lock()
	defer s.writerMu.Unlock()
	for _, document := range documents {
		written, err := s.conn.Write(document)
		if err != nil || written != len(document) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (s *sessionRuntime) terminalMessage(protocol string, stage sessiontermination.Stage, cause sessiontermination.Cause) (SessionMessage, bool) {
	if !s.termination.Observe(stage, cause) || protocol != SessionProtocolV2ID {
		return SessionMessage{}, false
	}
	return SessionMessage{Protocol: protocol, Version: SessionTerminalVersion, Type: SessionTerminalType, Stage: stage, Cause: cause}, true
}

func (s *sessionRuntime) publishTerminal(protocol string, stage sessiontermination.Stage, cause sessiontermination.Cause) {
	if message, ok := s.terminalMessage(protocol, stage, cause); ok && s.conn != nil {
		_ = s.writeBatch(protocol, message)
	}
}

func serveSession(ctx context.Context, connection net.Conn, open SessionOpen) error {
	return serveSessionProtocol(ctx, connection, open, SessionProtocolID)
}

func serveSessionV2(ctx context.Context, connection net.Conn, open SessionOpen) error {
	return serveSessionProtocol(ctx, connection, open, SessionProtocolV2ID)
}

func serveSessionProtocol(ctx context.Context, connection net.Conn, open SessionOpen, protocol string) error {
	if ctx == nil || connection == nil {
		return ErrInvalidSession
	}
	runtime, err := startSessionRuntime(ctx, connection, open)
	if err != nil {
		return err
	}
	defer func() {
		runtime.close()
		if record, ok := runtime.termination.Load(); ok {
			_, _ = fmt.Fprintf(os.Stderr, "desktop_broker_session_terminal %s\n", record.String())
		}
	}()
	expires, _ := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	sessionCtx, cancelSession := context.WithDeadline(ctx, expires)
	defer cancelSession()
	if err := runtime.write(SessionMessage{Protocol: protocol, Type: SessionAcceptedType, RequestID: open.RequestID, OK: true}, protocol); err != nil {
		runtime.termination.Observe(sessiontermination.StageMuxExec, sessiontermination.CauseTransportClosed)
		return err
	}
	reader := bufio.NewReaderSize(connection, SessionMaxDocument)
	commands := make(chan SessionCommand, open.MediaPolicy.MaxQueuedInputs)
	readErr := make(chan error, 1)
	go func() {
		for {
			line, readError := reader.ReadBytes('\n')
			if readError != nil {
				readErr <- readError
				return
			}
			var command SessionCommand
			if err := decodeSession(line, &command); err != nil {
				readErr <- err
				return
			}
			select {
			case commands <- command:
			case <-runtime.closed:
				return
			}
		}
	}()
	var previousSequence int64
	var frameSequence int64
	for {
		select {
		case <-sessionCtx.Done():
			cause := sessiontermination.CauseCallerCancel
			if errors.Is(sessionCtx.Err(), context.DeadlineExceeded) {
				cause = sessiontermination.CauseExpiry
			}
			runtime.publishTerminal(protocol, sessiontermination.StageBrokerRuntime, cause)
			return sessionCtx.Err()
		case <-runtime.closed:
			runtime.publishTerminal(protocol, sessiontermination.StageBrokerRuntime, sessiontermination.CauseRuntimeFailure)
			return ErrSessionClosed
		case err := <-readErr:
			return observeSessionReadError(runtime, protocol, err)
		case frame := <-runtime.frames:
			if len(frame) == 0 {
				runtime.publishTerminal(protocol, sessiontermination.StageMediaReader, sessiontermination.CauseRuntimeFailure)
				return ErrSessionClosed
			}
			payload := base64.StdEncoding.EncodeToString(frame)
			frameSequence++
			if err := runtime.write(SessionMessage{Protocol: protocol, Type: SessionFrameType, Sequence: frameSequence, Timestamp: time.Now().UnixNano(), Payload: payload}, protocol); err != nil {
				runtime.termination.Observe(sessiontermination.StageMuxExec, sessiontermination.CauseTransportClosed)
				return err
			}
		case command := <-commands:
			if err := command.ValidateFor(open.MediaPolicy, previousSequence, protocol); err != nil {
				runtime.publishTerminal(protocol, sessiontermination.StageInputWriter, sessiontermination.CauseProtocolViolation)
				return err
			}
			previousSequence = command.Sequence
			if command.Type == "close" {
				runtime.termination.Observe(sessiontermination.StageCloseOrdering, sessiontermination.CauseCleanClose)
				_ = runtime.write(SessionMessage{Protocol: protocol, Type: SessionClosedType}, protocol)
				return nil
			}
			if command.Type == "input" {
				if err := executeInput(sessionCtx, *command.Input, open.MediaPolicy); err != nil {
					result := SessionMessage{Protocol: protocol, Type: SessionResultType, RequestID: command.RequestID, Sequence: command.Sequence, ErrorCode: "input_rejected"}
					if terminal, ok := runtime.terminalMessage(protocol, sessiontermination.StageInputWriter, inputTerminationCause(err)); ok {
						_ = runtime.writeBatch(protocol, terminal, result)
						return err
					}
					_ = runtime.write(result, protocol)
					continue
				}
			}
			if err := runtime.write(SessionMessage{Protocol: protocol, Type: SessionResultType, RequestID: command.RequestID, Sequence: command.Sequence, OK: true}, protocol); err != nil {
				runtime.termination.Observe(sessiontermination.StageInputResultReader, sessiontermination.CauseTransportClosed)
				return err
			}
		}
	}
}

func observeSessionReadError(runtime *sessionRuntime, protocol string, err error) error {
	if errors.Is(err, io.EOF) {
		runtime.publishTerminal(protocol, sessiontermination.StageMuxExec, sessiontermination.CauseTransportClosed)
		return io.EOF
	}
	runtime.publishTerminal(protocol, sessiontermination.StageInputWriter, sessiontermination.CauseProtocolViolation)
	return err
}

func startSessionRuntime(ctx context.Context, connection net.Conn, open SessionOpen) (*sessionRuntime, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, ErrInvalidSession
	}
	args := []string{"-hide_banner", "-loglevel", "error", "-f", "x11grab", "-video_size", fmt.Sprintf("%dx%d", open.MediaPolicy.Width, open.MediaPolicy.Height), "-framerate", fmt.Sprint(open.MediaPolicy.MaxFPS), "-draw_mouse", "1", "-i", DefaultDisplay, "-an", "-c:v", "libvpx", "-deadline", "realtime", "-cpu-used", "8", "-b:v", fmt.Sprintf("%dk", open.MediaPolicy.MaxVideoBitrateKbps), "-f", "rtp", fmt.Sprintf("rtp://127.0.0.1:%d?pkt_size=1200", udp.LocalAddr().(*net.UDPAddr).Port)}
	process := exec.CommandContext(ctx, "/usr/bin/ffmpeg", args...)
	process.Stdout = io.Discard
	process.Stderr = io.Discard
	if err := process.Start(); err != nil {
		_ = udp.Close()
		return nil, ErrInvalidSession
	}
	runtime := &sessionRuntime{open: open, conn: connection, closed: make(chan struct{}), frames: make(chan []byte, open.MediaPolicy.MaxQueuedFrames), process: process, udp: udp}
	go func() {
		buffer := make([]byte, SessionMaxFrame+1)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			read, _, readErr := udp.ReadFromUDP(buffer)
			if readErr != nil {
				if errors.Is(readErr, net.ErrClosed) {
					return
				}
				if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
					continue
				}
				return
			}
			if read < 12 || read > SessionMaxFrame || buffer[0]>>6 != 2 {
				continue
			}
			frame := append([]byte(nil), buffer[:read]...)
			select {
			case runtime.frames <- frame:
			default:
				runtime.publishTerminal(runtime.open.Protocol, sessiontermination.StageMediaReader, sessiontermination.CauseBackpressure)
				runtime.close()
				return
			}
		}
	}()
	return runtime, nil
}

func executeInput(ctx context.Context, input desktopmedia.Input, policy desktopmedia.MediaPolicy) error {
	return executeInputWithRunner(ctx, input, policy, runInputCommand)
}

func executeInputWithRunner(ctx context.Context, input desktopmedia.Input, policy desktopmedia.MediaPolicy, run func(context.Context, []string) error) error {
	if !desktopmedia.ValidInput(input, policy) {
		return ErrInvalidSession
	}
	var args []string
	switch input.Kind {
	case "pointer":
		// Process completion acknowledges that xdotool submitted the move to X.
		// --sync waits for a subsequent pointer movement and can therefore time
		// out when a reconnect legitimately repeats the current coordinates.
		args = []string{"mousemove", fmt.Sprint(input.X), fmt.Sprint(input.Y)}
		if input.Event == "down" {
			args = []string{"mousedown", fmt.Sprint(input.Button)}
		}
		if input.Event == "up" {
			args = []string{"mouseup", fmt.Sprint(input.Button)}
		}
		if input.Event == "wheel" {
			button := 4
			if input.DeltaY > 0 {
				button = 5
			}
			args = []string{"click", "--repeat", fmt.Sprint(min(abs(input.DeltaY), 32)), fmt.Sprint(button)}
		}
	case "keyboard":
		key := input.Key
		if key == "" {
			return ErrInvalidSession
		}
		for _, modifier := range input.Modifiers {
			key = modifier + "+" + key
		}
		if input.Event == "down" {
			args = []string{"keydown", key}
		} else {
			args = []string{"keyup", key}
		}
	default:
		return ErrInvalidSession
	}
	if run == nil {
		return ErrInvalidSession
	}
	commandCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := run(commandCtx, args); err != nil {
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(ErrInvalidSession, errInputTimeout)
		}
		if errors.Is(err, errInputNonzeroExit) {
			return errors.Join(ErrInvalidSession, errInputNonzeroExit)
		}
		return errors.Join(ErrInvalidSession, errInputStartFailure)
	}
	return nil
}

func runInputCommand(ctx context.Context, args []string) error {
	command := exec.CommandContext(ctx, "/usr/bin/xdotool", args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	err := command.Run()
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errInputTimeout
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return errInputNonzeroExit
	}
	return errInputStartFailure
}

var (
	errInputTimeout      = errors.New("Desktop input command timeout")
	errInputNonzeroExit  = errors.New("Desktop input command nonzero exit")
	errInputStartFailure = errors.New("Desktop input command start failure")
)

func inputTerminationCause(err error) sessiontermination.Cause {
	switch {
	case errors.Is(err, errInputTimeout):
		return sessiontermination.CauseInputTimeout
	case errors.Is(err, errInputNonzeroExit):
		return sessiontermination.CauseInputNonzeroExit
	default:
		return sessiontermination.CauseInputStartFailure
	}
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
