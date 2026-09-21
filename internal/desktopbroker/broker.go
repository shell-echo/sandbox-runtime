// Package desktopbroker implements the private in-sandbox Desktop display
// supervisor and its bounded Unix-socket observation protocol. The protocol is
// not a public Gateway and carries neither end-user authorization nor media.
package desktopbroker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	ProtocolID        = "sandbox.runtime/desktop-broker/v1"
	RuntimeProfileID  = "sandbox-runtime-desktop-v1"
	MediaProfileID    = "desktop-media-v1"
	ControlProfileID  = "desktop-control-v1"
	DefaultSocketPath = "/tmp/sandbox-runtime-desktop-broker.sock"
	DefaultDisplay    = ":99"
	DisplayReference  = "ref:desktop-display:primary"
	ScreenWidth       = 1280
	ScreenHeight      = 720
	ScreenDepth       = 24
	MaxRequestBytes   = 4 << 10
	MaxResponseBytes  = 8 << 10
	MaxConnections    = 16
	ReplayLedgerPath  = "/tmp/desktop-runtime/desktop-bridge-replay-v2.json"
	BridgeProbeMethod = "probe.v2"

	acceptPollInterval  = 200 * time.Millisecond
	requestTimeout      = 2 * time.Second
	displayReadyTimeout = 10 * time.Second
	processStopTimeout  = 2 * time.Second
)

var (
	ErrInvalidArguments = errors.New("invalid desktop broker arguments")
	ErrInvalidRequest   = errors.New("invalid desktop broker request")
	ErrUnavailable      = errors.New("desktop broker is unavailable")
	ErrAlreadyRunning   = errors.New("desktop broker is already running")
	ErrDisplayExited    = errors.New("desktop display process exited")

	socketPattern    = regexp.MustCompile(`^/tmp/sandbox-runtime-desktop(?:-broker|-[0-9a-f]{32})\.sock$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type Request struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
}

func (r Request) Validate() error {
	if r.Protocol != ProtocolID || !requestIDPattern.MatchString(r.RequestID) {
		return ErrInvalidRequest
	}
	switch r.Method {
	case "probe", "describe", BridgeProbeMethod:
		return nil
	default:
		return ErrInvalidRequest
	}
}

type Descriptor struct {
	State             string   `json:"state"`
	RuntimeProfileID  string   `json:"runtime_profile_id"`
	MediaProfileID    string   `json:"media_profile_id"`
	ControlProfileID  string   `json:"control_profile_id"`
	DisplayReference  string   `json:"display_reference"`
	Width             int      `json:"width"`
	Height            int      `json:"height"`
	Depth             int      `json:"depth"`
	AudioOutput       bool     `json:"audio_output"`
	PrivateInputModes []string `json:"private_input_modes"`
}

func ReadyDescriptor() Descriptor {
	return Descriptor{
		State: "ready", RuntimeProfileID: RuntimeProfileID,
		MediaProfileID: MediaProfileID, ControlProfileID: ControlProfileID,
		DisplayReference: DisplayReference, Width: ScreenWidth,
		Height: ScreenHeight, Depth: ScreenDepth, AudioOutput: false,
		PrivateInputModes: []string{"keyboard", "pointer"},
	}
}

func (d Descriptor) Validate() error {
	want := ReadyDescriptor()
	if d.State != want.State || d.RuntimeProfileID != want.RuntimeProfileID ||
		d.MediaProfileID != want.MediaProfileID || d.ControlProfileID != want.ControlProfileID ||
		d.DisplayReference != want.DisplayReference || d.Width != want.Width ||
		d.Height != want.Height || d.Depth != want.Depth || d.AudioOutput != want.AudioOutput ||
		len(d.PrivateInputModes) != len(want.PrivateInputModes) {
		return ErrInvalidRequest
	}
	for index := range want.PrivateInputModes {
		if d.PrivateInputModes[index] != want.PrivateInputModes[index] {
			return ErrInvalidRequest
		}
	}
	return nil
}

type Response struct {
	Protocol   string      `json:"protocol"`
	RequestID  string      `json:"request_id"`
	Status     string      `json:"status"`
	ErrorCode  string      `json:"error_code,omitempty"`
	Descriptor *Descriptor `json:"descriptor,omitempty"`
}

func (r Response) Validate() error {
	if r.Protocol != ProtocolID || !requestIDPattern.MatchString(r.RequestID) {
		return ErrInvalidRequest
	}
	switch r.Status {
	case "ok":
		if r.ErrorCode != "" || r.Descriptor == nil {
			return ErrInvalidRequest
		}
		return r.Descriptor.Validate()
	case "error":
		if r.ErrorCode != "invalid_request" || r.Descriptor != nil {
			return ErrInvalidRequest
		}
		return nil
	default:
		return ErrInvalidRequest
	}
}

func connectSession(ctx context.Context, socketPath string, input io.Reader, output io.Writer) error {
	if ctx == nil || !socketPattern.MatchString(socketPath) || input == nil || output == nil {
		return ErrInvalidArguments
	}
	connectionValue, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return ErrUnavailable
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return ErrUnavailable
	}
	defer connection.Close()
	result := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(connection, io.LimitReader(input, 1<<30))
		_ = connection.CloseWrite()
		_ = copyErr
	}()
	go func() {
		_, copyErr := io.Copy(output, connection)
		result <- copyErr
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		return err
	}
}

// Run executes one broker subcommand without accepting executable, display,
// geometry, or workspace overrides.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if ctx == nil {
		return context.Canceled
	}
	if len(args) == 0 || stdout == nil || stderr == nil {
		return ErrInvalidArguments
	}
	switch args[0] {
	case "serve":
		if len(args) != 1 {
			return ErrInvalidArguments
		}
		return Serve(ctx, stderr)
	case "probe", "describe":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		socketPath := flags.String("socket", DefaultSocketPath, "private broker socket")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return ErrInvalidArguments
		}
		response, err := request(ctx, *socketPath, args[0])
		if err != nil {
			return err
		}
		if args[0] == "describe" {
			encoder := json.NewEncoder(stdout)
			encoder.SetEscapeHTML(false)
			return encoder.Encode(response)
		}
		return nil
	case "session":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		socketPath := flags.String("socket", DefaultSocketPath, "private broker socket")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return ErrInvalidArguments
		}
		return connectSession(ctx, *socketPath, os.Stdin, stdout)
	default:
		return ErrInvalidArguments
	}
}

// Serve owns one fixed Xvfb/Openbox display and exposes observation only over
// the fixed private Unix socket. Runtime cleanup terminates the container; the
// broker protocol deliberately has no remote stop or arbitrary process method.
func Serve(ctx context.Context, stderr io.Writer) error {
	return serve(ctx, stderr, nil)
}

// ServeWithBridge starts the broker with pinned Provider bridge verification
// keys. The legacy Serve path intentionally has no v2 authority and therefore
// cannot admit executor.v2 sessions.
func ServeWithBridge(ctx context.Context, stderr io.Writer, keys map[string]ed25519.PublicKey) error {
	if len(keys) == 0 {
		return ErrInvalidArguments
	}
	return serve(ctx, stderr, keys)
}

func serve(ctx context.Context, stderr io.Writer, keys map[string]ed25519.PublicKey) error {
	if ctx == nil {
		return context.Canceled
	}
	desktop, err := startDesktop(ctx, stderr)
	if err != nil {
		return err
	}
	defer desktop.stop()
	return serveProtocolWithBridge(ctx, DefaultSocketPath, ReadyDescriptor(), desktop.critical, keys)
}

type desktopProcesses struct {
	commands []*exec.Cmd
	critical <-chan error
	done     []<-chan error
}

func startDesktop(ctx context.Context, stderr io.Writer) (*desktopProcesses, error) {
	environment := append(os.Environ(),
		"DISPLAY="+DefaultDisplay,
		"HOME=/tmp/desktop-home",
		"XDG_CACHE_HOME=/tmp/desktop-cache",
		"XDG_CONFIG_HOME=/tmp/desktop-config",
		"XDG_RUNTIME_DIR=/tmp/desktop-runtime",
	)
	for _, path := range []string{"/tmp/desktop-home", "/tmp/desktop-cache", "/tmp/desktop-config", "/tmp/desktop-runtime"} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("prepare desktop runtime directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, fmt.Errorf("protect desktop runtime directory: %w", err)
		}
	}
	if err := os.MkdirAll("/tmp/.X11-unix", 0o1777); err != nil {
		return nil, fmt.Errorf("prepare X11 socket directory: %w", err)
	}
	if err := os.Chmod("/tmp/.X11-unix", 0o1777); err != nil {
		return nil, fmt.Errorf("protect X11 socket directory: %w", err)
	}

	critical := make(chan error, 2)
	result := &desktopProcesses{critical: critical}
	start := func(path string, args []string, criticalProcess bool) error {
		command := exec.Command(path, args...)
		command.Env = environment
		command.Stdout = stderr
		command.Stderr = stderr
		if err := command.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() {
			err := command.Wait()
			done <- err
			if criticalProcess {
				select {
				case critical <- err:
				default:
				}
			}
		}()
		result.commands = append(result.commands, command)
		result.done = append(result.done, done)
		return nil
	}

	if err := start("/usr/bin/Xvfb", []string{DefaultDisplay, "-screen", "0", "1280x720x24", "-nolisten", "tcp", "-noreset", "-ac"}, true); err != nil {
		return nil, fmt.Errorf("start desktop display: %w", err)
	}
	if err := waitForDisplay(ctx, critical, environment); err != nil {
		result.stop()
		return nil, err
	}
	if err := start("/usr/bin/openbox", []string{"--sm-disable"}, true); err != nil {
		result.stop()
		return nil, fmt.Errorf("start desktop window manager: %w", err)
	}
	if err := start("/usr/bin/xterm", []string{"-geometry", "100x30+20+20", "-title", "Sandbox Desktop", "-e", "/bin/sh", "-c", "cd /workspace && exec /bin/sh"}, false); err != nil {
		result.stop()
		return nil, fmt.Errorf("start desktop terminal: %w", err)
	}
	return result, nil
}

func waitForDisplay(ctx context.Context, critical <-chan error, environment []string) error {
	deadline := time.NewTimer(displayReadyTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrUnavailable
		case <-critical:
			return ErrDisplayExited
		case <-ticker.C:
			info, err := os.Lstat("/tmp/.X11-unix/X99")
			if err == nil && info.Mode()&os.ModeSocket != 0 {
				probeContext, cancel := context.WithTimeout(ctx, time.Second)
				probe := exec.CommandContext(probeContext, "/usr/bin/xdpyinfo", "-display", DefaultDisplay)
				probe.Env = environment
				probeErr := probe.Run()
				cancel()
				if probeErr == nil {
					return nil
				}
			}
		}
	}
}

func (p *desktopProcesses) stop() {
	if p == nil {
		return
	}
	for index := len(p.commands) - 1; index >= 0; index-- {
		command := p.commands[index]
		if command != nil && command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
		}
	}
	deadline := time.NewTimer(processStopTimeout)
	defer deadline.Stop()
	for index, done := range p.done {
		select {
		case <-done:
		case <-deadline.C:
			for _, command := range p.commands[index:] {
				if command != nil && command.Process != nil {
					_ = command.Process.Kill()
				}
			}
			return
		}
	}
}

func serveProtocol(ctx context.Context, socketPath string, descriptor Descriptor, critical <-chan error) error {
	return serveProtocolWithBridge(ctx, socketPath, descriptor, critical, nil)
}

func serveProtocolWithBridge(ctx context.Context, socketPath string, descriptor Descriptor, critical <-chan error, keys map[string]ed25519.PublicKey) error {
	return serveProtocolWithBridgeLedger(ctx, socketPath, descriptor, critical, keys, ReplayLedgerPath)
}

func serveProtocolWithBridgeLedger(ctx context.Context, socketPath string, descriptor Descriptor, critical <-chan error, keys map[string]ed25519.PublicKey, replayPath string) error {
	if ctx == nil || !socketPattern.MatchString(socketPath) || descriptor.Validate() != nil {
		return ErrInvalidArguments
	}
	listener, err := listen(socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	semaphore := make(chan struct{}, MaxConnections)
	var replay *bridgeReplayLedger
	if keys != nil {
		replay, err = newBridgeReplayLedger(replayPath, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("open Desktop bridge replay ledger: %w", err)
		}
	}
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-critical:
			return ErrDisplayExited
		default:
		}
		if err := listener.SetDeadline(time.Now().Add(acceptPollInterval)); err != nil {
			return fmt.Errorf("set desktop broker accept deadline: %w", err)
		}
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			var networkError net.Error
			if errors.As(acceptErr, &networkError) && networkError.Timeout() {
				continue
			}
			if errors.Is(acceptErr, net.ErrClosed) && ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept desktop broker connection: %w", acceptErr)
		}
		select {
		case semaphore <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-semaphore }()
				handle(ctx, connection, descriptor, keys, replay)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func handle(ctx context.Context, connection *net.UnixConn, descriptor Descriptor, keys map[string]ed25519.PublicKey, replay *bridgeReplayLedger) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(requestTimeout))
	reader := bufio.NewReaderSize(connection, SessionMaxDocument)
	data, err := reader.ReadBytes('\n')
	if errors.Is(err, io.EOF) && len(data) > 0 {
		err = nil
	}
	if err != nil || len(data) == 0 || len(data) > SessionMaxDocument {
		return
	}
	if !bytes.HasSuffix(data, []byte{'\n'}) && len(data) > MaxRequestBytes {
		return
	}
	var sessionOpen SessionOpen
	if decodeSession(data, &sessionOpen) == nil && sessionOpen.Method == SessionMethod && sessionOpen.Protocol == SessionProtocolID {
		_ = connection.SetDeadline(time.Time{})
		_ = serveSession(ctx, &bufferedConn{UnixConn: connection, reader: reader}, sessionOpen)
		return
	}
	if decodeSession(data, &sessionOpen) == nil && sessionOpen.Method == SessionMethod && sessionOpen.Protocol == SessionProtocolV2ID && keys != nil && replay != nil {
		if sessionOpen.ValidateV2(time.Now().UTC(), keys) != nil || !replay.claim(sessionOpen.Bridge) {
			return
		}
		_ = connection.SetDeadline(time.Time{})
		_ = serveSessionV2(ctx, &bufferedConn{UnixConn: connection, reader: reader}, sessionOpen)
		return
	}
	// Probe/describe are still one-shot bounded requests. Reject any trailing
	// bytes after the first object so the legacy protocol remains closed.
	if reader.Buffered() != 0 {
		return
	}
	data = bytes.TrimSpace(data)
	requestValue, err := parseRequest(data)
	if err != nil {
		requestID := "invalid-request"
		var partial struct {
			RequestID string `json:"request_id"`
		}
		if json.Unmarshal(data, &partial) == nil && requestIDPattern.MatchString(partial.RequestID) {
			requestID = partial.RequestID
		}
		_ = writeResponse(connection, Response{Protocol: ProtocolID, RequestID: requestID, Status: "error", ErrorCode: "invalid_request"})
		return
	}
	if requestValue.Method == BridgeProbeMethod && len(keys) == 0 {
		_ = writeResponse(connection, Response{Protocol: ProtocolID, RequestID: requestValue.RequestID, Status: "error", ErrorCode: "invalid_request"})
		return
	}
	response := Response{Protocol: ProtocolID, RequestID: requestValue.RequestID, Status: "ok", Descriptor: &descriptor}
	_ = writeResponse(connection, response)
}

// bufferedConn preserves bytes already read by the session discriminator.
type bufferedConn struct {
	*net.UnixConn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(value []byte) (int, error) { return c.reader.Read(value) }

func parseRequest(data []byte) (Request, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var requestValue Request
	if err := decoder.Decode(&requestValue); err != nil {
		return Request{}, ErrInvalidRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil || !errors.Is(err, io.EOF) {
		return Request{}, ErrInvalidRequest
	}
	if err := requestValue.Validate(); err != nil {
		return Request{}, err
	}
	return requestValue, nil
}

func writeResponse(writer io.Writer, response Response) error {
	if err := response.Validate(); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}

func request(ctx context.Context, socketPath, method string) (Response, error) {
	if ctx == nil {
		return Response{}, context.Canceled
	}
	requestValue := Request{Protocol: ProtocolID, RequestID: "client-" + strconv.Itoa(os.Getpid()), Method: method}
	if !socketPattern.MatchString(socketPath) || requestValue.Validate() != nil {
		return Response{}, ErrInvalidArguments
	}
	dialer := net.Dialer{}
	connectionValue, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, ErrUnavailable
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return Response{}, ErrUnavailable
	}
	defer connection.Close()
	deadline := time.Now().Add(requestTimeout)
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if err := json.NewEncoder(connection).Encode(requestValue); err != nil {
		return Response{}, ErrUnavailable
	}
	if err := connection.CloseWrite(); err != nil {
		return Response{}, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(connection, MaxResponseBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxResponseBytes {
		return Response{}, ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return Response{}, ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil || !errors.Is(err, io.EOF) {
		return Response{}, ErrUnavailable
	}
	if response.Validate() != nil || response.RequestID != requestValue.RequestID || response.Status != "ok" {
		return Response{}, ErrUnavailable
	}
	return response, nil
}

func listen(socketPath string) (*net.UnixListener, error) {
	if !socketPattern.MatchString(socketPath) || filepath.Dir(socketPath) != "/tmp" {
		return nil, ErrInvalidArguments
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, ErrUnavailable
		}
		probeContext, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, probeErr := request(probeContext, socketPath, "probe")
		cancel()
		if probeErr == nil {
			return nil, ErrAlreadyRunning
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	address := &net.UnixAddr{Name: socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, ErrUnavailable
	}
	return listener, nil
}
