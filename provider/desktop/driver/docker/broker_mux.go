package docker

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
)

const (
	brokerMuxMaxSessions        = 256
	brokerTerminalDrainDeadline = 500 * time.Millisecond
)

var brokerMuxSocketPattern = regexp.MustCompile(`^desktop-broker-[0-9a-f]{32}\.sock$`)

// BrokerMuxAuthority revalidates the current durable Provider authority. The
// mux deliberately does not know how Provider stores session or tenant truth.
type BrokerMuxAuthority interface {
	Authorize(context.Context, desktopbroker.SessionOpen) error
	Probe(context.Context) (desktopbroker.SessionOpen, error)
}

type BrokerMuxOptions struct {
	SocketPath       string
	MaxSessions      int
	OperationTimeout time.Duration
	Authority        BrokerMuxAuthority
}

type brokerTerminalStream interface {
	io.ReadWriteCloser
	CloseWrite() error
	Terminal() <-chan sessiontermination.Record
}

// BrokerMux is the Provider-owned, host-side adapter between an opaque Unix
// capability and a fixed Docker exec into the already-owned Desktop runtime.
// It exposes neither a generic exec surface nor a backend/container ID.
type BrokerMux struct {
	driver    *Driver
	options   BrokerMuxOptions
	mu        sync.Mutex
	listener  *net.UnixListener
	clients   map[*net.UnixConn]struct{}
	active    int
	shutdown  bool
	clientsWG sync.WaitGroup
}

func NewBrokerMux(driver *Driver, options BrokerMuxOptions) (*BrokerMux, error) {
	if driver == nil || driver.engine == nil || driver.candidate == nil || driver.options.BridgeKeyID == "" || len(driver.options.BridgePublicKey) == 0 ||
		options.Authority == nil || !validBrokerMuxSocketPath(options.SocketPath) || options.MaxSessions < 1 || options.MaxSessions > brokerMuxMaxSessions ||
		options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 30*time.Second {
		return nil, ErrInvalidOptions
	}
	if err := validateBrokerMuxDirectory(filepath.Dir(options.SocketPath)); err != nil {
		return nil, err
	}
	return &BrokerMux{driver: driver, options: options, clients: make(map[*net.UnixConn]struct{})}, nil
}

func (m *BrokerMux) Startup(ctx context.Context) error {
	if m == nil || ctx == nil {
		return context.Canceled
	}
	listener, socketInfo, err := listenBrokerMux(m.options.SocketPath)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.shutdown || m.listener != nil {
		m.mu.Unlock()
		_ = listener.Close()
		removeBrokerMuxSocket(m.options.SocketPath, socketInfo)
		return ErrInvalidRuntime
	}
	m.listener = listener
	m.mu.Unlock()
	defer func() {
		_ = listener.Close()
		removeBrokerMuxSocket(m.options.SocketPath, socketInfo)
		m.mu.Lock()
		if m.listener == listener {
			m.listener = nil
		}
		m.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return acceptErr
		}
		if !peerIsCurrentUser(connection) || !m.acquire(connection) {
			_ = connection.Close()
			continue
		}
		m.clientsWG.Add(1)
		go func() {
			defer m.clientsWG.Done()
			defer m.release(connection)
			m.handle(ctx, connection)
		}()
	}
}

func (m *BrokerMux) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	m.shutdown = true
	listener := m.listener
	clients := make([]*net.UnixConn, 0, len(m.clients))
	for connection := range m.clients {
		clients = append(clients, connection)
	}
	m.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, connection := range clients {
		_ = connection.Close()
	}
	done := make(chan struct{})
	go func() { m.clientsWG.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *BrokerMux) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	operationCtx, cancel := context.WithTimeout(parent, m.options.OperationTimeout)
	defer cancel()
	_ = connection.SetReadDeadline(time.Now().Add(m.options.OperationTimeout))
	reader := bufio.NewReaderSize(connection, desktopbroker.SessionMaxDocument)
	document, err := reader.ReadBytes('\n')
	if err != nil || len(document) == 0 || len(document) > desktopbroker.SessionMaxDocument || reader.Buffered() != 0 {
		return
	}
	var open desktopbroker.SessionOpen
	if desktopbroker.DecodeSession(document, &open) == nil && open.Method == desktopbroker.SessionMethod {
		canonical, encodeErr := desktopbroker.EncodeSession(open)
		if encodeErr != nil || !bytes.Equal(canonical, document) {
			return
		}
		m.serveOpen(parent, operationCtx, connection, open)
		return
	}
	var request desktopbroker.Request
	if desktopbroker.DecodeSession(document, &request) != nil || request.Method != desktopbroker.BridgeProbeMethod {
		return
	}
	canonical, encodeErr := desktopbroker.EncodeSession(request)
	if encodeErr != nil || !bytes.Equal(canonical, document) {
		return
	}
	m.serveProbe(operationCtx, connection, request)
}

func (m *BrokerMux) serveOpen(parent, operationCtx context.Context, connection *net.UnixConn, open desktopbroker.SessionOpen) {
	now := time.Now().UTC()
	keys := map[string][]byte{m.driver.options.BridgeKeyID: m.driver.options.BridgePublicKey}
	verificationKeys := makeBridgeVerificationKeys(keys)
	if open.ValidateV2(now, verificationKeys) != nil || m.options.Authority.Authorize(operationCtx, open) != nil {
		return
	}
	stream, err := m.driver.openMuxSession(operationCtx, open)
	if err != nil {
		return
	}
	defer stream.Close()
	if m.options.Authority.Authorize(operationCtx, open) != nil {
		return
	}
	document, err := desktopbroker.EncodeSession(open)
	if err != nil || writeFull(stream, document) != nil {
		return
	}
	streamReader := bufio.NewReaderSize(stream, desktopbroker.SessionMaxDocument)
	accepted, acceptedDocument, err := readMuxMessage(streamReader)
	if err != nil || accepted.Type != desktopbroker.SessionAcceptedType || accepted.RequestID != open.RequestID || writeFull(connection, acceptedDocument) != nil {
		return
	}
	expires, _ := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	sessionCtx, cancel := context.WithDeadline(parent, expires)
	defer cancel()
	stop := context.AfterFunc(sessionCtx, func() {
		_ = connection.Close()
		_ = stream.Close()
	})
	defer stop()
	_ = connection.SetDeadline(expires)
	results := make(chan muxDirectionResult, 2)
	go func() {
		results <- muxDirectionResult{commands: true, err: proxyMuxCommands(sessionCtx, bufio.NewReaderSize(connection, desktopbroker.SessionMaxDocument), stream, open)}
	}()
	go func() { results <- muxDirectionResult{err: proxyMuxMessages(sessionCtx, streamReader, connection)} }()
	var termination sessiontermination.First
	first := <-results
	if first.commands && errors.Is(first.err, errMuxCloseRequested) {
		select {
		case second := <-results:
			record := muxTerminationRecord(second)
			termination.Observe(record.Stage, record.Cause)
		case <-sessionCtx.Done():
			record := sessiontermination.FromError(sessionCtx.Err(), sessiontermination.StageCloseOrdering, sessiontermination.CauseTransportClosed)
			termination.Observe(record.Stage, record.Cause)
		}
	} else {
		record := muxTerminationRecord(first)
		var peerConsumed bool
		record, peerConsumed = arbitrateMuxTermination(sessionCtx, m.options.OperationTimeout, record, results, stream)
		termination.Observe(record.Stage, record.Cause)
		cancel()
		_ = connection.Close()
		_ = stream.Close()
		if !peerConsumed {
			<-results
		}
	}
	if record, ok := termination.Load(); ok {
		log.Printf("desktop_provider_mux_session_terminal %s", record.String())
	}
}

func arbitrateMuxTermination(ctx context.Context, operationTimeout time.Duration, first sessiontermination.Record, results <-chan muxDirectionResult, stream io.ReadWriteCloser) (sessiontermination.Record, bool) {
	reporter, ok := stream.(brokerTerminalStream)
	if first.Cause != sessiontermination.CauseTransportClosed || ctx == nil {
		return first, false
	}
	if ctx.Err() != nil {
		policy := sessiontermination.FromError(ctx.Err(), sessiontermination.StageCloseOrdering, sessiontermination.CauseTransportClosed)
		if muxTerminationPriority(policy) > muxTerminationPriority(first) {
			return policy, false
		}
		return first, false
	}
	limit := brokerTerminalDrainDeadline
	if operationTimeout < limit {
		limit = operationTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return first, false
		}
		if remaining < limit {
			limit = remaining
		}
	}
	if limit <= 0 {
		return first, false
	}
	var terminal <-chan sessiontermination.Record
	if ok {
		_ = reporter.CloseWrite()
		terminal = reporter.Terminal()
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case result := <-results:
		best := strongerMuxTermination(first, muxTerminationRecord(result))
		if ctx.Err() != nil {
			best = strongerMuxTermination(best, sessiontermination.FromError(ctx.Err(), sessiontermination.StageCloseOrdering, sessiontermination.CauseTransportClosed))
		}
		select {
		case record := <-terminal:
			best = strongerMuxTermination(best, record)
		default:
		}
		return best, true
	case record := <-terminal:
		best := strongerMuxTermination(first, record)
		if ctx.Err() != nil {
			best = strongerMuxTermination(best, sessiontermination.FromError(ctx.Err(), sessiontermination.StageCloseOrdering, sessiontermination.CauseTransportClosed))
		}
		select {
		case result := <-results:
			best = strongerMuxTermination(best, muxTerminationRecord(result))
			return best, true
		default:
		}
		return best, false
	case <-ctx.Done():
		best := strongerMuxTermination(first, sessiontermination.FromError(ctx.Err(), sessiontermination.StageCloseOrdering, sessiontermination.CauseTransportClosed))
		consumed := false
		select {
		case result := <-results:
			best = strongerMuxTermination(best, muxTerminationRecord(result))
			consumed = true
		default:
		}
		select {
		case record := <-terminal:
			best = strongerMuxTermination(best, record)
		default:
		}
		return best, consumed
	case <-timer.C:
		best := first
		consumed := false
		if ctx.Err() != nil {
			best = strongerMuxTermination(best, sessiontermination.FromError(ctx.Err(), sessiontermination.StageCloseOrdering, sessiontermination.CauseTransportClosed))
		}
		select {
		case result := <-results:
			best = strongerMuxTermination(best, muxTerminationRecord(result))
			consumed = true
		default:
		}
		select {
		case record := <-terminal:
			best = strongerMuxTermination(best, record)
		default:
		}
		return best, consumed
	}
}

func strongerMuxTermination(current, candidate sessiontermination.Record) sessiontermination.Record {
	if candidate.Valid() && muxTerminationPriority(candidate) > muxTerminationPriority(current) {
		return candidate
	}
	return current
}

func muxTerminationPriority(record sessiontermination.Record) int {
	if !record.Valid() {
		return -1
	}
	switch record.Cause {
	case sessiontermination.CauseExpiry, sessiontermination.CauseAuthorityDrift, sessiontermination.CauseAuthorityUnavailable:
		return 5
	case sessiontermination.CauseInputTimeout, sessiontermination.CauseInputNonzeroExit, sessiontermination.CauseInputStartFailure:
		return 4
	case sessiontermination.CauseBackpressure, sessiontermination.CauseProtocolViolation, sessiontermination.CauseRuntimeFailure,
		sessiontermination.CauseCapacity, sessiontermination.CauseReplay, sessiontermination.CauseBrokerUnavailable:
		return 3
	case sessiontermination.CauseCallerCancel:
		return 2
	case sessiontermination.CauseTransportClosed:
		return 1
	case sessiontermination.CauseCleanClose:
		return 0
	default:
		return -1
	}
}

func muxTerminationRecord(result muxDirectionResult) sessiontermination.Record {
	stage := sessiontermination.StageMuxExec
	if result.commands {
		stage = sessiontermination.StageInputWriter
	}
	if result.err == nil || errors.Is(result.err, errMuxCloseRequested) {
		return sessiontermination.Record{Stage: sessiontermination.StageCloseOrdering, Cause: sessiontermination.CauseCleanClose}
	}
	if errors.Is(result.err, desktopbroker.ErrInvalidSession) {
		return sessiontermination.Record{Stage: stage, Cause: sessiontermination.CauseProtocolViolation}
	}
	return sessiontermination.FromError(result.err, stage, sessiontermination.CauseTransportClosed)
}

func (m *BrokerMux) serveProbe(ctx context.Context, connection *net.UnixConn, request desktopbroker.Request) {
	open, err := m.options.Authority.Probe(ctx)
	if err != nil || open.ValidateV2(time.Now().UTC(), makeBridgeVerificationKeys(map[string][]byte{m.driver.options.BridgeKeyID: m.driver.options.BridgePublicKey})) != nil || m.options.Authority.Authorize(ctx, open) != nil {
		return
	}
	stream, err := m.driver.openMuxSession(ctx, open)
	if err != nil {
		return
	}
	defer stream.Close()
	if m.options.Authority.Authorize(ctx, open) != nil {
		return
	}
	document, _ := desktopbroker.EncodeSession(open)
	if writeFull(stream, document) != nil {
		return
	}
	reader := bufio.NewReaderSize(stream, desktopbroker.SessionMaxDocument)
	accepted, _, err := readMuxMessage(reader)
	if err != nil || accepted.Type != desktopbroker.SessionAcceptedType || accepted.RequestID != open.RequestID {
		return
	}
	closeCommand := desktopbroker.SessionCommand{Protocol: desktopbroker.SessionProtocolV2ID, Type: "close", RequestID: "broker-probe-close", Sequence: 1}
	closeDocument, _ := desktopbroker.EncodeSession(closeCommand)
	if writeFull(stream, closeDocument) != nil {
		return
	}
	closed := false
	for count := 0; count < desktopbroker.SessionMaxQueue+2; count++ {
		message, _, readErr := readMuxMessage(reader)
		if readErr != nil {
			return
		}
		if message.Type == desktopbroker.SessionClosedType {
			closed = true
			break
		}
	}
	if !closed {
		return
	}
	descriptor := desktopbroker.ReadyDescriptor()
	response, err := desktopbroker.EncodeSession(desktopbroker.Response{Protocol: desktopbroker.ProtocolID, RequestID: request.RequestID, Status: "ok", Descriptor: &descriptor})
	if err == nil {
		_ = writeFull(connection, response)
	}
}

func (d *Driver) openMuxSession(ctx context.Context, open desktopbroker.SessionOpen) (io.ReadWriteCloser, error) {
	if d == nil || d.candidate == nil || ctx == nil {
		return nil, ErrInvalidRuntime
	}
	_, statePath, err := d.stateLocation(open.SandboxID, open.DesktopSessionID)
	if err != nil {
		return nil, err
	}
	state, err := loadDesktopState(statePath, d.options.NetworkPolicyReference)
	handoffExpiry, expiryErr := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	if err != nil || expiryErr != nil || !state.Ready || state.Receipt.Reference != open.AllocationReference ||
		state.Receipt.ConnectionGeneration != open.ConnectionGeneration || !state.Receipt.ExpiresAt.Equal(handoffExpiry) ||
		state.Request.SandboxID != open.SandboxID || state.Request.DesktopSessionID != open.DesktopSessionID {
		return nil, ErrInvalidRuntime
	}
	info, found, err := d.inspectOwned(ctx, state)
	if err != nil || !found || !info.running || info.paused || info.restarting || info.dead {
		return nil, ErrInvalidRuntime
	}
	backend, ok := d.engine.(sessionEngine)
	if !ok {
		return nil, ErrInvalidRuntime
	}
	return backend.openSession(ctx, info.id)
}

type muxDirectionResult struct {
	commands bool
	err      error
}

var errMuxCloseRequested = errors.New("Desktop mux close requested")

func proxyMuxCommands(ctx context.Context, reader *bufio.Reader, stream io.Writer, open desktopbroker.SessionOpen) error {
	var previous int64
	for {
		document, err := reader.ReadBytes('\n')
		if err != nil {
			return err
		}
		var command desktopbroker.SessionCommand
		if desktopbroker.DecodeSession(document, &command) != nil || command.ValidateFor(open.MediaPolicy, previous, desktopbroker.SessionProtocolV2ID) != nil {
			return desktopbroker.ErrInvalidSession
		}
		canonical, encodeErr := desktopbroker.EncodeSession(command)
		if encodeErr != nil || !bytes.Equal(canonical, document) || writeFull(stream, document) != nil {
			return desktopbroker.ErrInvalidSession
		}
		previous = command.Sequence
		if command.Type == "close" {
			return errMuxCloseRequested
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func proxyMuxMessages(ctx context.Context, reader *bufio.Reader, connection io.Writer) error {
	var terminal *sessiontermination.Record
	for {
		message, document, err := readMuxMessage(reader)
		if err != nil {
			if terminal != nil && errors.Is(err, io.EOF) {
				return sessiontermination.Error{Record: *terminal}
			}
			return err
		}
		if message.Type == desktopbroker.SessionTerminalType {
			if terminal != nil {
				return desktopbroker.ErrInvalidSession
			}
			record := sessiontermination.Record{Stage: message.Stage, Cause: message.Cause}
			if !record.Valid() {
				return desktopbroker.ErrInvalidSession
			}
			terminal = &record
			continue
		}
		if terminal != nil {
			if message.Type != desktopbroker.SessionResultType || message.OK || message.ErrorCode != "input_rejected" {
				return desktopbroker.ErrInvalidSession
			}
			if writeFull(connection, document) != nil {
				return sessiontermination.Error{Record: *terminal}
			}
			return sessiontermination.Error{Record: *terminal}
		}
		if message.Type == desktopbroker.SessionAcceptedType {
			return desktopbroker.ErrInvalidSession
		}
		if message.Type == desktopbroker.SessionResultType && !message.OK && message.ErrorCode == "input_rejected" {
			return desktopbroker.ErrInvalidSession
		}
		if writeFull(connection, document) != nil {
			return io.ErrClosedPipe
		}
		if message.Type == desktopbroker.SessionClosedType {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func readMuxMessage(reader *bufio.Reader) (desktopbroker.SessionMessage, []byte, error) {
	document, err := reader.ReadBytes('\n')
	if err != nil || len(document) > desktopbroker.SessionMaxDocument {
		return desktopbroker.SessionMessage{}, nil, err
	}
	var message desktopbroker.SessionMessage
	if desktopbroker.DecodeSession(document, &message) != nil || message.ValidateFor(desktopbroker.SessionProtocolV2ID) != nil {
		return desktopbroker.SessionMessage{}, nil, desktopbroker.ErrInvalidSession
	}
	canonical, err := desktopbroker.EncodeSession(message)
	if err != nil || !bytes.Equal(canonical, document) {
		return desktopbroker.SessionMessage{}, nil, desktopbroker.ErrInvalidSession
	}
	return message, document, nil
}

func writeFull(writer io.Writer, document []byte) error {
	written, err := writer.Write(document)
	if err != nil || written != len(document) {
		return io.ErrShortWrite
	}
	return nil
}

func (m *BrokerMux) acquire(connection *net.UnixConn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shutdown || m.active >= m.options.MaxSessions {
		return false
	}
	m.active++
	m.clients[connection] = struct{}{}
	return true
}

func (m *BrokerMux) release(connection *net.UnixConn) {
	m.mu.Lock()
	delete(m.clients, connection)
	if m.active > 0 {
		m.active--
	}
	m.mu.Unlock()
}

func validBrokerMuxSocketPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && brokerMuxSocketPattern.MatchString(filepath.Base(path))
}

func validateBrokerMuxDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentProcess(info) {
		return ErrInvalidOptions
	}
	return nil
}

func listenBrokerMux(path string) (*net.UnixListener, os.FileInfo, error) {
	if !validBrokerMuxSocketPath(path) || validateBrokerMuxDirectory(filepath.Dir(path)) != nil {
		return nil, nil, ErrInvalidOptions
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !ownedByCurrentProcess(info) {
			return nil, nil, ErrInvalidRuntime
		}
		connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, nil, ErrOwnershipConflict
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, nil, ErrInvalidRuntime
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*net.UnixListener, os.FileInfo, error) {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fail(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !ownedByCurrentProcess(info) {
		return fail(ErrInvalidRuntime)
	}
	return listener, info, nil
}

func removeBrokerMuxSocket(path string, original os.FileInfo) {
	current, err := os.Lstat(path)
	if err == nil && original != nil && os.SameFile(original, current) {
		_ = os.Remove(path)
	}
}

func ownedByCurrentProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(stat.Uid) == uint32(os.Getuid())
}
