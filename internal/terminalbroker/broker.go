// Package terminalbroker implements the private in-sandbox terminal broker.
// It owns one PTY and shell while allowing sequential clients to reconnect over
// a bounded Unix socket protocol.
package terminalbroker

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

const (
	dataHandshake  = "SRTERM1 DATA\n"
	probeHandshake = "SRTERM1 PROBE\n"
	stopHandshake  = "SRTERM1 STOP\n"
	okResponse     = "SRTERM1 OK\n"

	acceptPollInterval = 200 * time.Millisecond
	handshakeTimeout   = 2 * time.Second
	clientWriteTimeout = 5 * time.Second
	shutdownTimeout    = 2 * time.Second
)

var (
	ErrInvalidArguments = errors.New("invalid terminal broker arguments")
	ErrAlreadyRunning   = errors.New("terminal broker is already running")
	ErrUnavailable      = errors.New("terminal broker is unavailable")

	socketPattern           = regexp.MustCompile(`^/tmp/sandbox-runtime-terminal-[0-9a-f]{32}\.sock$`)
	shellPattern            = regexp.MustCompile(`^/(bin|usr/bin|usr/local/bin)/[A-Za-z0-9._-]+$`)
	workingDirectoryPattern = regexp.MustCompile(`^/(workspace|tmp)(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
)

// Run executes one broker subcommand without binding the implementation to a
// particular CLI framework.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if ctx == nil {
		return context.Canceled
	}
	if len(args) == 0 {
		return ErrInvalidArguments
	}
	switch args[0] {
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(stderr)
		socket := flags.String("socket", "", "private broker socket")
		shell := flags.String("shell", "", "shell executable")
		workingDirectory := flags.String("working-directory", "", "shell working directory")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return ErrInvalidArguments
		}
		return Serve(ctx, *socket, *shell, *workingDirectory)
	case "connect", "probe", "stop":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		socket := flags.String("socket", "", "private broker socket")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return ErrInvalidArguments
		}
		switch args[0] {
		case "connect":
			return Connect(ctx, *socket, stdin, stdout)
		case "probe":
			return control(ctx, *socket, probeHandshake)
		default:
			return control(ctx, *socket, stopHandshake)
		}
	default:
		return ErrInvalidArguments
	}
}

// Serve starts one shell under a PTY and accepts reconnecting data clients.
func Serve(ctx context.Context, socketPath, shellPath, workingDirectory string) error {
	if err := validateServeOptions(socketPath, shellPath, workingDirectory); err != nil {
		return err
	}
	listener, err := listen(socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	command := exec.Command(shellPath)
	command.Dir = workingDirectory
	command.Env = append(os.Environ(), "HOME=/workspace", "SHELL="+shellPath, "TERM=xterm-256color")
	pseudoterminal, err := pty.StartWithSize(command, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		return fmt.Errorf("start terminal shell: %w", err)
	}
	session := &brokerSession{pty: pseudoterminal}
	defer session.closeClient()

	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	go session.relayOutput()
	stop := make(chan struct{}, 1)

	for {
		select {
		case <-ctx.Done():
			return stopProcess(command, pseudoterminal, processDone, ctx.Err())
		case err := <-processDone:
			_ = pseudoterminal.Close()
			if err == nil {
				return nil
			}
			return fmt.Errorf("terminal shell exited: %w", err)
		case <-stop:
			return stopProcess(command, pseudoterminal, processDone, nil)
		default:
		}

		if err := listener.SetDeadline(time.Now().Add(acceptPollInterval)); err != nil {
			return fmt.Errorf("set terminal broker accept deadline: %w", err)
		}
		connection, err := listener.AcceptUnix()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("accept terminal broker connection: %w", err)
		}
		go session.handle(connection, stop)
	}
}

type brokerSession struct {
	pty     *os.File
	mu      sync.Mutex
	current *net.UnixConn
}

func (s *brokerSession) handle(connection *net.UnixConn, stop chan<- struct{}) {
	if err := connection.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		_ = connection.Close()
		return
	}
	reader := bufio.NewReaderSize(connection, len(dataHandshake))
	header, err := reader.ReadString('\n')
	if err != nil {
		_ = connection.Close()
		return
	}
	_ = connection.SetReadDeadline(time.Time{})
	switch header {
	case dataHandshake:
		s.setClient(connection)
		_, _ = io.Copy(s.pty, reader)
		s.clearClient(connection)
	case probeHandshake:
		_ = connection.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		_, _ = io.WriteString(connection, okResponse)
		_ = connection.Close()
	case stopHandshake:
		_ = connection.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		_, _ = io.WriteString(connection, okResponse)
		_ = connection.Close()
		select {
		case stop <- struct{}{}:
		default:
		}
	default:
		_ = connection.Close()
	}
}

func (s *brokerSession) relayOutput() {
	buffer := make([]byte, 32<<10)
	for {
		count, err := s.pty.Read(buffer)
		if count > 0 {
			s.writeClient(buffer[:count])
		}
		if err != nil {
			return
		}
	}
}

func (s *brokerSession) setClient(connection *net.UnixConn) {
	s.mu.Lock()
	previous := s.current
	s.current = connection
	s.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
}

func (s *brokerSession) clearClient(connection *net.UnixConn) {
	s.mu.Lock()
	if s.current == connection {
		s.current = nil
	}
	s.mu.Unlock()
	_ = connection.Close()
}

func (s *brokerSession) closeClient() {
	s.mu.Lock()
	connection := s.current
	s.current = nil
	s.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
}

func (s *brokerSession) writeClient(value []byte) {
	s.mu.Lock()
	connection := s.current
	if connection != nil {
		_ = connection.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
		if _, err := connection.Write(value); err != nil {
			s.current = nil
			_ = connection.Close()
		}
	}
	s.mu.Unlock()
}

// Connect bridges process stdin/stdout to an existing broker. The Docker
// adapter runs this command in a fresh attached exec for every reconnect.
func Connect(ctx context.Context, socketPath string, stdin io.Reader, stdout io.Writer) error {
	if !socketPattern.MatchString(socketPath) || stdin == nil || stdout == nil {
		return ErrInvalidArguments
	}
	connection, err := dial(ctx, socketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, dataHandshake); err != nil {
		return fmt.Errorf("start terminal broker stream: %w", err)
	}

	var restore func()
	if file, ok := stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		state, rawErr := term.MakeRaw(int(file.Fd()))
		if rawErr != nil {
			return fmt.Errorf("set terminal client raw mode: %w", rawErr)
		}
		restore = func() { _ = term.Restore(int(file.Fd()), state) }
	}
	if restore != nil {
		defer restore()
	}

	done := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(connection, stdin)
		done <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(stdout, connection)
		done <- copyErr
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case copyErr := <-done:
		if copyErr == nil || errors.Is(copyErr, io.EOF) || errors.Is(copyErr, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("proxy terminal broker stream: %w", copyErr)
	}
}

func control(ctx context.Context, socketPath, handshake string) error {
	if !socketPattern.MatchString(socketPath) {
		return ErrInvalidArguments
	}
	connection, err := dial(ctx, socketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	deadline := time.Now().Add(handshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(connection, handshake); err != nil {
		return fmt.Errorf("write terminal broker control: %w", err)
	}
	response, err := bufio.NewReaderSize(connection, len(okResponse)).ReadString('\n')
	if err != nil || response != okResponse {
		return ErrUnavailable
	}
	return nil
}

func listen(socketPath string) (*net.UnixListener, error) {
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%w: socket path is not a socket", ErrUnavailable)
		}
		probeCtx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		probeErr := control(probeCtx, socketPath, probeHandshake)
		cancel()
		if probeErr == nil {
			return nil, ErrAlreadyRunning
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale terminal broker socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect terminal broker socket: %w", err)
	}
	address := &net.UnixAddr{Name: socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, fmt.Errorf("listen terminal broker socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("secure terminal broker socket: %w", err)
	}
	return listener, nil
}

func dial(ctx context.Context, socketPath string) (*net.UnixConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	return unixConnection, nil
}

func stopProcess(command *exec.Cmd, pseudoterminal *os.File, processDone <-chan error, result error) error {
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	}
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()
	select {
	case <-processDone:
	case <-timer.C:
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		<-processDone
	}
	_ = pseudoterminal.Close()
	return result
}

func validateServeOptions(socketPath, shellPath, workingDirectory string) error {
	if !socketPattern.MatchString(socketPath) || !shellPattern.MatchString(shellPath) ||
		!workingDirectoryPattern.MatchString(workingDirectory) || filepath.Clean(socketPath) != socketPath ||
		strings.ContainsAny(shellPath+workingDirectory, "\x00\r\n") {
		return ErrInvalidArguments
	}
	return nil
}
