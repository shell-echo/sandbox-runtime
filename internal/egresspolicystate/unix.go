package egresspolicystate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type AuthorityServerConfig struct {
	SocketPath        string
	AuthorityUID      uint32
	BrokerGID         uint32
	ExpectedBrokerUID uint32
	ExpectedBrokerGID uint32
	MaxConnections    int
}

type AuthorityServer struct {
	listener          *net.UnixListener
	socketPath        string
	socketInfo        os.FileInfo
	authority         *Authority
	expectedBrokerUID uint32
	expectedBrokerGID uint32
	capacity          chan struct{}
	handlers          sync.WaitGroup
	closeOnce         sync.Once
	closeErr          error
}

func ListenAuthority(config AuthorityServerConfig, authority *Authority) (*AuthorityServer, error) {
	if authority == nil || !validAuthoritySocketParent(config.SocketPath, config.AuthorityUID, config.BrokerGID) ||
		config.MaxConnections < 1 || config.MaxConnections > 64 ||
		config.ExpectedBrokerGID != config.BrokerGID ||
		uint32(os.Getuid()) != config.AuthorityUID {
		return nil, ErrInvalid
	}
	if !recoverStaleAuthoritySocket(config.SocketPath, config.AuthorityUID, config.BrokerGID) {
		return nil, ErrInvalid
	}
	parentBefore, err := os.Lstat(filepath.Dir(config.SocketPath))
	if err != nil {
		return nil, ErrInvalid
	}
	syscall.Umask(0o077) // dedicated authority process retains a strict umask
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, ErrInvalid
	}
	listener.SetUnlinkOnClose(false)
	initial, initialErr := os.Lstat(config.SocketPath)
	parentAfter, parentErr := os.Lstat(filepath.Dir(config.SocketPath))
	if initialErr != nil || parentErr != nil || !os.SameFile(parentBefore, parentAfter) ||
		initial.Mode()&os.ModeSocket == 0 || initial.Mode().Perm()&0o077 != 0 ||
		os.Chmod(config.SocketPath, 0o666) != nil ||
		!validAuthoritySocket(config.SocketPath, config.AuthorityUID, config.BrokerGID) {
		_ = listener.Close()
		if current, currentErr := os.Lstat(config.SocketPath); currentErr == nil &&
			initialErr == nil && os.SameFile(initial, current) {
			_ = os.Remove(config.SocketPath)
		}
		return nil, ErrInvalid
	}
	socketInfo, err := os.Lstat(config.SocketPath)
	if err != nil || !os.SameFile(initial, socketInfo) {
		_ = listener.Close()
		_ = os.Remove(config.SocketPath)
		return nil, ErrInvalid
	}
	return &AuthorityServer{listener: listener, socketPath: config.SocketPath, socketInfo: socketInfo, authority: authority,
		expectedBrokerUID: config.ExpectedBrokerUID, expectedBrokerGID: config.ExpectedBrokerGID,
		capacity: make(chan struct{}, config.MaxConnections)}, nil
}

func recoverStaleAuthoritySocket(socketPath string, authorityUID, brokerGID uint32) bool {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || !validAuthoritySocketParent(socketPath, authorityUID, brokerGID) ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 ||
		(info.Mode().Perm() != 0o666 && info.Mode().Perm()&0o077 != 0) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != authorityUID {
		return false
	}
	connection, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
		return false
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return false
	}
	current, err := os.Lstat(socketPath)
	if err != nil || !os.SameFile(info, current) || os.Remove(socketPath) != nil {
		return false
	}
	_, err = os.Lstat(socketPath)
	return errors.Is(err, os.ErrNotExist)
}

func (s *AuthorityServer) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return ErrInvalid
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			s.handlers.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return ErrInvalid
		}
		select {
		case s.capacity <- struct{}{}:
			s.handlers.Add(1)
			go func() {
				defer s.handlers.Done()
				defer func() { <-s.capacity }()
				s.handle(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s *AuthorityServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closeErr = s.listener.Close()
		s.handlers.Wait()
		current, statErr := os.Lstat(s.socketPath)
		if statErr != nil || !os.SameFile(s.socketInfo, current) || os.Remove(s.socketPath) != nil {
			s.closeErr = ErrInvalid
		}
		if errors.Is(s.closeErr, net.ErrClosed) {
			s.closeErr = nil
		}
	})
	return s.closeErr
}

func (s *AuthorityServer) handle(connection *net.UnixConn) {
	defer connection.Close()
	UID, GID, err := unixPeer(connection)
	if err != nil || UID != s.expectedBrokerUID || GID != s.expectedBrokerGID {
		return
	}
	_ = connection.SetDeadline(time.Now().Add(MaxCurrentTTL))
	document, err := readCurrentFrame(connection)
	if err != nil {
		return
	}
	defer clear(document)
	now := s.authority.now().UTC()
	request, err := DecodeCurrentRequest(document, s.authority.binding, now)
	if err != nil {
		return
	}
	response, err := s.authority.currentLive(request)
	if err != nil {
		return
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return
	}
	defer clear(encoded)
	_ = writeCurrentFrame(connection, encoded)
}

type AuthorityClientConfig struct {
	SocketPath           string
	ExpectedAuthorityUID uint32
	ExpectedAuthorityGID uint32
	BrokerGID            uint32
	Binding              Binding
	Timeout              time.Duration
	Now                  func() time.Time
}

type AuthorityClient struct{ config AuthorityClientConfig }

func NewAuthorityClient(config AuthorityClientConfig) (*AuthorityClient, error) {
	if !validAuthoritySocket(config.SocketPath, config.ExpectedAuthorityUID, config.BrokerGID) ||
		config.Timeout < 100*time.Millisecond || config.Timeout > MaxCurrentTTL ||
		config.Now == nil || config.Now().IsZero() ||
		uint32(os.Getgid()) != config.BrokerGID {
		return nil, ErrInvalid
	}
	return &AuthorityClient{config: config}, nil
}

func (c *AuthorityClient) Current(ctx context.Context) (CurrentResponse, error) {
	if c == nil || ctx == nil || !validAuthoritySocket(c.config.SocketPath,
		c.config.ExpectedAuthorityUID, c.config.BrokerGID) {
		return CurrentResponse{}, ErrInvalid
	}
	now := c.config.Now().UTC()
	request, err := NewCurrentRequest(c.config.Binding, now)
	if err != nil {
		return CurrentResponse{}, ErrInvalid
	}
	operationContext, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	connectionValue, err := (&net.Dialer{}).DialContext(operationContext, "unix", c.config.SocketPath)
	if err != nil {
		return CurrentResponse{}, ErrInvalid
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return CurrentResponse{}, ErrInvalid
	}
	defer connection.Close()
	UID, GID, err := unixPeer(connection)
	if err != nil || UID != c.config.ExpectedAuthorityUID || GID != c.config.ExpectedAuthorityGID {
		return CurrentResponse{}, ErrInvalid
	}
	deadline := now.Add(c.config.Timeout)
	if contextDeadline, hasDeadline := operationContext.Deadline(); hasDeadline && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	document, err := json.Marshal(request)
	if err != nil || writeCurrentFrame(connection, document) != nil {
		return CurrentResponse{}, ErrInvalid
	}
	clear(document)
	responseDocument, err := readCurrentFrame(connection)
	if err != nil {
		return CurrentResponse{}, ErrInvalid
	}
	defer clear(responseDocument)
	return DecodeCurrentResponse(responseDocument, request, c.config.Binding, c.config.Now().UTC())
}

func validAuthoritySocketParent(path string, authorityUID, brokerGID uint32) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return false
	}
	parentPath := filepath.Dir(path)
	if !safeAncestorDirectories(parentPath) {
		return false
	}
	info, err := os.Lstat(parentPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o710 || info.Mode()&(os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == authorityUID && stat.Gid == brokerGID
}

func safeAncestorDirectories(directory string) bool {
	for ancestor := directory; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (info.Mode().Perm()&0o022 != 0 &&
			!(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0 && info.Mode().Perm()&0o002 != 0)) {
			return false
		}
		if ancestor == filepath.Dir(ancestor) {
			return true
		}
	}
}

func validAuthoritySocket(path string, authorityUID, brokerGID uint32) bool {
	if !validAuthoritySocketParent(path, authorityUID, brokerGID) {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 ||
		info.Mode().Perm() != 0o666 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == authorityUID
}

func readCurrentFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrInvalid
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length < 1 || length > MaxCurrentBytes {
		return nil, ErrInvalid
	}
	document := make([]byte, length)
	if _, err := io.ReadFull(reader, document); err != nil {
		clear(document)
		return nil, ErrInvalid
	}
	return document, nil
}

func writeCurrentFrame(writer io.Writer, document []byte) error {
	if len(document) < 1 || len(document) > MaxCurrentBytes {
		return ErrInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(document)))
	if writeExact(writer, header[:]) != nil || writeExact(writer, document) != nil {
		return ErrInvalid
	}
	return nil
}
