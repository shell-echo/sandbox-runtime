package workloadcredential

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type ServerConfig struct {
	SocketPath        string
	SocketUID         uint32
	SocketGID         uint32
	ExpectedClientUID uint32
	ExpectedClientGID uint32
	MaxConnections    int
	ReapInterval      time.Duration
}

type Server struct {
	listener          *net.UnixListener
	controller        *Controller
	expectedClientUID uint32
	expectedClientGID uint32
	capacity          chan struct{}
	reapInterval      time.Duration
	handlers          sync.WaitGroup
	stop              chan struct{}
	stopOnce          sync.Once
}

func Listen(config ServerConfig, controller *Controller) (*Server, error) {
	if controller == nil || !validSocketParent(config.SocketPath, config.SocketUID, config.SocketGID) ||
		config.MaxConnections < 1 || config.MaxConnections > 256 || config.ReapInterval < time.Second || config.ReapInterval > time.Minute {
		return nil, ErrUnavailable
	}
	if _, err := os.Lstat(config.SocketPath); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, ErrUnavailable
	}
	listener.SetUnlinkOnClose(true)
	if os.Chmod(config.SocketPath, 0o600) != nil || os.Chown(config.SocketPath, int(config.SocketUID), int(config.SocketGID)) != nil ||
		validateSocket(config.SocketPath, config.SocketUID, config.SocketGID) != nil {
		_ = listener.Close()
		return nil, ErrUnavailable
	}
	return &Server{listener: listener, controller: controller, expectedClientUID: config.ExpectedClientUID,
		expectedClientGID: config.ExpectedClientGID, capacity: make(chan struct{}, config.MaxConnections), reapInterval: config.ReapInterval,
		stop: make(chan struct{})}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return ErrUnavailable
	}
	defer s.stopOnce.Do(func() { close(s.stop) })
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		ticker := time.NewTicker(s.reapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = s.listener.Close()
				return
			case <-s.stop:
				return
			case <-ticker.C:
				reapContext, cancel := context.WithTimeout(ctx, s.reapInterval)
				_ = s.controller.Reap(reapContext)
				cancel()
			}
		}
	}()
	defer func() { <-watcherDone }()
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			s.handlers.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return ErrUnavailable
		}
		select {
		case s.capacity <- struct{}{}:
			s.handlers.Add(1)
			go func() {
				defer s.handlers.Done()
				defer func() { <-s.capacity }()
				s.handle(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stop) })
	err := s.listener.Close()
	s.handlers.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != s.expectedClientUID || identity.gid != s.expectedClientGID {
		return
	}
	document, err := readFrame(connection, MaxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	request, err := DecodeRequest(document)
	if err != nil {
		return
	}
	deadline, err := parseTime(request.Deadline)
	if err != nil {
		return
	}
	operationContext, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	response, handleErr := s.controller.Handle(operationContext, request)
	if handleErr != nil && response.Status == "" {
		return
	}
	encoded, err := EncodeResponse(response, request, s.controller.now().UTC())
	if err != nil {
		return
	}
	defer clear(encoded)
	_ = writeFrame(connection, encoded, MaxResponseBytes)
}

func readFrame(reader io.Reader, maximum int) ([]byte, error) {
	buffered := bufio.NewReaderSize(reader, min(maximum+4, 64<<10))
	var header [4]byte
	if _, err := io.ReadFull(buffered, header[:]); err != nil {
		return nil, ErrUnavailable
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length < 1 || length > maximum {
		return nil, ErrUnavailable
	}
	document := make([]byte, length)
	if _, err := io.ReadFull(buffered, document); err != nil {
		clear(document)
		return nil, ErrUnavailable
	}
	return document, nil
}

func writeFrame(writer io.Writer, document []byte, maximum int) error {
	if len(document) < 1 || len(document) > maximum {
		return ErrUnavailable
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(document)))
	if err := writeBytes(writer, header[:]); err != nil {
		return err
	}
	return writeBytes(writer, document)
}

func writeBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return ErrUnavailable
		}
		value = value[count:]
	}
	return nil
}

type peerIdentity struct{ uid, gid uint32 }

func socketPeer(connection *net.UnixConn) (peerIdentity, error) {
	return peerCredentials(connection)
}

func validSocketParent(path string, uid, gid uint32) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return false
	}
	info, err := os.Lstat(filepath.Dir(path))
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 && ownedBy(info, uid, gid)
}

func validateSocket(path string, uid, gid uint32) error {
	if !validSocketParent(path, uid, gid) {
		return ErrUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !ownedBy(info, uid, gid) {
		return ErrUnavailable
	}
	return nil
}

func ownedBy(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}
