package workloadcredentialv2

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
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
	socketPath        string
	socketInfo        os.FileInfo
	layout            restrictedunix.Layout
	controller        *Controller
	expectedClientUID uint32
	expectedClientGID uint32
	capacity          chan struct{}
	reapInterval      time.Duration
	tracker           *restrictedunix.Tracker
	stop              chan struct{}
	stopOnce          sync.Once
}

func Listen(config ServerConfig, controller *Controller) (*Server, error) {
	if controller == nil || uint32(os.Getuid()) != config.SocketUID ||
		config.SocketGID != config.ExpectedClientGID || config.ExpectedClientUID == config.SocketUID ||
		config.ExpectedClientGID == uint32(os.Getgid()) ||
		config.MaxConnections < 1 || config.MaxConnections > 256 || config.ReapInterval < time.Second || config.ReapInterval > time.Minute {
		return nil, ErrUnavailable
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666, OwnerUID: config.SocketUID, DirectoryGID: config.SocketGID}
	listener, socketInfo, err := restrictedunix.Listen(config.SocketPath, layout)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Server{listener: listener, socketPath: config.SocketPath, socketInfo: socketInfo, layout: layout,
		controller: controller, expectedClientUID: config.ExpectedClientUID,
		expectedClientGID: config.ExpectedClientGID, capacity: make(chan struct{}, config.MaxConnections),
		reapInterval: config.ReapInterval, tracker: restrictedunix.NewTracker(), stop: make(chan struct{})}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return ErrUnavailable
	}
	defer s.stopServer()
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		ticker := time.NewTicker(s.reapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				s.stopServer()
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
			s.stopServer()
			s.tracker.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return ErrUnavailable
		}
		select {
		case s.capacity <- struct{}{}:
			if !s.tracker.Add(connection) {
				<-s.capacity
				_ = connection.Close()
				continue
			}
			go func() {
				defer s.tracker.Done(connection)
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
	s.stopServer()
	s.tracker.Wait()
	return nil
}

func (s *Server) stopServer() {
	s.stopOnce.Do(func() {
		close(s.stop)
		_ = s.listener.Close()
		restrictedunix.RemoveIfSame(s.socketPath, s.socketInfo)
		s.tracker.Stop()
	})
}

func (s *Server) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	current, err := os.Lstat(s.socketPath)
	if err != nil || !os.SameFile(current, s.socketInfo) || !restrictedunix.ValidateSocket(s.socketPath, s.layout) {
		return
	}
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != s.expectedClientUID || identity.gid != s.expectedClientGID {
		return
	}
	if connection.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		return
	}
	document, err := readFrame(connection, MaxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	request, policy, err := DecodeRequest(document, s.controller.policies, s.controller.now().UTC())
	if err != nil || policy.ExpectedUID != identity.uid || policy.ExpectedGID != identity.gid {
		return
	}
	deadline, err := parseTime(request.Deadline)
	if err != nil {
		return
	}
	operationContext, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	operationDeadline, _ := operationContext.Deadline()
	if connection.SetDeadline(operationDeadline) != nil {
		return
	}
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		var extra [1]byte
		_, _ = connection.Read(extra[:])
		cancel()
	}()
	defer func() {
		_ = connection.Close()
		<-peerDone
	}()
	response, handleErr := s.controller.Handle(operationContext, request, identity.uid, identity.gid)
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
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrUnavailable
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length < 1 || length > maximum {
		return nil, ErrUnavailable
	}
	document := make([]byte, length)
	if _, err := io.ReadFull(reader, document); err != nil {
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
		if err != nil || count < 1 || count > len(value) {
			return ErrUnavailable
		}
		value = value[count:]
	}
	return nil
}

type peerIdentity struct{ uid, gid uint32 }

func socketPeer(connection *net.UnixConn) (peerIdentity, error) { return peerCredentials(connection) }
