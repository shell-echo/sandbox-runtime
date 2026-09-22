package breakglass

import (
	"bufio"
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
)

const (
	SubmitType  = "submit"
	ApproveType = "approve"
	IssueType   = "issue"
	ConsumeType = "consume"
	RevokeType  = "revoke"

	ResponseOK          = "ok"
	ResponseDenied      = "denied"
	ResponseUnavailable = "unavailable"
	ResponseExpired     = "expired"
	ResponseRevoked     = "revoked"
	ResponseConsumed    = "consumed"

	maxRequestBytes  = 128 << 10
	maxResponseBytes = 128 << 10
)

type WireRequest struct {
	Protocol string         `json:"protocol"`
	Type     string         `json:"type"`
	Request  *AccessRequest `json:"request"`
	Approval *Approval      `json:"approval"`
	Command  *Command       `json:"command"`
	Consume  *Consume       `json:"consume"`
}

type WireResponse struct {
	Protocol   string      `json:"protocol"`
	Status     string      `json:"status"`
	Revision   int64       `json:"revision"`
	Capability *Capability `json:"capability"`
}

type ServerConfig struct {
	SocketPath        string
	SocketUID         uint32
	SocketGID         uint32
	ExpectedClientUID uint32
	ExpectedClientGID uint32
	MaxConnections    int
}

type Server struct {
	listener          *net.UnixListener
	controller        *Controller
	expectedClientUID uint32
	expectedClientGID uint32
	capacity          chan struct{}
	handlers          sync.WaitGroup
}

func Listen(config ServerConfig, controller *Controller) (*Server, error) {
	if controller == nil || !validSocketParent(config.SocketPath, config.SocketUID, config.SocketGID) || config.MaxConnections < 1 || config.MaxConnections > 256 {
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
	if os.Chmod(config.SocketPath, 0o600) != nil || os.Chown(config.SocketPath, int(config.SocketUID), int(config.SocketGID)) != nil || validateSocket(config.SocketPath, config.SocketUID, config.SocketGID) != nil {
		_ = listener.Close()
		return nil, ErrUnavailable
	}
	return &Server{listener: listener, controller: controller, expectedClientUID: config.ExpectedClientUID,
		expectedClientGID: config.ExpectedClientGID, capacity: make(chan struct{}, config.MaxConnections)}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return ErrUnavailable
	}
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		<-ctx.Done()
		_ = s.listener.Close()
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
	err := s.listener.Close()
	s.handlers.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) handle(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	identity, err := peerCredentials(connection)
	if err != nil || identity.uid != s.expectedClientUID || identity.gid != s.expectedClientGID {
		return
	}
	document, err := readFrame(connection, maxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	request, err := decodeWireRequest(document)
	if err != nil {
		return
	}
	response := WireResponse{Protocol: ProtocolID, Status: ResponseOK}
	switch request.Type {
	case SubmitType:
		response.Revision, err = s.controller.Submit(ctx, *request.Request)
	case ApproveType:
		response.Revision, err = s.controller.Approve(ctx, *request.Approval)
	case IssueType:
		var capability Capability
		capability, err = s.controller.Issue(ctx, *request.Command)
		if err == nil {
			response.Capability = &capability
		}
	case ConsumeType:
		err = s.controller.Consume(ctx, *request.Consume)
	case RevokeType:
		err = s.controller.Revoke(ctx, *request.Command)
	}
	if err != nil {
		response.Status = responseStatus(err)
		response.Revision, response.Capability = 0, nil
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > maxResponseBytes {
		return
	}
	defer clear(encoded)
	_ = writeFrame(connection, encoded, maxResponseBytes)
}

func Call(ctx context.Context, socketPath string, expectedUID, expectedGID uint32, request WireRequest) (WireResponse, error) {
	if ctx == nil || validateWireRequest(request) != nil || validateSocket(socketPath, expectedUID, expectedGID) != nil {
		return WireResponse{}, ErrUnavailable
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) > maxRequestBytes {
		return WireResponse{}, ErrUnavailable
	}
	defer clear(document)
	connectionValue, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return WireResponse{}, ErrUnavailable
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return WireResponse{}, ErrUnavailable
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	identity, err := peerCredentials(connection)
	if err != nil || identity.uid != expectedUID || identity.gid != expectedGID || writeFrame(connection, document, maxRequestBytes) != nil {
		return WireResponse{}, ErrUnavailable
	}
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		return WireResponse{}, ErrUnavailable
	}
	defer clear(responseDocument)
	var response WireResponse
	if decodeCanonical(responseDocument, &response) != nil || response.Protocol != ProtocolID {
		return WireResponse{}, ErrUnavailable
	}
	if response.Status != ResponseOK {
		return response, responseError(response.Status)
	}
	return response, nil
}

func decodeWireRequest(document []byte) (WireRequest, error) {
	var request WireRequest
	if len(document) < 1 || len(document) > maxRequestBytes || decodeCanonical(document, &request) != nil || validateWireRequest(request) != nil {
		return WireRequest{}, ErrDenied
	}
	return request, nil
}

func validateWireRequest(request WireRequest) error {
	if request.Protocol != ProtocolID {
		return ErrDenied
	}
	count := 0
	for _, present := range []bool{request.Request != nil, request.Approval != nil, request.Command != nil, request.Consume != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return ErrDenied
	}
	switch request.Type {
	case SubmitType:
		if request.Request == nil {
			return ErrDenied
		}
	case ApproveType:
		if request.Approval == nil {
			return ErrDenied
		}
	case IssueType:
		if request.Command == nil || request.Command.Type != CommandIssue {
			return ErrDenied
		}
	case RevokeType:
		if request.Command == nil || request.Command.Type != CommandRevoke {
			return ErrDenied
		}
	case ConsumeType:
		if request.Consume == nil {
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	return nil
}

func responseStatus(err error) string {
	switch {
	case errors.Is(err, ErrDenied):
		return ResponseDenied
	case errors.Is(err, ErrExpired):
		return ResponseExpired
	case errors.Is(err, ErrRevoked):
		return ResponseRevoked
	case errors.Is(err, ErrConsumed):
		return ResponseConsumed
	default:
		return ResponseUnavailable
	}
}

func responseError(status string) error {
	switch status {
	case ResponseDenied:
		return ErrDenied
	case ResponseExpired:
		return ErrExpired
	case ResponseRevoked:
		return ErrRevoked
	case ResponseConsumed:
		return ErrConsumed
	default:
		return ErrUnavailable
	}
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
	for _, value := range [][]byte{header[:], document} {
		for len(value) > 0 {
			count, err := writer.Write(value)
			if err != nil {
				return ErrUnavailable
			}
			value = value[count:]
		}
	}
	return nil
}

type peerIdentity struct{ uid, gid uint32 }

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
