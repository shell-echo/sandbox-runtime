package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
)

// V2ControllerServerConfig narrows one cross-UID listener to either the
// operator's four control operations or one agent's consume operation.
// Business payloads and signature domains remain the existing v1 protocol.
type V2ControllerServerConfig struct {
	ServerConfig
	Kind          string
	TargetAgentID string
}

type V2ControllerServer struct {
	listener   *net.UnixListener
	socketPath string
	socketInfo os.FileInfo
	layout     restrictedunix.Layout
	config     V2ControllerServerConfig
	controller *Controller
	capacity   chan struct{}
	tracker    *restrictedunix.Tracker
	stopOnce   sync.Once
	stop       chan struct{}
}

func ListenV2Controller(config V2ControllerServerConfig, controller *Controller) (*V2ControllerServer, error) {
	if controller == nil || uint32(os.Getuid()) != config.SocketUID ||
		config.SocketGID != config.ExpectedClientGID || config.SocketGID == uint32(os.Getgid()) ||
		config.ExpectedClientUID == config.SocketUID || config.MaxConnections < 1 || config.MaxConnections > 16 ||
		(config.Kind != "control" && config.Kind != "consume") ||
		(config.Kind == "control" && config.TargetAgentID != "") ||
		(config.Kind == "consume" && !identifierPattern.MatchString(config.TargetAgentID)) {
		return nil, ErrUnavailable
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666,
		OwnerUID: config.SocketUID, DirectoryGID: config.SocketGID}
	listener, info, err := restrictedunix.Listen(config.SocketPath, layout)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &V2ControllerServer{listener: listener, socketPath: config.SocketPath, socketInfo: info,
		layout: layout, config: config, controller: controller, capacity: make(chan struct{}, config.MaxConnections),
		tracker: restrictedunix.NewTracker(), stop: make(chan struct{})}, nil
}

func (s *V2ControllerServer) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return ErrUnavailable
	}
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			s.stopServer()
		case <-s.stop:
		}
	}()
	defer func() { s.stopServer(); <-watcherDone }()
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

func (s *V2ControllerServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	s.stopServer()
	s.tracker.Wait()
	return nil
}

func (s *V2ControllerServer) stopServer() {
	s.stopOnce.Do(func() {
		close(s.stop)
		_ = s.listener.Close()
		restrictedunix.RemoveIfSame(s.socketPath, s.socketInfo)
		s.tracker.Stop()
	})
}

func (s *V2ControllerServer) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	current, err := os.Lstat(s.socketPath)
	if err != nil || !os.SameFile(current, s.socketInfo) || !restrictedunix.ValidateSocket(s.socketPath, s.layout) ||
		connection.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		return
	}
	identity, err := peerCredentials(connection)
	if err != nil || identity.uid != s.config.ExpectedClientUID || identity.gid != s.config.ExpectedClientGID {
		return
	}
	document, err := readFrame(connection, maxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	request, err := decodeWireRequest(document)
	if err != nil || !v2OperationAllowed(s.config.Kind, s.config.TargetAgentID, request) {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
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
	default:
		return
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

func v2OperationAllowed(kind, target string, request WireRequest) bool {
	if kind == "control" {
		return request.Type == SubmitType || request.Type == ApproveType || request.Type == IssueType || request.Type == RevokeType
	}
	return kind == "consume" && request.Type == ConsumeType && request.Consume != nil &&
		request.Consume.TargetAgentID == target && request.Consume.Capability.TargetAgentID == target
}

type V2ControllerClientConfig struct {
	SocketPath    string
	ExpectedUID   uint32
	ExpectedGID   uint32
	DirectoryGID  uint32
	Kind          string
	TargetAgentID string
}

func CallV2(ctx context.Context, config V2ControllerClientConfig, request WireRequest) (WireResponse, error) {
	if ctx == nil || ctx.Err() != nil || validateWireRequest(request) != nil ||
		!v2OperationAllowed(config.Kind, config.TargetAgentID, request) ||
		uint32(os.Getuid()) == config.ExpectedUID || uint32(os.Getgid()) != config.DirectoryGID ||
		uint32(os.Getgid()) == config.ExpectedGID {
		return WireResponse{}, ErrUnavailable
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666,
		OwnerUID: config.ExpectedUID, DirectoryGID: config.DirectoryGID}
	if !restrictedunix.ValidateSocket(config.SocketPath, layout) {
		return WireResponse{}, ErrUnavailable
	}
	before, err := os.Lstat(config.SocketPath)
	if err != nil {
		return WireResponse{}, ErrUnavailable
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) > maxRequestBytes {
		return WireResponse{}, ErrUnavailable
	}
	defer clear(document)
	operation, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	connectionValue, err := (&net.Dialer{}).DialContext(operation, "unix", config.SocketPath)
	if err != nil {
		return WireResponse{}, ErrUnavailable
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return WireResponse{}, ErrUnavailable
	}
	defer connection.Close()
	stopCancel := context.AfterFunc(operation, func() { _ = connection.Close() })
	defer stopCancel()
	deadline, _ := operation.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return WireResponse{}, ErrUnavailable
	}
	identity, err := peerCredentials(connection)
	after, statErr := os.Lstat(config.SocketPath)
	if err != nil || identity.uid != config.ExpectedUID || identity.gid != config.ExpectedGID ||
		statErr != nil || !os.SameFile(before, after) || !restrictedunix.ValidateSocket(config.SocketPath, layout) ||
		writeFrame(connection, document, maxRequestBytes) != nil {
		return WireResponse{}, ErrUnavailable
	}
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		if operation.Err() != nil {
			return WireResponse{}, operation.Err()
		}
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
