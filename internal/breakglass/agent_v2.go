package breakglass

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
)

type V2AgentServerConfig struct {
	AgentServerConfig
	ControllerDirectoryGID uint32
}

type V2AgentServer struct {
	listener   *net.UnixListener
	socketPath string
	socketInfo os.FileInfo
	layout     restrictedunix.Layout
	config     V2AgentServerConfig
	capacity   chan struct{}
	tracker    *restrictedunix.Tracker
	stopOnce   sync.Once
	stop       chan struct{}
}

// ListenAgentV2 is the operator -> agent delivery endpoint. The agent's
// separate outbound consume path is bound to its own controller-side socket.
func ListenAgentV2(config V2AgentServerConfig) (*V2AgentServer, error) {
	if uint32(os.Getuid()) != config.SocketUID || uint32(os.Getgid()) != config.ControllerDirectoryGID ||
		config.SocketGID != config.ExpectedOperatorGID || config.SocketGID == uint32(os.Getgid()) ||
		config.ExpectedOperatorUID == config.SocketUID || config.ControllerUID == config.SocketUID ||
		config.ControllerGID == config.ControllerDirectoryGID ||
		!identifierPattern.MatchString(config.AgentID) || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second ||
		config.MaxConnections < 1 || config.MaxConnections > 16 || config.Now == nil || config.Now().IsZero() ||
		config.Use == nil || !restrictedunix.ValidateSocket(config.ControllerSocketPath, restrictedunix.Layout{
		DirectoryMode: 0o710, SocketMode: 0o666, OwnerUID: config.ControllerUID,
		DirectoryGID: config.ControllerDirectoryGID}) {
		return nil, ErrUnavailable
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666,
		OwnerUID: config.SocketUID, DirectoryGID: config.SocketGID}
	listener, info, err := restrictedunix.Listen(config.SocketPath, layout)
	if err != nil {
		return nil, ErrUnavailable
	}
	config.PrivateKey = append(ed25519.PrivateKey(nil), config.PrivateKey...)
	return &V2AgentServer{listener: listener, socketPath: config.SocketPath, socketInfo: info,
		layout: layout, config: config, capacity: make(chan struct{}, config.MaxConnections),
		tracker: restrictedunix.NewTracker(), stop: make(chan struct{})}, nil
}

func (s *V2AgentServer) Serve(ctx context.Context) error {
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

func (s *V2AgentServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	s.stopServer()
	s.tracker.Wait()
	clear(s.config.PrivateKey)
	return nil
}

func (s *V2AgentServer) stopServer() {
	s.stopOnce.Do(func() {
		close(s.stop)
		_ = s.listener.Close()
		restrictedunix.RemoveIfSame(s.socketPath, s.socketInfo)
		s.tracker.Stop()
	})
}

func (s *V2AgentServer) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	current, err := os.Lstat(s.socketPath)
	if err != nil || !os.SameFile(current, s.socketInfo) || !restrictedunix.ValidateSocket(s.socketPath, s.layout) ||
		connection.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		return
	}
	identity, err := peerCredentials(connection)
	if err != nil || identity.uid != s.config.ExpectedOperatorUID || identity.gid != s.config.ExpectedOperatorGID {
		return
	}
	document, err := readFrame(connection, maxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	var request AgentRequest
	if decodeCanonical(document, &request) != nil || request.Protocol != AgentProtocolID ||
		request.Type != AgentConsumeType || request.Capability.TargetAgentID != s.config.AgentID {
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.config.OperationTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	consume, err := NewSignedConsume(Consume{Capability: request.Capability, TargetAgentID: s.config.AgentID,
		Deadline: s.config.Now().UTC().Add(s.config.OperationTimeout).Format(time.RFC3339Nano),
		JTI:      base64.RawURLEncoding.EncodeToString(nonce)}, s.config.PrivateKey)
	clear(nonce)
	status := ResponseOK
	if err != nil {
		status = ResponseDenied
	} else if _, err = CallV2(ctx, V2ControllerClientConfig{SocketPath: s.config.ControllerSocketPath,
		ExpectedUID: s.config.ControllerUID, ExpectedGID: s.config.ControllerGID,
		DirectoryGID: s.config.ControllerDirectoryGID, Kind: "consume", TargetAgentID: s.config.AgentID},
		WireRequest{Protocol: ProtocolID, Type: ConsumeType, Consume: &consume}); err != nil {
		status = responseStatus(err)
	} else if err = s.config.Use(ctx, request.Capability); err != nil {
		status = ResponseUnavailable
	}
	response, err := json.Marshal(AgentResponse{Protocol: AgentProtocolID, Status: status})
	if err == nil {
		defer clear(response)
		_ = writeFrame(connection, response, maxResponseBytes)
	}
}

type V2DeliveryConfig struct {
	SocketPath   string
	ExpectedUID  uint32
	ExpectedGID  uint32
	DirectoryGID uint32
	TargetAgent  string
}

func DeliverV2(ctx context.Context, config V2DeliveryConfig, capability Capability) error {
	if ctx == nil || ctx.Err() != nil || capability.TargetAgentID != config.TargetAgent ||
		uint32(os.Getuid()) == config.ExpectedUID || uint32(os.Getgid()) != config.DirectoryGID ||
		uint32(os.Getgid()) == config.ExpectedGID {
		return ErrUnavailable
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666,
		OwnerUID: config.ExpectedUID, DirectoryGID: config.DirectoryGID}
	if !restrictedunix.ValidateSocket(config.SocketPath, layout) {
		return ErrUnavailable
	}
	before, err := os.Lstat(config.SocketPath)
	if err != nil {
		return ErrUnavailable
	}
	document, err := json.Marshal(AgentRequest{Protocol: AgentProtocolID, Type: AgentConsumeType, Capability: capability})
	if err != nil || len(document) > maxRequestBytes {
		return ErrUnavailable
	}
	defer clear(document)
	operation, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	connectionValue, err := (&net.Dialer{}).DialContext(operation, "unix", config.SocketPath)
	if err != nil {
		return ErrUnavailable
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return ErrUnavailable
	}
	defer connection.Close()
	stopCancel := context.AfterFunc(operation, func() { _ = connection.Close() })
	defer stopCancel()
	deadline, _ := operation.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	identity, err := peerCredentials(connection)
	after, statErr := os.Lstat(config.SocketPath)
	if err != nil || identity.uid != config.ExpectedUID || identity.gid != config.ExpectedGID ||
		statErr != nil || !os.SameFile(before, after) || !restrictedunix.ValidateSocket(config.SocketPath, layout) ||
		writeFrame(connection, document, maxRequestBytes) != nil {
		return ErrUnavailable
	}
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		if operation.Err() != nil {
			return operation.Err()
		}
		return ErrUnavailable
	}
	defer clear(responseDocument)
	var response AgentResponse
	if decodeCanonical(responseDocument, &response) != nil || response.Protocol != AgentProtocolID || response.Status != ResponseOK {
		return responseError(response.Status)
	}
	return nil
}
