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
)

const (
	AgentProtocolID  = "sandbox-runtime.break-glass-agent.v1"
	AgentConsumeType = "consume"
)

type AgentRequest struct {
	Protocol   string     `json:"protocol"`
	Type       string     `json:"type"`
	Capability Capability `json:"capability"`
}

type AgentResponse struct {
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
}

type AgentServerConfig struct {
	SocketPath           string
	SocketUID            uint32
	SocketGID            uint32
	ExpectedOperatorUID  uint32
	ExpectedOperatorGID  uint32
	ControllerSocketPath string
	ControllerUID        uint32
	ControllerGID        uint32
	AgentID              string
	PrivateKey           ed25519.PrivateKey
	OperationTimeout     time.Duration
	MaxConnections       int
	Now                  func() time.Time
	Use                  func(context.Context, Capability) error
}

type AgentServer struct {
	listener *net.UnixListener
	config   AgentServerConfig
	capacity chan struct{}
	handlers sync.WaitGroup
}

func ListenAgent(config AgentServerConfig) (*AgentServer, error) {
	if !validSocketParent(config.SocketPath, config.SocketUID, config.SocketGID) ||
		validateSocket(config.ControllerSocketPath, config.ControllerUID, config.ControllerGID) != nil ||
		!identifierPattern.MatchString(config.AgentID) || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute || config.MaxConnections < 1 || config.MaxConnections > 16 ||
		config.Now == nil || config.Now().IsZero() || config.Use == nil {
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
	config.PrivateKey = append(ed25519.PrivateKey(nil), config.PrivateKey...)
	return &AgentServer{listener: listener, config: config, capacity: make(chan struct{}, config.MaxConnections)}, nil
}

func (s *AgentServer) Serve(ctx context.Context) error {
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

func (s *AgentServer) Close() error {
	if s == nil {
		return nil
	}
	clear(s.config.PrivateKey)
	err := s.listener.Close()
	s.handlers.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *AgentServer) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
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
	if decodeCanonical(document, &request) != nil || request.Protocol != AgentProtocolID || request.Type != AgentConsumeType ||
		request.Capability.TargetAgentID != s.config.AgentID {
		return
	}
	operationContext, cancel := context.WithTimeout(parent, s.config.OperationTimeout)
	defer cancel()
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	consume, err := NewSignedConsume(Consume{Capability: request.Capability, TargetAgentID: s.config.AgentID,
		Deadline: s.config.Now().UTC().Add(s.config.OperationTimeout).Format(time.RFC3339Nano), JTI: base64.RawURLEncoding.EncodeToString(nonce)}, s.config.PrivateKey)
	clear(nonce)
	status := ResponseOK
	if err != nil {
		status = ResponseDenied
	} else if _, err = Call(operationContext, s.config.ControllerSocketPath, s.config.ControllerUID, s.config.ControllerGID,
		WireRequest{Protocol: ProtocolID, Type: ConsumeType, Consume: &consume}); err != nil {
		status = responseStatus(err)
	} else if err = s.config.Use(operationContext, request.Capability); err != nil {
		status = ResponseUnavailable
	}
	response, err := json.Marshal(AgentResponse{Protocol: AgentProtocolID, Status: status})
	if err == nil {
		defer clear(response)
		_ = writeFrame(connection, response, maxResponseBytes)
	}
}

func Deliver(ctx context.Context, socketPath string, expectedUID, expectedGID uint32, capability Capability) error {
	if ctx == nil || validateSocket(socketPath, expectedUID, expectedGID) != nil {
		return ErrUnavailable
	}
	document, err := json.Marshal(AgentRequest{Protocol: AgentProtocolID, Type: AgentConsumeType, Capability: capability})
	if err != nil || len(document) > maxRequestBytes {
		return ErrUnavailable
	}
	defer clear(document)
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
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	identity, err := peerCredentials(connection)
	if err != nil || identity.uid != expectedUID || identity.gid != expectedGID || writeFrame(connection, document, maxRequestBytes) != nil {
		return ErrUnavailable
	}
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(responseDocument)
	var response AgentResponse
	if decodeCanonical(responseDocument, &response) != nil || response.Protocol != AgentProtocolID || response.Status != ResponseOK {
		return responseError(response.Status)
	}
	return nil
}
