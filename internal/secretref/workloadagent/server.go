package workloadagent

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const maxAgentBindings = 512

type ServerConfig struct {
	SocketPath        string
	SocketUID         uint32
	SocketGID         uint32
	ExpectedClientUID uint32
	ExpectedClientGID uint32
	Role              secretref.Role
	AllowedPurposes   []secretref.Purpose
	Bindings          []secretref.Binding
	MaxConnections    int
	MaxResolutions    int
	Now               func() time.Time
}

type Server struct {
	listener          *net.UnixListener
	provider          secretref.SecretProvider
	expectedClientUID uint32
	expectedClientGID uint32
	role              secretref.Role
	allowed           map[secretref.Purpose]struct{}
	bindings          map[string]secretref.Binding
	capacity          chan struct{}
	resolutionSlots   chan struct{}
	resolutionStop    sync.Once
	now               func() time.Time
	replayMu          sync.Mutex
	replay            map[string]time.Time
	serveMu           sync.Mutex
	serving           bool
	handlers          sync.WaitGroup
}

func Listen(config ServerConfig, provider secretref.SecretProvider) (*Server, error) {
	if provider == nil || !filepath.IsAbs(config.SocketPath) || filepath.Clean(config.SocketPath) != config.SocketPath || len(config.SocketPath) > 100 ||
		!validRole(config.Role) || len(config.AllowedPurposes) < 1 || len(config.Bindings) < 1 || len(config.Bindings) > maxAgentBindings ||
		config.MaxConnections < 1 || config.MaxConnections > 256 || config.MaxResolutions < 0 || config.MaxResolutions > maxAgentBindings ||
		config.Now == nil || config.Now().IsZero() {
		return nil, secretref.ErrUnavailable
	}
	parent := filepath.Dir(config.SocketPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0o700 || !ownedBy(parentInfo, config.SocketUID, config.SocketGID) {
		return nil, secretref.ErrUnavailable
	}
	if _, err := os.Lstat(config.SocketPath); !errors.Is(err, os.ErrNotExist) {
		return nil, secretref.ErrUnavailable
	}
	server := &Server{
		provider: provider, expectedClientUID: config.ExpectedClientUID, expectedClientGID: config.ExpectedClientGID,
		role: config.Role, allowed: make(map[secretref.Purpose]struct{}, len(config.AllowedPurposes)),
		bindings: make(map[string]secretref.Binding, len(config.Bindings)), capacity: make(chan struct{}, config.MaxConnections),
		now: config.Now, replay: make(map[string]time.Time),
	}
	if config.MaxResolutions > 0 {
		server.resolutionSlots = make(chan struct{}, config.MaxResolutions)
		for range config.MaxResolutions {
			server.resolutionSlots <- struct{}{}
		}
	}
	for _, purpose := range config.AllowedPurposes {
		if _, duplicate := server.allowed[purpose]; duplicate || !validPurpose(purpose) {
			return nil, secretref.ErrUnavailable
		}
		server.allowed[purpose] = struct{}{}
	}
	for _, binding := range config.Bindings {
		if binding.Validate() != nil || binding.Kind != secretref.KindSecret || binding.Role != config.Role {
			return nil, secretref.ErrUnavailable
		}
		if _, allowed := server.allowed[binding.Purpose]; !allowed {
			return nil, secretref.ErrUnavailable
		}
		digest := binding.Digest()
		if _, duplicate := server.bindings[digest]; duplicate {
			return nil, secretref.ErrUnavailable
		}
		server.bindings[digest] = binding
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(config.SocketPath, 0o600); err != nil || os.Chown(config.SocketPath, int(config.SocketUID), int(config.SocketGID)) != nil || validateSocket(config.SocketPath, config.SocketUID, config.SocketGID) != nil {
		_ = listener.Close()
		return nil, secretref.ErrUnavailable
	}
	server.listener = listener
	return server, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return secretref.ErrUnavailable
	}
	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return secretref.ErrUnavailable
	}
	s.serving = true
	s.serveMu.Unlock()
	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-stopWatcher:
		}
	}()
	defer func() {
		close(stopWatcher)
		<-watcherDone
	}()
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.handlers.Wait()
				return ctx.Err()
			}
			s.handlers.Wait()
			return secretref.ErrUnavailable
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

func (s *Server) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	credentials, err := peerCredentials(connection)
	if err != nil || credentials.UID != s.expectedClientUID || credentials.GID != s.expectedClientGID {
		return
	}
	document, err := ReadFrame(connection, maxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	trailing := make([]byte, 1)
	if count, readErr := connection.Read(trailing); count != 0 || !errors.Is(readErr, io.EOF) {
		return
	}
	now := s.now()
	request, err := DecodeRequest(document, now)
	if err != nil {
		return
	}
	deadline, err := parseCanonicalTime(request.Deadline)
	if err != nil {
		return
	}
	response := Response{Protocol: ProtocolID, Nonce: request.Nonce, RequestDigest: request.RequestDigest}
	if !s.authorize(request.Binding) || !s.acceptNonce(request.Nonce, deadline, now) {
		response.Type, response.Status = ErrorType, StatusUnavailable
		s.writeResponse(connection, request, response)
		return
	}
	if !s.acceptResolution() {
		response.Type, response.Status = ErrorType, StatusUnavailable
		s.writeResponse(connection, request, response)
		return
	}
	defer s.completeResolution()
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	material, resolveErr := s.provider.ResolveSecret(ctx, request.Binding)
	defer material.Destroy()
	if resolveErr != nil || material.Binding != request.Binding || material.Validate(s.now()) != nil {
		response.Type, response.Status = ErrorType, statusForError(resolveErr)
		s.writeResponse(connection, request, response)
		return
	}
	response.Type, response.Status = MaterialType, StatusOK
	response.BindingDigest, response.Version = request.Binding.Digest(), request.Binding.Version
	response.Revision, response.Digest, response.State = material.Revision, material.Digest, string(material.Window.State)
	response.NotBefore = material.Window.NotBefore.UTC().Format(time.RFC3339Nano)
	response.NotAfter = material.Window.NotAfter.UTC().Format(time.RFC3339Nano)
	response.Material = append([]byte(nil), material.Bytes...)
	defer clear(response.Material)
	s.writeResponse(connection, request, response)
}

func (s *Server) acceptResolution() bool {
	if s.resolutionSlots == nil {
		return true
	}
	select {
	case <-s.resolutionSlots:
		return true
	default:
		return false
	}
}

func (s *Server) completeResolution() {
	if s.resolutionSlots == nil || len(s.resolutionSlots) != 0 {
		return
	}
	s.resolutionStop.Do(func() { _ = s.listener.Close() })
}

func (s *Server) authorize(binding secretref.Binding) bool {
	if binding.Validate() != nil || binding.Kind != secretref.KindSecret || binding.Role != s.role {
		return false
	}
	if _, allowed := s.allowed[binding.Purpose]; !allowed {
		return false
	}
	configured, ok := s.bindings[binding.Digest()]
	return ok && configured == binding
}

func (s *Server) acceptNonce(nonce string, expires, now time.Time) bool {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	for value, expiry := range s.replay {
		if !expiry.After(now) {
			delete(s.replay, value)
		}
	}
	if _, duplicate := s.replay[nonce]; duplicate || len(s.replay) >= maxAgentBindings*2 {
		return false
	}
	s.replay[nonce] = expires
	return true
}

func (s *Server) writeResponse(connection *net.UnixConn, request Request, response Response) {
	document, err := EncodeResponse(response, request, s.now())
	if err != nil {
		return
	}
	defer clear(document)
	_ = WriteFrame(connection, document, maxResponseBytes)
}

func statusForError(err error) string {
	switch {
	case errors.Is(err, secretref.ErrRevoked):
		return StatusRevoked
	case errors.Is(err, secretref.ErrExpired):
		return StatusExpired
	default:
		return StatusUnavailable
	}
}

func validPurpose(purpose secretref.Purpose) bool {
	switch purpose {
	case secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey, secretref.PurposeCABundle,
		secretref.PurposePostgresMigrationDSN, secretref.PurposePostgresRuntimeDSN, secretref.PurposeIdentityKeyRing,
		secretref.PurposeAdmissionVerification, secretref.PurposeCoordinationEndpoint, secretref.PurposeCoordinationIdentity,
		secretref.PurposeObjectStoreEndpoint, secretref.PurposeObjectStoreIdentity, secretref.PurposeKMSEndpoint,
		secretref.PurposeKMSIdentity, secretref.PurposeWorkloadCredential, secretref.PurposeGatewayGrantKey,
		secretref.PurposeGuestSigningKey, secretref.PurposeExecutorClientKey, secretref.PurposeExecutorBridgeKey:
		return true
	default:
		return false
	}
}
