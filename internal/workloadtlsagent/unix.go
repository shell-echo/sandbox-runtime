package workloadtlsagent

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	AgentGID          uint32
	ExpectedClientUID uint32
	ExpectedClientGID uint32
	MaxConnections    int
	ReplayCapacity    int
	Now               func() time.Time
}

type Server struct {
	listener          *net.UnixListener
	socketPath        string
	socketInfo        os.FileInfo
	manager           *Manager
	expectedClientUID uint32
	expectedClientGID uint32
	capacity          chan struct{}
	now               func() time.Time
	replayCapacity    int
	replayMu          sync.Mutex
	replay            map[string]time.Time
	tracker           *restrictedunix.Tracker
	stopOnce          sync.Once
}

const initialFrameTimeout = 2 * time.Second

func Listen(config ServerConfig, manager *Manager) (*Server, error) {
	if manager == nil || config.Now == nil || config.Now().IsZero() ||
		uint32(os.Getuid()) != config.SocketUID || uint32(os.Getgid()) != config.AgentGID ||
		config.SocketGID != config.ExpectedClientGID ||
		config.MaxConnections < 1 || config.MaxConnections > 256 || config.ReplayCapacity < 16 || config.ReplayCapacity > 65536 {
		return nil, ErrUnavailable
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666, OwnerUID: config.SocketUID, DirectoryGID: config.SocketGID}
	listener, socketInfo, err := restrictedunix.Listen(config.SocketPath, layout)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Server{listener: listener, socketPath: config.SocketPath, socketInfo: socketInfo,
		manager: manager, expectedClientUID: config.ExpectedClientUID,
		expectedClientGID: config.ExpectedClientGID, capacity: make(chan struct{}, config.MaxConnections), now: config.Now,
		replayCapacity: config.ReplayCapacity, replay: make(map[string]time.Time, config.ReplayCapacity),
		tracker: restrictedunix.NewTracker()}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return ErrUnavailable
	}
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			s.stop()
		case <-watchDone:
		}
	}()
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			s.stop()
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
				defer func() { <-s.capacity }()
				defer s.tracker.Done(connection)
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
	s.stop()
	s.tracker.Wait()
	return nil
}

func (s *Server) stop() {
	s.stopOnce.Do(func() {
		_ = s.listener.Close()
		restrictedunix.RemoveIfSame(s.socketPath, s.socketInfo)
		s.tracker.Stop()
	})
}

func (s *Server) handle(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != s.expectedClientUID || identity.gid != s.expectedClientGID {
		return
	}
	if connection.SetReadDeadline(time.Now().Add(initialFrameTimeout)) != nil {
		return
	}
	document, err := readFrame(connection, maxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	now := s.now().UTC()
	request, err := decodeRequest(document, now)
	if err != nil {
		return
	}
	deadline, _ := parseProtocolTime(request.Deadline)
	if connection.SetDeadline(deadline) != nil {
		return
	}
	if !s.reserve(request.Nonce, deadline, now) {
		s.writeResponse(connection, errorResponse(request), request, now)
		return
	}
	operationContext, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	var response Response
	switch request.Type {
	case SnapshotType:
		snapshot, snapshotErr := s.manager.Snapshot()
		if snapshotErr != nil {
			response = errorResponse(request)
		} else {
			response = responseFor(request, snapshot, nil)
			snapshot.Destroy()
		}
	case SignType:
		if operationContext.Err() != nil {
			response = errorResponse(request)
			break
		}
		signature, signErr := s.manager.Sign(request.Generation, request.Digest, crypto.SHA256)
		if signErr != nil {
			response = errorResponse(request)
		} else {
			response = responseFor(request, Snapshot{}, signature)
			clear(signature)
		}
	default:
		response = errorResponse(request)
	}
	s.writeResponse(connection, response, request, s.now().UTC())
}

func (s *Server) writeResponse(connection *net.UnixConn, response Response, request Request, now time.Time) {
	document, err := encodeResponse(response, request, now)
	if err != nil {
		return
	}
	defer clear(document)
	_ = writeFrame(connection, document, maxResponseBytes)
}

func (s *Server) reserve(nonce string, deadline, now time.Time) bool {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	for known, expiry := range s.replay {
		if !expiry.After(now) {
			delete(s.replay, known)
		}
	}
	if _, duplicate := s.replay[nonce]; duplicate || len(s.replay) >= s.replayCapacity {
		return false
	}
	s.replay[nonce] = deadline
	return true
}

type ClientConfig struct {
	SocketPath       string
	ExpectedUID      uint32
	ExpectedGID      uint32
	RoleGID          uint32
	OperationTimeout time.Duration
	Now              func() time.Time
	Random           io.Reader
}

type Client struct{ config ClientConfig }

func NewClient(config ClientConfig) (*Client, error) {
	if validateSocket(config.SocketPath, config.ExpectedUID, config.RoleGID) != nil ||
		config.RoleGID != uint32(os.Getgid()) || config.OperationTimeout < time.Second ||
		config.OperationTimeout > time.Minute || config.Now == nil || config.Now().IsZero() || config.Random == nil {
		return nil, ErrUnavailable
	}
	return &Client{config: config}, nil
}

func NewProductionClient(config ClientConfig) (*Client, error) {
	if config.Random != nil {
		return nil, ErrUnavailable
	}
	config.Random = rand.Reader
	return NewClient(config)
}

func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	request, err := c.newRequest(ctx, SnapshotType, 0, nil)
	if err != nil {
		return Snapshot{}, err
	}
	response, err := c.execute(ctx, request)
	if err != nil {
		return Snapshot{}, err
	}
	notBefore, _ := parseProtocolTime(response.NotBefore)
	notAfter, _ := parseProtocolTime(response.NotAfter)
	safeTo, _ := parseProtocolTime(response.RevocationSafeTo)
	leaf, leafErr := x509.ParseCertificate(response.CertificateDER[0])
	publicKey, publicErr := x509.ParsePKIXPublicKey(response.PublicKeyDER)
	if leafErr != nil || publicErr != nil || !publicKeysEqual(leaf.PublicKey, publicKey) || !leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(notAfter) {
		return Snapshot{}, ErrUnavailable
	}
	return Snapshot{Generation: response.Generation, IssuerRevision: response.IssuerRevision, Serial: response.Serial,
		CertificateDER: cloneDER(response.CertificateDER), PublicKeyDER: append([]byte(nil), response.PublicKeyDER...),
		NotBefore: notBefore, NotAfter: notAfter, RevocationSafeTo: safeTo}, nil
}

func (c *Client) Sign(ctx context.Context, generation int64, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, ErrUnavailable
	}
	request, err := c.newRequest(ctx, SignType, generation, digest)
	if err != nil {
		return nil, err
	}
	response, err := c.execute(ctx, request)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), response.Signature...), nil
}

func (c *Client) Certificate(ctx context.Context) (tls.Certificate, error) {
	snapshot, err := c.Snapshot(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer snapshot.Destroy()
	publicKey, err := x509.ParsePKIXPublicKey(snapshot.PublicKeyDER)
	if err != nil {
		return tls.Certificate{}, ErrUnavailable
	}
	return tls.Certificate{Certificate: cloneDER(snapshot.CertificateDER), PrivateKey: &RemoteSigner{client: c,
		generation: snapshot.Generation, publicKey: publicKey}, Leaf: mustParseCertificate(snapshot.CertificateDER[0])}, nil
}

// CertificateForHandshake binds signing to the TLS handshake lifetime. The
// crypto.Signer interface has no context parameter, so this explicitly keeps
// cancellation from a client hello through the later CertificateVerify sign.
func (c *Client) CertificateForHandshake(ctx context.Context) (tls.Certificate, error) {
	if ctx == nil {
		return tls.Certificate{}, ErrUnavailable
	}
	certificate, err := c.Certificate(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	signer, ok := certificate.PrivateKey.(*RemoteSigner)
	if !ok {
		return tls.Certificate{}, ErrUnavailable
	}
	signer.context = ctx
	return certificate, nil
}

func (c *Client) newRequest(ctx context.Context, kind string, generation int64, digest []byte) (Request, error) {
	if c == nil || ctx == nil {
		return Request{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	deadline, _ := operationContext.Deadline()
	nonce := make([]byte, 32)
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(c.config.Random, nonce); err != nil {
		return Request{}, ErrUnavailable
	}
	defer clear(nonce)
	if _, err := io.ReadFull(c.config.Random, requestID); err != nil {
		return Request{}, ErrUnavailable
	}
	defer clear(requestID)
	return newRequest(kind, "tls_"+hex.EncodeToString(requestID), base64.RawURLEncoding.EncodeToString(nonce), deadline, generation, digest), nil
}

func (c *Client) execute(ctx context.Context, request Request) (Response, error) {
	deadline, err := parseProtocolTime(request.Deadline)
	if err != nil {
		return Response{}, ErrUnavailable
	}
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	document, err := encodeRequest(request, c.config.Now().UTC())
	if err != nil {
		return Response{}, err
	}
	defer clear(document)
	if validateSocket(c.config.SocketPath, c.config.ExpectedUID, c.config.RoleGID) != nil {
		return Response{}, ErrUnavailable
	}
	connectionValue, err := (&net.Dialer{}).DialContext(operationContext, "unix", c.config.SocketPath)
	if err != nil {
		return Response{}, clientError(err)
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return Response{}, ErrUnavailable
	}
	defer connection.Close()
	if connection.SetDeadline(deadline) != nil {
		return Response{}, ErrUnavailable
	}
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != c.config.ExpectedUID || identity.gid != c.config.ExpectedGID {
		return Response{}, ErrUnavailable
	}
	if writeFrame(connection, document, maxRequestBytes) != nil {
		return Response{}, ErrUnavailable
	}
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		return Response{}, clientError(err)
	}
	defer clear(responseDocument)
	return decodeResponse(responseDocument, request, c.config.Now().UTC())
}

type RemoteSigner struct {
	client     *Client
	generation int64
	publicKey  crypto.PublicKey
	context    context.Context
}

func (s *RemoteSigner) Public() crypto.PublicKey {
	if s == nil {
		return nil
	}
	return s.publicKey
}

func (s *RemoteSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, ErrUnavailable
	}
	ctx := s.context
	if ctx == nil {
		ctx = context.Background()
	}
	return s.client.Sign(ctx, s.generation, digest, opts)
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
		if err != nil || count < 1 {
			return ErrUnavailable
		}
		value = value[count:]
	}
	return nil
}

func clientError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrUnavailable
}

func validateSocket(path string, uid, gid uint32) error {
	if !restrictedunix.ValidateSocket(path, restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666, OwnerUID: uid, DirectoryGID: gid}) {
		return ErrUnavailable
	}
	return nil
}

type peerIdentity struct{ uid, gid uint32 }

func socketPeer(connection *net.UnixConn) (peerIdentity, error) { return peerCredentials(connection) }

func publicKeysEqual(first, second any) bool {
	firstKey, firstOK := first.(*ecdsa.PublicKey)
	secondKey, secondOK := second.(*ecdsa.PublicKey)
	return firstOK && secondOK && firstKey.Equal(secondKey)
}

func mustParseCertificate(document []byte) *x509.Certificate {
	certificate, _ := x509.ParseCertificate(document)
	return certificate
}
