package artifactscanner

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	"github.com/shell-echo/sandbox-runtime/provider/artifact/staging"
)

const scanAuthorityHeader = "X-Sandbox-Scan-Authority"

type scanConnectionKey struct{}

type MalwareEngine interface {
	Ready(context.Context) error
	Scan(context.Context, []byte) (MalwareVerdict, error)
}

// RuleAuthority verifies an immutable, operator-checked complete rule set.
// Its production implementation must verify signed rule assets, engine/config
// binding and the 72-hour trusted-check age before and after every scan.
type RuleAuthority interface {
	Verify(context.Context, time.Time) (string, error)
}

type ServiceConfig struct {
	TLSConfig         *tls.Config
	ExpectedClientURI string
	ProfileDigest     string
	OperationTimeout  time.Duration
	Engine            MalwareEngine
	Rules             RuleAuthority
	Peer              connectiondrain.PeerMonitor
	Clock             func() time.Time
}

type Service struct {
	config ServiceConfig
	server *http.Server
	active chan struct{}
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.TLSConfig == nil || config.TLSConfig.MinVersion < tls.VersionTLS13 ||
		config.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || config.TLSConfig.ClientCAs == nil ||
		config.TLSConfig.InsecureSkipVerify ||
		config.TLSConfig.GetConfigForClient != nil ||
		config.TLSConfig.VerifyConnection == nil ||
		(len(config.TLSConfig.Certificates) == 0 && config.TLSConfig.GetCertificate == nil) ||
		config.ExpectedClientURI == "" || !scanDigestPattern.MatchString(config.ProfileDigest) ||
		config.OperationTimeout < time.Second || config.OperationTimeout > maxAuthorityAge ||
		config.Engine == nil || config.Rules == nil || config.Peer == nil ||
		config.Peer.PollInterval() < 100*time.Millisecond || config.Clock == nil {
		return nil, ErrInvalidScanProtocol
	}
	service := &Service{config: config, active: make(chan struct{}, 1)}
	service.server = &http.Server{Handler: http.HandlerFunc(service.handle), TLSConfig: config.TLSConfig.Clone(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: maxAuthorityAge,
		WriteTimeout: maxAuthorityAge, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10,
		ConnState: connectiondrain.PeerConnState(config.Peer),
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			return context.WithValue(ctx, scanConnectionKey{}, connection)
		}}
	return service, nil
}

func (s *Service) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil {
		return ErrInvalidScanProtocol
	}
	stopPeerPoll := connectiondrain.StartPeerPoll(ctx, s.config.Peer)
	defer stopPeerPoll()
	defer s.config.Peer.Close()
	s.server.BaseContext = func(net.Listener) context.Context { return ctx }
	shutdownDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(shutdownDone)
		drain, cancel := context.WithTimeout(context.Background(), s.config.OperationTimeout)
		defer cancel()
		_ = s.server.Shutdown(drain)
		_ = s.server.Close()
	})
	defer func() {
		if stop() {
			close(shutdownDone)
		}
		<-shutdownDone
	}()
	err := s.server.Serve(tls.NewListener(listener, s.config.TLSConfig.Clone()))
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Service) Close() error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Close()
}

func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.handle) }

func (s *Service) handle(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if s == nil || request == nil || !s.authenticated(request) || !s.config.Peer.Ready() {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == "/readyz" && request.URL.RawQuery == "" {
		select {
		case s.active <- struct{}{}:
			defer func() { <-s.active }()
		default:
			http.Error(writer, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), s.config.OperationTimeout)
		defer cancel()
		rulesDigest, err := s.ready(ctx)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("X-Sandbox-Rule-Set-Digest", rulesDigest)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/scan" || request.URL.RawQuery != "" ||
		request.Header.Get("Content-Type") != "application/octet-stream" || len(request.Header.Values(scanAuthorityHeader)) != 1 ||
		request.ContentLength < 1 || request.ContentLength > artifact.MaxArtifactBytes || len(request.TransferEncoding) != 0 {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		http.Error(writer, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	authorityHeader := request.Header.Get(scanAuthorityHeader)
	encoded, err := base64.RawURLEncoding.DecodeString(authorityHeader)
	if err != nil || base64.RawURLEncoding.EncodeToString(encoded) != authorityHeader {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	now := s.config.Clock().UTC()
	authority, err := DecodeAuthority(encoded, now)
	if err != nil || authority.ProfileDigest != s.config.ProfileDigest {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	deadline := s.config.Clock().UTC().Add(s.config.OperationTimeout)
	if authority.ExpiresAt.Before(deadline) {
		deadline = authority.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(request.Context(), deadline)
	defer cancel()
	rulesDigest, err := s.config.Rules.Verify(ctx, now)
	if err != nil || !scanDigestPattern.MatchString(rulesDigest) {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	content, err := readScanBody(ctx, request)
	if err != nil || ctx.Err() != nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if int64(len(content)) != request.ContentLength || scanDigest(content) != authority.ContentDigest {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	response := Response{Protocol: ProtocolID, RequestID: authority.RequestID,
		AuthorityDigest: authority.Digest(), ContentDigest: authority.ContentDigest,
		RuleSetDigest: rulesDigest, Active: artifact.CheckNotRun, Malware: artifact.CheckNotRun}
	response.Active, err = staging.NewPassiveJSONChecker().CheckContent(ctx,
		artifact.Request{ExpectedMediaType: authority.MediaType}, content)
	if err != nil || response.Active == artifact.CheckNotRun {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if response.Active == artifact.CheckPassed {
		verdict, scanErr := s.config.Engine.Scan(ctx, content)
		if scanErr != nil {
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		switch verdict {
		case MalwareClean:
			response.Malware = artifact.CheckPassed
		case MalwareInfected:
			response.Malware = artifact.CheckFailed
		default:
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	}
	response.CheckedAt = s.config.Clock().UTC()
	verifiedDigest, err := s.config.Rules.Verify(ctx, response.CheckedAt)
	if err != nil || verifiedDigest != rulesDigest || ctx.Err() != nil || response.Validate(authority, response.CheckedAt) != nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	encodedResponse, err := EncodeResponse(response)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encodedResponse)
}

func readScanBody(ctx context.Context, request *http.Request) ([]byte, error) {
	if connection, ok := request.Context().Value(scanConnectionKey{}).(net.Conn); ok {
		deadline, exists := ctx.Deadline()
		if !exists || connection.SetReadDeadline(deadline) != nil {
			return nil, ErrInvalidScanProtocol
		}
		finished := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			_ = connection.SetReadDeadline(time.Now())
			close(finished)
		})
		defer func() {
			if stop() {
				close(finished)
			}
			<-finished
			_ = connection.SetReadDeadline(time.Time{})
		}()
	}
	return io.ReadAll(io.LimitReader(request.Body, artifact.MaxArtifactBytes+1))
}

func (s *Service) authenticated(request *http.Request) bool {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return false
	}
	leaf := request.TLS.PeerCertificates[0]
	return len(leaf.URIs) == 1 && leaf.URIs[0].String() == s.config.ExpectedClientURI
}

func (s *Service) ready(ctx context.Context) (string, error) {
	if err := s.config.Peer.Poll(ctx); err != nil || !s.config.Peer.Ready() {
		return "", ErrInvalidScanProtocol
	}
	digest, err := s.config.Rules.Verify(ctx, s.config.Clock().UTC())
	if err != nil || !scanDigestPattern.MatchString(digest) {
		return "", ErrInvalidScanProtocol
	}
	if err := s.config.Engine.Ready(ctx); err != nil {
		return "", err
	}
	return digest, nil
}
