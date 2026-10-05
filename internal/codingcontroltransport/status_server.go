// Package codingcontroltransport contains the read-only Provider→Control
// status HTTP endpoint. It cannot activate Docker or synthesize a PG snapshot.
// The production constructor requires a concrete Profile-bound peer CRL
// guard and receipt ledger; v2 role composition remains separately gated.
package codingcontroltransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
)

const CodingStatusPath = "/control/coding"

var (
	ErrInvalidStatusServer = errors.New("invalid Coding Control status server")
	statusDigestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type statusServerConfig struct {
	TLSConfig               *tls.Config
	ListenAddress           string
	ExpectedProviderURI     string
	ProviderPrincipalDigest string
	ProfileDigest           string
	ControlPolicyDigest     string
	OperationTimeout        time.Duration
	Ledger                  *dockercontrol.CodingReceiptLedger
	Clock                   func() time.Time
}

type statusProjector func(*dockercontrol.CodingReceiptLedger, codingcontrolprotocol.Request,
	string, time.Time) (codingcontrolprotocol.Response, error)

type statusPeer interface {
	connectiondrain.PeerMonitor
}

type StatusServer struct {
	config  statusServerConfig
	peer    statusPeer
	project statusProjector
	server  *http.Server
}

// projectStatus reads one ledger-locked receipt/state pair after the transport
// has authenticated the Provider and decoded a status-only request. A missing
// record is an observation, not evidence of physical absence or cleanup.
func projectStatus(ledger *dockercontrol.CodingReceiptLedger, request codingcontrolprotocol.Request,
	peerDigest string, now time.Time) (codingcontrolprotocol.Response, error) {
	if ledger == nil || request.Action != codingcontrolprotocol.ActionStatus ||
		request.Validate(now, peerDigest) != nil {
		return codingcontrolprotocol.Response{}, codingcontrolprotocol.ErrInvalidWire
	}
	receipt, revision, stateDigest, err := ledger.LookupBoundProjection(request.Create, peerDigest, now)
	if errors.Is(err, os.ErrNotExist) {
		return codingcontrolprotocol.Response{Protocol: codingcontrolprotocol.ProtocolID,
			Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus,
			Status:                codingcontrolprotocol.StatusNotFound,
			CreateAuthorityDigest: request.Create.Digest(), EffectID: request.Create.EffectID}, nil
	}
	if err != nil {
		return codingcontrolprotocol.Response{}, err
	}
	return codingcontrolprotocol.ProjectReceipt(request, receipt, revision, stateDigest)
}

// This constructor remains package-private until one complete Profile-v2
// factory supplies its exact TLS/CRL peer and receipt binding. The test-only
// projector hook cannot be selected by a production composition.
func newStatusServer(config statusServerConfig, peer statusPeer, project statusProjector) (*StatusServer, error) {
	uri, err := url.Parse(config.ExpectedProviderURI)
	if config.TLSConfig == nil || config.TLSConfig.MinVersion < tls.VersionTLS13 ||
		config.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert ||
		config.TLSConfig.ClientCAs == nil || config.TLSConfig.InsecureSkipVerify ||
		config.TLSConfig.GetConfigForClient != nil || config.TLSConfig.VerifyConnection == nil ||
		(len(config.TLSConfig.Certificates) == 0 && config.TLSConfig.GetCertificate == nil) ||
		config.ListenAddress == "" || uri == nil || err != nil || uri.Scheme != "spiffe" ||
		uri.Host == "" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" ||
		uri.String() != config.ExpectedProviderURI ||
		!statusDigestPattern.MatchString(config.ProviderPrincipalDigest) ||
		!statusDigestPattern.MatchString(config.ProfileDigest) ||
		!statusDigestPattern.MatchString(config.ControlPolicyDigest) ||
		config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second ||
		config.Clock == nil || config.Ledger == nil || peer == nil ||
		peer.PollInterval() < 100*time.Millisecond || project == nil {
		return nil, ErrInvalidStatusServer
	}
	service := &StatusServer{config: config, peer: peer, project: project}
	service.server = &http.Server{Handler: http.HandlerFunc(service.handle),
		TLSConfig: config.TLSConfig.Clone(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: config.OperationTimeout, WriteTimeout: config.OperationTimeout,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10,
		ConnState: connectiondrain.PeerConnState(peer)}
	return service, nil
}

func (s *StatusServer) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil || listener.Addr().String() != s.config.ListenAddress {
		return ErrInvalidStatusServer
	}
	stopPoll := connectiondrain.StartPeerPoll(ctx, s.peer)
	defer stopPoll()
	defer s.peer.Close()
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

func (s *StatusServer) Close() error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Close()
}

func (s *StatusServer) handle(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if s == nil || request == nil || !s.authenticated(request) || !s.peer.Ready() {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != CodingStatusPath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		len(request.Header.Values("Content-Type")) != 1 ||
		request.Header.Get("Content-Type") != "application/json" ||
		request.Header.Get("Content-Encoding") != "" ||
		request.ContentLength < 1 || request.ContentLength > codingcontrolprotocol.MaxRequestBytes ||
		len(request.TransferEncoding) != 0 {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), s.config.OperationTimeout)
	defer cancel()
	if s.peer.Poll(ctx) != nil || !s.peer.Ready() || ctx.Err() != nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	document, err := io.ReadAll(io.LimitReader(request.Body, codingcontrolprotocol.MaxRequestBytes+1))
	defer clear(document)
	if err != nil || int64(len(document)) != request.ContentLength || ctx.Err() != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	now := s.config.Clock().UTC()
	bound, err := codingcontrolprotocol.DecodeRequest(document, now, s.config.ProviderPrincipalDigest)
	if err != nil || bound.Action != codingcontrolprotocol.ActionStatus ||
		bound.Create.ProfileDigest != s.config.ProfileDigest ||
		bound.Create.ControlPolicyDigest != s.config.ControlPolicyDigest {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	response, err := s.project(s.config.Ledger, bound, s.config.ProviderPrincipalDigest, now)
	if err != nil || response.Validate(bound) != nil || ctx.Err() != nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	encoded, err := codingcontrolprotocol.EncodeResponse(response)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func (s *StatusServer) authenticated(request *http.Request) bool {
	if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.VerifiedChains) != 1 || len(request.TLS.VerifiedChains[0]) < 2 ||
		len(request.TLS.PeerCertificates) < 1 || request.TLS.PeerCertificates[0] == nil {
		return false
	}
	leaf := request.TLS.PeerCertificates[0]
	return len(leaf.URIs) == 1 && leaf.URIs[0].String() == s.config.ExpectedProviderURI &&
		len(leaf.Raw) != 0 &&
		request.TLS.VerifiedChains[0][0] != nil &&
		bytes.Equal(request.TLS.VerifiedChains[0][0].Raw, leaf.Raw)
}
