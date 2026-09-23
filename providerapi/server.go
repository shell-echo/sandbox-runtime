package providerapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

const (
	providerReadHeaderTimeout       = 10 * time.Second
	providerReadTimeout             = 30 * time.Second
	providerWriteTimeout            = 30 * time.Second
	providerIdleTimeout             = 120 * time.Second
	providerMaxHeaderBytes          = 8 << 10
	providerProtectedHeaderReserve  = 8 << 10
	providerProtectedMaxHeaderBytes = admission.MaxAdmissionContextBytes + maxCompactBearerBytes + providerProtectedHeaderReserve
)

// TransportOptions contains only the process-local inputs needed to construct
// the dedicated Provider HTTPS listener. TLS policy is deliberately fixed by
// this package and cannot be weakened through configuration.
type TransportOptions struct {
	Address                    option.HTTP
	ServerCertificateFile      string
	ServerPrivateKeyFile       string
	ClientCABundleFile         string
	TLSConfig                  *tls.Config
	AllowedClientURIIdentities []string
	Protected                  *ProtectedTransportOptions
	ConnectionMaxAge           time.Duration
	PeerRevocationMonitor      PeerRevocationMonitor
}

// Server is the dedicated mTLS-only Provider API server. Construction validates
// either an exclusive live signer or a historical frozen identity and freezes
// the capability response before Startup can accept traffic.
type Server struct {
	http              *http.Server
	identityAdmission *clientIdentityAdmission
	listen            func(context.Context, string, string) (net.Listener, error)
	connections       *connectiondrain.Registry
	peerRevocation    PeerRevocationMonitor
}

// NewServer constructs the complete Provider transport boundary. It is the
// only exported path to the package's HTTP handler, preventing callers from
// accidentally serving Provider routes without the required mTLS admission.
func NewServer(ctx context.Context, options TransportOptions, source provider.CapabilityReader) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("Provider server construction context is nil")
	}
	if strings.TrimSpace(options.Address.Host) == "" {
		return nil, errors.New("Provider server address host must not be empty")
	}
	if err := options.Address.Validate(); err != nil {
		return nil, fmt.Errorf("validate Provider server address: %w", err)
	}

	snapshot, err := readCapabilitySnapshot(ctx, source)
	if err != nil {
		return nil, err
	}
	handler, err := newCapabilitiesHandlerFromSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	var tlsConfig *tls.Config
	var identityAdmission *clientIdentityAdmission
	if options.TLSConfig != nil {
		if options.ServerCertificateFile != "" || options.ServerPrivateKeyFile != "" || options.ClientCABundleFile != "" {
			return nil, errors.New("Provider server TLS configuration mixes static material")
		}
		if options.TLSConfig.GetCertificate != nil && options.ConnectionMaxAge == 0 {
			return nil, errors.New("Provider live Contract TLS requires a bounded connection lifetime")
		}
		tlsConfig, err = cloneStrictProviderMTLS(options.TLSConfig)
		if err != nil {
			return nil, err
		}
		identityAdmission, err = bindProviderClientAdmission(tlsConfig, options.AllowedClientURIIdentities)
	} else {
		tlsConfig, identityAdmission, err = loadMTLSConfigWithIdentity(
			options.ServerCertificateFile,
			options.ServerPrivateKeyFile,
			options.ClientCABundleFile,
			options.AllowedClientURIIdentities,
		)
	}
	if options.PeerRevocationMonitor != nil && (options.TLSConfig == nil || options.ConnectionMaxAge == 0 ||
		options.PeerRevocationMonitor.PollInterval() < 100*time.Millisecond ||
		options.PeerRevocationMonitor.PollInterval() > time.Minute) {
		return nil, errors.New("Provider peer revocation monitor requires bounded live TLS")
	}
	if err != nil {
		return nil, err
	}
	rootHandler := handler
	maxHeaderBytes := providerMaxHeaderBytes
	if options.Protected != nil {
		protectedOptions := *options.Protected
		protectedOptions.capabilitySnapshot = snapshot
		protected, protectedErr := newProtectedHandler(identityAdmission, protectedOptions)
		if protectedErr != nil {
			return nil, protectedErr
		}
		rootHandler = &providerHandler{capabilities: handler, protected: protected}
		maxHeaderBytes = providerProtectedMaxHeaderBytes
	}
	var connections *connectiondrain.Registry
	if options.ConnectionMaxAge != 0 {
		connections, err = connectiondrain.New(options.ConnectionMaxAge)
		if err != nil {
			return nil, errors.New("Provider Contract connection lifetime is invalid")
		}
		if options.PeerRevocationMonitor != nil && connections.OnClose(options.PeerRevocationMonitor.Forget) != nil {
			return nil, errors.New("Provider peer revocation cleanup is unavailable")
		}
	}

	listenConfig := &net.ListenConfig{}
	return &Server{
		identityAdmission: identityAdmission,
		connections:       connections,
		peerRevocation:    options.PeerRevocationMonitor,
		http: &http.Server{
			Addr:              options.Address.Addr(),
			Handler:           rootHandler,
			TLSConfig:         tlsConfig,
			ConnState:         peerRevocationConnState(options.PeerRevocationMonitor),
			ReadHeaderTimeout: providerReadHeaderTimeout,
			ReadTimeout:       providerReadTimeout,
			WriteTimeout:      providerWriteTimeout,
			IdleTimeout:       providerIdleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
		},
		listen: listenConfig.Listen,
	}, nil
}

type providerHandler struct {
	capabilities http.Handler
	protected    http.Handler
}

func (h *providerHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == capabilitiesPath {
		h.capabilities.ServeHTTP(response, request)
		return
	}
	h.protected.ServeHTTP(response, request)
}

// Startup serves HTTPS until Shutdown completes. Empty certificate arguments
// are intentional: the TLS identity is supplied by the validated TLSConfig.
func (s *Server) Startup(ctx context.Context) error {
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("bind Provider API server: %w", err)
	}
	if s.connections != nil {
		tracked, trackErr := s.connections.Wrap(listener)
		if trackErr != nil {
			_ = listener.Close()
			return errors.New("track Provider Contract connections")
		}
		listener = tracked
		defer s.connections.Drain()
	}
	stopClosingListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClosingListener()
	if s.peerRevocation != nil {
		defer s.peerRevocation.Close()
	}
	stopPeerPoll := startPeerRevocationPoll(ctx, s.peerRevocation)
	defer stopPeerPoll()

	if err := s.http.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("start Provider API server: %w", err)
	}
	return nil
}

// Shutdown stops the Provider listener and closes tracked live connections,
// including sockets no longer owned by net/http after a hijack.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.connections != nil {
		s.connections.Drain()
	}
	if s.peerRevocation != nil {
		s.peerRevocation.Close()
	}
	return normalizeProviderShutdownError(s.http.Shutdown(ctx))
}

func normalizeProviderShutdownError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
