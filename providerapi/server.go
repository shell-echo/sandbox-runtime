package providerapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

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
	AllowedClientURIIdentities []string
	Protected                  *ProtectedTransportOptions
}

// Server is the dedicated mTLS-only Provider API server. Construction loads
// and freezes both TLS material and the capability response before Startup can
// accept traffic.
type Server struct {
	http              *http.Server
	identityAdmission *clientIdentityAdmission
	listen            func(context.Context, string, string) (net.Listener, error)
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

	handler, err := newCapabilitiesHandler(ctx, source)
	if err != nil {
		return nil, err
	}
	tlsConfig, identityAdmission, err := loadMTLSConfigWithIdentity(
		options.ServerCertificateFile,
		options.ServerPrivateKeyFile,
		options.ClientCABundleFile,
		options.AllowedClientURIIdentities,
	)
	if err != nil {
		return nil, err
	}
	rootHandler := handler
	maxHeaderBytes := providerMaxHeaderBytes
	if options.Protected != nil {
		protected, protectedErr := newProtectedHandler(identityAdmission, *options.Protected)
		if protectedErr != nil {
			return nil, protectedErr
		}
		rootHandler = &providerHandler{capabilities: handler, protected: protected}
		maxHeaderBytes = providerProtectedMaxHeaderBytes
	}

	listenConfig := &net.ListenConfig{}
	return &Server{
		identityAdmission: identityAdmission,
		http: &http.Server{
			Addr:              options.Address.Addr(),
			Handler:           rootHandler,
			TLSConfig:         tlsConfig,
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
// are intentional: the validated key pair is already frozen in TLSConfig.
func (s *Server) Startup(ctx context.Context) error {
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("bind Provider API server: %w", err)
	}
	stopClosingListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClosingListener()

	if err := s.http.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("start Provider API server: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the Provider listener within the caller's
// deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	return normalizeProviderShutdownError(s.http.Shutdown(ctx))
}

func normalizeProviderShutdownError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
