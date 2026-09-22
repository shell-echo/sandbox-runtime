package providerapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
)

const (
	privateDefaultReadHeaderTimeout = 5 * time.Second
	privateDefaultReadTimeout       = 30 * time.Second
	privateDefaultWriteTimeout      = 30 * time.Second
	privateDefaultIdleTimeout       = 60 * time.Second
	privateDefaultMaxHeaderBytes    = 32 << 10
	privateDefaultMaxBodyBytes      = 256 << 10
)

// PrivateTransportOptions constructs the Provider-local adapter listener. It
// deliberately has no Provider Contract handler or DTO dependency; callers
// must provide an adapter-specific handler and a separate trust domain.
type PrivateTransportOptions struct {
	Address                    option.HTTP
	ServerCertificateFile      string
	ServerPrivateKeyFile       string
	ClientCABundleFile         string
	TLSConfig                  *tls.Config
	AllowedClientURIIdentities []string
	Handler                    http.Handler
	ReadHeaderTimeout          time.Duration
	ReadTimeout                time.Duration
	WriteTimeout               time.Duration
	IdleTimeout                time.Duration
	MaxHeaderBytes             int
	MaxBodyBytes               int64
}

// PrivateServer is an independent lifecycle and routing boundary. It cannot
// be mounted on Server's public Contract listener by construction.
type PrivateServer struct {
	http   *http.Server
	listen func(context.Context, string, string) (net.Listener, error)
}

func NewPrivateServer(ctx context.Context, options PrivateTransportOptions) (*PrivateServer, error) {
	if ctx == nil {
		return nil, errors.New("Provider private server construction context is nil")
	}
	if options.Handler == nil {
		return nil, errors.New("Provider private server handler is required")
	}
	if options.Address.Host == "" {
		return nil, errors.New("Provider private server address host must not be empty")
	}
	if err := options.Address.Validate(); err != nil {
		return nil, fmt.Errorf("validate Provider private server address: %w", err)
	}
	var tlsConfig *tls.Config
	var err error
	if options.TLSConfig != nil {
		if options.ServerCertificateFile != "" || options.ServerPrivateKeyFile != "" || options.ClientCABundleFile != "" ||
			options.TLSConfig.MinVersion != tls.VersionTLS13 || options.TLSConfig.MaxVersion != tls.VersionTLS13 ||
			len(options.TLSConfig.Certificates) != 1 || options.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || options.TLSConfig.ClientCAs == nil || options.TLSConfig.VerifyConnection == nil {
			return nil, errors.New("Provider private server frozen TLS configuration is invalid")
		}
		tlsConfig = options.TLSConfig.Clone()
	} else {
		tlsConfig, err = loadMTLSConfig(options.ServerCertificateFile, options.ServerPrivateKeyFile, options.ClientCABundleFile, options.AllowedClientURIIdentities)
	}
	if err != nil {
		return nil, err
	}
	readHeader := options.ReadHeaderTimeout
	if readHeader == 0 {
		readHeader = privateDefaultReadHeaderTimeout
	}
	read := options.ReadTimeout
	if read == 0 {
		read = privateDefaultReadTimeout
	}
	write := options.WriteTimeout
	if write == 0 {
		write = privateDefaultWriteTimeout
	}
	idle := options.IdleTimeout
	if idle == 0 {
		idle = privateDefaultIdleTimeout
	}
	maxHeader := options.MaxHeaderBytes
	if maxHeader == 0 {
		maxHeader = privateDefaultMaxHeaderBytes
	}
	maxBody := options.MaxBodyBytes
	if maxBody == 0 {
		maxBody = privateDefaultMaxBodyBytes
	}
	if readHeader < 100*time.Millisecond || readHeader > 60*time.Second || read < 100*time.Millisecond || read > 5*time.Minute || write < 100*time.Millisecond || write > 5*time.Minute || idle < 100*time.Millisecond || idle > 10*time.Minute || maxHeader < 1024 || maxHeader > 1<<20 || maxBody < 1024 || maxBody > 16<<20 {
		return nil, errors.New("Provider private server limits are invalid")
	}
	handler := boundedPrivateHandler(options.Handler, maxBody)
	return &PrivateServer{
		http: &http.Server{Addr: options.Address.Addr(), Handler: handler, TLSConfig: tlsConfig,
			ReadHeaderTimeout: readHeader, ReadTimeout: read, WriteTimeout: write, IdleTimeout: idle, MaxHeaderBytes: maxHeader},
		listen: (&net.ListenConfig{}).Listen,
	}, nil
}

func boundedPrivateHandler(next http.Handler, maxBody int64) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request == nil || request.Body == nil {
			next.ServeHTTP(writer, request)
			return
		}
		if request.ContentLength > maxBody {
			http.Error(writer, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxBody)
		next.ServeHTTP(writer, request)
	})
}

func (s *PrivateServer) Startup(ctx context.Context) error {
	if s == nil || s.http == nil || s.listen == nil || ctx == nil {
		return errors.New("Provider private server is not initialized")
	}
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("bind Provider private server: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	if err := s.http.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("start Provider private server: %w", err)
	}
	return nil
}

func (s *PrivateServer) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil {
		return nil
	}
	return normalizeProviderShutdownError(s.http.Shutdown(ctx))
}
