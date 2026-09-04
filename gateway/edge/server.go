package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/netutil"
)

const (
	MaxAcceptedConnections = 10_000
	MinHTTPTimeout         = 100 * time.Millisecond
	MaxHTTPTimeout         = 5 * time.Minute
	MinHTTPHeaderBytes     = 1 << 10
	MaxHTTPHeaderBytes     = 1 << 20

	maxPublicCertificateBytes = 128 << 10
	maxPublicPrivateKeyBytes  = 64 << 10
)

var ErrInvalidServerOptions = errors.New("invalid Browser public-edge server options")

// ServerOptions contains the complete process-local listener, TLS, and HTTP
// policy for a caller-owned public Gateway. No unbounded defaults are supplied.
type ServerOptions struct {
	Address               string
	Handler               http.Handler
	ServerCertificateFile string
	ServerPrivateKeyFile  string
	MaxConnections        int
	ReadHeaderTimeout     time.Duration
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	MaxHeaderBytes        int
}

// TLSServer bounds accepted connections before TLS and serves only TLS 1.3
// HTTP/1.1. The Browser Gateway's authentication and routing remain in Handler.
type TLSServer struct {
	http           *http.Server
	maxConnections int
	listen         func(context.Context, string, string) (net.Listener, error)
}

func NewTLSServer(options ServerOptions) (*TLSServer, error) {
	if err := validateServerOptions(options); err != nil {
		return nil, err
	}
	tlsConfig, err := loadPublicTLSConfig(options.ServerCertificateFile, options.ServerPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: TLS material: %w", ErrInvalidServerOptions, err)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	listenConfig := &net.ListenConfig{}
	return &TLSServer{
		http: &http.Server{
			Addr:              options.Address,
			Handler:           options.Handler,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: options.ReadHeaderTimeout,
			ReadTimeout:       options.ReadTimeout,
			WriteTimeout:      options.WriteTimeout,
			IdleTimeout:       options.IdleTimeout,
			MaxHeaderBytes:    options.MaxHeaderBytes,
			Protocols:         protocols,
		},
		maxConnections: options.MaxConnections,
		listen:         listenConfig.Listen,
	}, nil
}

func validateServerOptions(options ServerOptions) error {
	host, portText, err := net.SplitHostPort(options.Address)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("%w: TCP address", ErrInvalidServerOptions)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65_535 {
		return fmt.Errorf("%w: TCP port", ErrInvalidServerOptions)
	}
	if options.Handler == nil || nilDependency(options.Handler) {
		return fmt.Errorf("%w: HTTP handler", ErrInvalidServerOptions)
	}
	if options.MaxConnections < 1 || options.MaxConnections > MaxAcceptedConnections {
		return fmt.Errorf("%w: accepted connection limit", ErrInvalidServerOptions)
	}
	for name, value := range map[string]time.Duration{
		"read header timeout": options.ReadHeaderTimeout,
		"read timeout":        options.ReadTimeout,
		"write timeout":       options.WriteTimeout,
		"idle timeout":        options.IdleTimeout,
	} {
		if value < MinHTTPTimeout || value > MaxHTTPTimeout {
			return fmt.Errorf("%w: %s", ErrInvalidServerOptions, name)
		}
	}
	if options.ReadTimeout < options.ReadHeaderTimeout {
		return fmt.Errorf("%w: read timeout is shorter than header timeout", ErrInvalidServerOptions)
	}
	if options.MaxHeaderBytes < MinHTTPHeaderBytes || options.MaxHeaderBytes > MaxHTTPHeaderBytes {
		return fmt.Errorf("%w: HTTP header budget", ErrInvalidServerOptions)
	}
	if options.ServerCertificateFile == "" || options.ServerPrivateKeyFile == "" {
		return fmt.Errorf("%w: TLS certificate and private key paths", ErrInvalidServerOptions)
	}
	return nil
}

// Startup binds the listener, applies the accepted-connection limit before
// TLS, and serves until Shutdown or caller cancellation completes.
func (s *TLSServer) Startup(ctx context.Context) error {
	if s == nil || s.http == nil || s.listen == nil || s.maxConnections < 1 {
		return ErrUnavailable
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil startup context", ErrUnavailable)
	}
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("bind Browser public edge: %w", err)
	}
	limited := netutil.LimitListener(listener, s.maxConnections)
	stopClosingListener := context.AfterFunc(ctx, func() { _ = limited.Close() })
	defer stopClosingListener()

	if err := s.http.ServeTLS(limited, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("serve Browser public edge: %w", err)
	}
	return nil
}

func (s *TLSServer) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil shutdown context", ErrUnavailable)
	}
	err := s.http.Shutdown(ctx)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func loadPublicTLSConfig(certificatePath, privateKeyPath string) (*tls.Config, error) {
	certificatePEM, err := readBoundedPublicTLSFile(certificatePath, maxPublicCertificateBytes)
	if err != nil {
		return nil, fmt.Errorf("read server certificate: %w", err)
	}
	privateKeyPEM, err := readBoundedPublicTLSFile(privateKeyPath, maxPublicPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read server private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}
	if err := validatePublicServerCertificate(certificate, time.Now()); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func readBoundedPublicTLSFile(path string, maxBytes int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}
	file, err := openRegularPublicTLSFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return contents, nil
}

func validatePublicServerCertificate(certificate tls.Certificate, now time.Time) error {
	if len(certificate.Certificate) == 0 {
		return errors.New("server certificate chain is empty")
	}
	for index, raw := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse server certificate %d: %w", index, err)
		}
		if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
			return fmt.Errorf("server certificate %d is outside its validity period", index)
		}
		if index == 0 && !hasPublicServerAuth(parsed) {
			return errors.New("server leaf certificate lacks explicit server-auth usage")
		}
	}
	return nil
}

func hasPublicServerAuth(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	found := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return false
		}
		if usage == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	return found
}
