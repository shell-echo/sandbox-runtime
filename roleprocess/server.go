// Package roleprocess supplies the transport boundary shared by the Phase 6
// Gateway, Guest, Browser, and Desktop role commands. It intentionally has no
// Product, Provider, or local-instance handler.
package roleprocess

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/gateway/edge"
	"github.com/shell-echo/sandbox-runtime/internal/phase6profile"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/providerapi"
	providerprocess "github.com/shell-echo/sandbox-runtime/providerapi/process"
	"github.com/shell-echo/sandbox-runtime/server"
)

type readinessFunc func(context.Context) error

func (f readinessFunc) Ready(ctx context.Context) error { return f(ctx) }

type Composition struct {
	cfg     *config.DataPlaneProcessConfig
	public  server.Server
	private server.Server
	probe   server.Server
}

// New constructs only the listener/probe graph. Role applications are supplied
// by later slices and are not silently fabricated by this boundary package.
// Every non-probe route is a bodyless 404 until a role-specific handler is
// explicitly composed by the owning command.
func New(ctx context.Context, cfg *config.DataPlaneProcessConfig) (*Composition, error) {
	if ctx == nil || cfg == nil || !cfg.Enabled {
		return nil, errors.New("enabled data-plane role configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	frozen := *cfg
	frozen.TLS.AllowedClientIdentity = append([]string(nil), cfg.TLS.AllowedClientIdentity...)
	cfg = &frozen
	ready := readinessFunc(func(checkContext context.Context) error { return checkReadiness(checkContext, cfg) })
	probe, err := providerprocess.NewServer(cfg.Probe, ready)
	if err != nil {
		return nil, err
	}
	composition := &Composition{cfg: cfg, probe: probe}
	missing := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNotFound)
	})
	switch cfg.Role {
	case config.DataPlaneGateway:
		public, publicErr := edge.NewTLSServer(edge.ServerOptions{
			Address: cfg.Public.Addr(), Handler: missing,
			ServerCertificateFile: cfg.TLS.CertificateFile, ServerPrivateKeyFile: cfg.TLS.PrivateKeyFile,
			MaxConnections: 1000, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		})
		if publicErr != nil {
			return nil, publicErr
		}
		composition.public = public
	case config.DataPlaneBrowser, config.DataPlaneDesktop:
		private, privateErr := newPrivateTLSServer(cfg.Private.Addr(), missing, cfg.TLS)
		if privateErr != nil {
			return nil, privateErr
		}
		composition.private = private
	case config.DataPlaneGuest:
		// Guest is outbound-only. It intentionally has no inbound listener.
	default:
		return nil, errors.New("unsupported data-plane role")
	}
	return composition, nil
}

// checkReadiness verifies only process-owned inputs. It deliberately does
// not claim that a complete Gateway/Guest/Browser/Desktop application graph
// exists: those role-specific adapters must replace the bounded route before
// a deployment can advertise readiness.
func checkReadiness(ctx context.Context, cfg *config.DataPlaneProcessConfig) error {
	if ctx == nil || cfg == nil {
		return errors.New("role readiness is not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, path := range []string{cfg.Authority.CredentialFile, cfg.Authority.DependencyFile, cfg.Authority.PolicyFile} {
		contents, err := secretfile.Read(path, 64<<10)
		if err != nil {
			return errors.New("role authority is unavailable")
		}
		clear(contents)
	}
	if _, err := secretref.Parse(cfg.Authority.RecordingKeyRef); err != nil {
		return errors.New("role recording authority is unavailable")
	}
	if cfg.Authority.ReleaseProfile != "" {
		profile, err := phase6profile.VerifyFile(cfg.Authority.ReleaseProfile)
		if err != nil {
			return errors.New("role release profile is unavailable")
		}
		found := false
		for _, role := range profile.Roles {
			if role.Name == string(cfg.Role) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("role release profile does not contain this role")
		}
	}
	if config.Phase6Dependencies == nil {
		return errors.New("role dependencies are unavailable")
	}
	if err := config.Phase6Dependencies.Validate(); err != nil {
		return errors.New("role dependencies are unavailable")
	}
	return errors.New("role application graph is not composed")
}

func (c *Composition) Startup(ctx context.Context) error {
	if c == nil || c.probe == nil {
		return errors.New("role composition is not initialized")
	}
	servers := map[string]server.Server{"probe": c.probe}
	if c.public != nil {
		servers["public"] = c.public
	}
	if c.private != nil {
		servers["private"] = c.private
	}
	return server.RunE(servers)
}

func (c *Composition) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	var result error
	for _, srv := range []server.Server{c.public, c.private, c.probe} {
		if srv != nil {
			result = errors.Join(result, srv.Shutdown(ctx))
		}
	}
	return result
}

type privateTLSServer struct {
	http   *http.Server
	config *tls.Config
	listen func(context.Context, string, string) (net.Listener, error)
}

func newPrivateTLSServer(address string, handler http.Handler, tlsConfig config.DataPlaneTLSConfig) (*privateTLSServer, error) {
	transport, err := providerapi.LoadMTLSConfig(tlsConfig.CertificateFile, tlsConfig.PrivateKeyFile, tlsConfig.ClientCABundleFile, tlsConfig.AllowedClientIdentity)
	if err != nil {
		return nil, err
	}
	return &privateTLSServer{
		http:   &http.Server{Addr: address, Handler: handler, TLSConfig: transport, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10},
		config: transport, listen: (&net.ListenConfig{}).Listen,
	}, nil
}

func (s *privateTLSServer) Startup(ctx context.Context) error {
	if s == nil || s.http == nil || s.config == nil || ctx == nil {
		return errors.New("private role server is not initialized")
	}
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return errors.New("bind private role server")
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	if err := s.http.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return errors.New("serve private role server")
	}
	return nil
}

func (s *privateTLSServer) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}
