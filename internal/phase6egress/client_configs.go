package phase6egress

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
)

// RejectPostgresEnvironment prevents libpq-style environment defaults from
// adding a host, TLS mode, service file or fallback outside the fixed witness
// target. The production process must rely only on its purpose-bound secret.
func RejectPostgresEnvironment() error {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PG") {
			return ErrUnavailable
		}
	}
	return nil
}

// BindPostgres replaces pgx's network path with the single witnessed broker
// tunnel and the profile-pinned external TLS verifier. Call this before pool
// construction; a parsed configuration with fallback/plaintext/alternate
// address is rejected rather than normalized into apparent safety.
func (d *FixedAlias) BindPostgres(config *pgxpool.Config) error {
	return d.bindPostgres(config, 16)
}

// BindProviderPostgres keeps the existing witness ceiling at 16 while using
// the separately validated Provider pool bound (up to 64). Only the exact
// Provider-owned postgres alias may call this path.
func (d *FixedAlias) BindProviderPostgres(config *pgxpool.Config) error {
	if d == nil || d.alias != "postgres" ||
		(d.principal != "provider-browser-runtime" && d.principal != "provider-desktop-runtime") {
		return ErrUnavailable
	}
	return d.bindPostgres(config, 64)
}

func (d *FixedAlias) bindPostgres(config *pgxpool.Config, maxConnections int32) error {
	if d == nil || d.protocol != "postgres" || d.remote == nil || config == nil || config.ConnConfig == nil ||
		RejectPostgresEnvironment() != nil {
		return ErrUnavailable
	}
	host, port, err := net.SplitHostPort(d.address)
	if err != nil || config.ConnConfig.Host != host || fmt.Sprint(config.ConnConfig.Port) != port ||
		config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify ||
		config.ConnConfig.TLSConfig.ServerName != host || len(config.ConnConfig.Fallbacks) != 0 ||
		(config.ConnConfig.SSLNegotiation != "" && config.ConnConfig.SSLNegotiation != "postgres") ||
		config.BeforeConnect != nil || config.AfterConnect != nil || config.ConnConfig.AfterNetConnect != nil || config.ConnConfig.User == "" ||
		config.ConnConfig.Password == "" || config.ConnConfig.Database == "" ||
		config.MaxConns < 1 || config.MaxConns > maxConnections {
		return ErrUnavailable
	}
	config.ConnConfig.TLSConfig = d.ExternalTLSConfig()
	config.ConnConfig.DialFunc = d.TunnelDialContext
	// pgx resolves DNS before DialFunc; returning the unchanged, exact host
	// keeps DNS entirely inside the alias-only broker instead.
	config.ConnConfig.LookupFunc = func(ctx context.Context, candidate string) ([]string, error) {
		if ctx == nil || ctx.Err() != nil || candidate != host {
			return nil, ErrUnavailable
		}
		return []string{host}, nil
	}
	return nil
}

// BindRedis ensures go-redis's custom Dialer performs the external TLS layer:
// that library does not automatically wrap a connection returned by Dialer.
func (d *FixedAlias) BindRedis(options *goredis.Options, credentials CapacityValkeyCredentials, operationTimeout time.Duration) error {
	if d == nil || d.protocol != "tls" || d.remote == nil || options == nil ||
		!credentials.valid() || options.Username != "" || options.Password != "" ||
		options.CredentialsProvider != nil || options.CredentialsProviderContext != nil ||
		options.StreamingCredentialsProvider != nil ||
		operationTimeout < time.Second || operationTimeout > 5*time.Second || operationTimeout >= d.lease ||
		options.Addr != d.address || options.Network != "tcp" || options.DB != 0 ||
		options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify ||
		options.TLSConfig.ServerName != d.remote.ServerName || options.Dialer != nil ||
		options.PoolSize > 16 || options.MinIdleConns != 0 {
		return ErrUnavailable
	}
	options.TLSConfig = d.ExternalTLSConfig()
	options.Dialer = d.TLSDialContext
	options.Username = credentials.Username
	options.Password = credentials.Password
	options.Protocol = 2
	options.MaxRetries = -1
	options.DialerRetries = -1
	options.ContextTimeoutEnabled = true
	options.DisableIdentity = true
	options.PoolSize = 4
	options.MaxActiveConns = 4
	options.DialTimeout = operationTimeout
	options.ReadTimeout = operationTimeout
	options.WriteTimeout = operationTimeout
	options.PoolTimeout = operationTimeout
	return nil
}
