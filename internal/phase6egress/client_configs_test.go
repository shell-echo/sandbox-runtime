package phase6egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
)

func configDialer(protocol, host string, port int) *FixedAlias {
	return &FixedAlias{protocol: protocol, address: net.JoinHostPort(host, strconv.Itoa(port)), lease: time.Minute,
		remote: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: x509.NewCertPool(), ServerName: host,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }}}
}

func TestPostgresConfigRejectsFallbackAndEnvironment(t *testing.T) {
	dialer := configDialer("postgres", "witness.sandbox-runtime.test", 5432)
	newConfig := func(t *testing.T, sslmode string) *pgxpool.Config {
		t.Helper()
		config, err := pgxpool.ParseConfig("postgres://runtime:secret@witness.sandbox-runtime.test:5432/witness?sslmode=" + sslmode)
		if err != nil {
			t.Fatal(err)
		}
		config.MaxConns = 4
		return config
	}
	valid := newConfig(t, "verify-full")
	if err := dialer.BindPostgres(valid); err != nil || valid.ConnConfig.DialFunc == nil || valid.ConnConfig.TLSConfig == nil ||
		valid.ConnConfig.TLSConfig.RootCAs != dialer.remote.RootCAs {
		t.Fatalf("bound PostgreSQL config = %v, %#v", err, valid.ConnConfig)
	}
	if hosts, err := valid.ConnConfig.LookupFunc(context.Background(), "witness.sandbox-runtime.test"); err != nil ||
		len(hosts) != 1 || hosts[0] != "witness.sandbox-runtime.test" {
		t.Fatalf("fixed PostgreSQL lookup = %v, %v", hosts, err)
	}
	if hosts, err := valid.ConnConfig.LookupFunc(context.Background(), "alternate.sandbox-runtime.test"); hosts != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("alternate PostgreSQL lookup = %v, %v", hosts, err)
	}
	if network, address := pgconn.NetworkAddress("witness.sandbox-runtime.test", 5432); network != "tcp" || address != dialer.address {
		t.Fatalf("pgx broker route = %s %s", network, address)
	}
	for name, mutate := range map[string]func(*pgxpool.Config){
		"alternate host":  func(c *pgxpool.Config) { c.ConnConfig.Host = "alternate.sandbox-runtime.test" },
		"plaintext":       func(c *pgxpool.Config) { c.ConnConfig.TLSConfig = nil },
		"verify disabled": func(c *pgxpool.Config) { c.ConnConfig.TLSConfig.InsecureSkipVerify = true },
		"fallback": func(c *pgxpool.Config) {
			c.ConnConfig.Fallbacks = append(c.ConnConfig.Fallbacks, &pgconn.FallbackConfig{Host: "other.sandbox-runtime.test"})
		},
		"direct negotiation": func(c *pgxpool.Config) { c.ConnConfig.SSLNegotiation = "direct" },
		"mutable before connect": func(c *pgxpool.Config) {
			c.BeforeConnect = func(_ context.Context, connection *pgx.ConnConfig) error {
				connection.Host = "alternate.sandbox-runtime.test"
				return nil
			}
		},
		"unreviewed after connect": func(c *pgxpool.Config) {
			c.AfterConnect = func(context.Context, *pgx.Conn) error { return nil }
		},
		"unbounded pool": func(c *pgxpool.Config) { c.MaxConns = 128 },
	} {
		t.Run(name, func(t *testing.T) {
			config := newConfig(t, "verify-full")
			mutate(config)
			if err := dialer.BindPostgres(config); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unsafe PostgreSQL config accepted: %v", err)
			}
		})
	}
	prefer := newConfig(t, "prefer")
	if err := dialer.BindPostgres(prefer); !errors.Is(err, ErrUnavailable) {
		t.Fatal("sslmode=prefer accepted")
	}
	t.Setenv("PGHOST", "alternate.sandbox-runtime.test")
	if err := dialer.BindPostgres(newConfig(t, "verify-full")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("PGHOST override accepted")
	}
}

func TestProviderPostgresUsesOwnAliasAndBoundedRoleSpecificPool(t *testing.T) {
	newConfig := func(t *testing.T, capacity int32) *pgxpool.Config {
		t.Helper()
		config, err := pgxpool.ParseConfig("postgres://browser_provider_runtime:secret@postgres.sandbox-runtime.test:5432/provider_browser?sslmode=verify-full")
		if err != nil {
			t.Fatal(err)
		}
		config.MaxConns = capacity
		return config
	}
	dialer := configDialer("postgres", "postgres.sandbox-runtime.test", 5432)
	dialer.principal, dialer.alias = "provider-browser-runtime", "postgres"
	if err := dialer.BindPostgres(newConfig(t, 64)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("witness pool limit silently expanded")
	}
	valid := newConfig(t, 64)
	if err := dialer.BindProviderPostgres(valid); err != nil || valid.ConnConfig.DialFunc == nil {
		t.Fatalf("exact Provider alias did not bind: %v", err)
	}
	if err := dialer.BindProviderPostgres(newConfig(t, 65)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unbounded Provider pool accepted")
	}
	for _, variant := range []struct{ principal, alias string }{
		{"product-runtime", "postgres"}, {"provider-browser-runtime", "action-history"},
		{"provider-desktop-runtime", "capacity"},
	} {
		dialer.principal, dialer.alias = variant.principal, variant.alias
		if err := dialer.BindProviderPostgres(newConfig(t, 4)); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("cross-role alias accepted: %+v", variant)
		}
	}
}

func TestRedisConfigRequiresProfileTLSAndFixedAddress(t *testing.T) {
	dialer := configDialer("tls", "capacity.sandbox-runtime.test", 6379)
	credentials := CapacityValkeyCredentials{Protocol: capacityCredentialsProtocol, Username: "ingress_capacity", Password: "secret"}
	newOptions := func(t *testing.T, uri string) *goredis.Options {
		t.Helper()
		options, err := goredis.ParseURL(uri)
		if err != nil {
			t.Fatal(err)
		}
		return options
	}
	valid := newOptions(t, "rediss://capacity.sandbox-runtime.test:6379/0")
	if err := dialer.BindRedis(valid, credentials, 2*time.Second); err != nil || valid.Dialer == nil || valid.Protocol != 2 ||
		valid.MaxRetries != -1 || valid.DialerRetries != -1 || valid.MaxActiveConns != 4 || !valid.ContextTimeoutEnabled {
		t.Fatalf("bound Redis config = %v, %#v", err, valid)
	}
	for name, uri := range map[string]string{
		"plaintext":       "redis://capacity.sandbox-runtime.test:6379/0",
		"verify disabled": "rediss://capacity.sandbox-runtime.test:6379/0?skip_verify=true",
		"alternate host":  "rediss://alternate.sandbox-runtime.test:6379/0",
		"alternate db":    "rediss://capacity.sandbox-runtime.test:6379/1",
		"URI credentials": "rediss://runtime:secret@capacity.sandbox-runtime.test:6379/0",
	} {
		t.Run(name, func(t *testing.T) {
			options := newOptions(t, uri)
			if err := dialer.BindRedis(options, credentials, 2*time.Second); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unsafe Redis options accepted: %v", err)
			}
		})
	}
	prewired := newOptions(t, "rediss://capacity.sandbox-runtime.test:6379/0")
	prewired.Dialer = func(context.Context, string, string) (net.Conn, error) { return nil, nil }
	if err := dialer.BindRedis(prewired, credentials, 2*time.Second); !errors.Is(err, ErrUnavailable) {
		t.Fatal("alternate Redis dialer accepted")
	}
	dynamic := newOptions(t, "rediss://capacity.sandbox-runtime.test:6379/0")
	dynamic.CredentialsProvider = func() (string, string) { return "other", "secret" }
	if err := dialer.BindRedis(dynamic, credentials, 2*time.Second); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unbound Redis credentials provider accepted")
	}
}
