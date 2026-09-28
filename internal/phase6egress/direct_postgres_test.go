package phase6egress

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestDirectPostgresBindsOneSourceAndRejectsBrokerOrAlternateTarget(t *testing.T) {
	authority := phase6security.Slice6PostgresAuthority{Owner: "product-runtime", Dialer: "product-runtime",
		PeerEdgeID: "product-postgres", SourceAddress: "172.30.1.2", ServerAddress: "172.30.1.3",
		ServerHost: "postgres.sandbox-runtime.test", ServerPort: 5432, Database: "product",
		SQLRole: "product_runtime", ServerAnchor: phase6security.TrustAnchor{ID: "external-server-ca"}}
	direct := &DirectPostgres{authority: authority, remote: &tls.Config{MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool(), ServerName: authority.ServerHost,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, ErrUnavailable }}}
	config := testPostgresPeerConfig(t)
	if err := direct.Bind(config, &testPostgresPeerGuard{ready: true}); err != nil {
		t.Fatalf("exact direct PostgreSQL binding: %v", err)
	}
	if config.ConnConfig.AfterNetConnect == nil || config.ConnConfig.LookupFunc == nil || config.BeforeAcquire == nil {
		t.Fatal("direct PostgreSQL path lacks revocation or fixed lookup hooks")
	}
	for _, item := range []struct{ network, address string }{
		{"unix", authority.ServerHost + ":5432"},
		{"tcp", "other.test:5432"},
		{"tcp", "172.30.1.3:5432"},
		{"tcp", authority.ServerHost + ":5433"},
	} {
		if connection, err := direct.DialContext(t.Context(), item.network, item.address); err == nil || connection != nil {
			t.Fatalf("alternate direct target %q/%q admitted", item.network, item.address)
		}
	}
	if _, err := config.ConnConfig.LookupFunc(t.Context(), "other.test"); err == nil {
		t.Fatal("alternate DNS authority admitted")
	}
	if addresses, err := config.ConnConfig.LookupFunc(t.Context(), authority.ServerHost); err != nil ||
		len(addresses) != 1 || addresses[0] != authority.ServerHost {
		t.Fatalf("fixed DNS label was altered: %v %v", addresses, err)
	}
	broker := *direct
	broker.authority.BrokerOnly = true
	if err := broker.Bind(testPostgresPeerConfig(t), &testPostgresPeerGuard{ready: true}); err == nil {
		t.Fatal("broker-only Provider admitted to direct PostgreSQL path")
	}
	wrong := testPostgresPeerConfig(t)
	wrong.ConnConfig.Database = "provider"
	if err := direct.Bind(wrong, &testPostgresPeerGuard{ready: true}); err == nil {
		t.Fatal("wrong database admitted to direct PostgreSQL path")
	}
	// Actual .2/.3 topology and cleanup are checked in the Docker gate.
}
