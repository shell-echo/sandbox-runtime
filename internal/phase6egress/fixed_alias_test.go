package phase6egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type testBroker struct {
	connection net.Conn
	err        error
	calls      int
	alias      string
	lease      time.Duration
}

func (b *testBroker) Dial(_ context.Context, alias string, lease time.Duration) (net.Conn, error) {
	b.calls++
	b.alias, b.lease = alias, lease
	return b.connection, b.err
}

type testTracker struct {
	tracked, forgotten int
	reject             bool
}

func (g *testTracker) Track(net.Conn, tls.ConnectionState) error {
	g.tracked++
	if g.reject {
		return ErrUnavailable
	}
	return nil
}

func (g *testTracker) Forget(net.Conn) { g.forgotten++ }

func testFixedAlias(t *testing.T) (*FixedAlias, *testBroker, *testTracker, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	broker := &testBroker{connection: tls.Client(left, &tls.Config{ServerName: "broker.test"})}
	guard := &testTracker{}
	dialer := &FixedAlias{broker: broker, tracker: guard, alias: "action-history", protocol: "postgres",
		address: "witness.sandbox-runtime.test:5432", lease: time.Minute}
	return dialer, broker, guard, right
}

func TestFixedAliasRejectsUnapprovedDialBeforeBroker(t *testing.T) {
	dialer, broker, _, peer := testFixedAlias(t)
	defer peer.Close()
	for _, attempt := range []struct{ network, address string }{
		{"udp", "witness.sandbox-runtime.test:5432"},
		{"tcp", "127.0.0.1:5432"},
		{"tcp", "alternate.sandbox-runtime.test:5432"},
		{"tcp", "witness.sandbox-runtime.test:5433"},
		{"unix", "/run/postgres.sock"},
	} {
		if connection, err := dialer.TunnelDialContext(context.Background(), attempt.network, attempt.address); connection != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("dial %q %q = %v, %v", attempt.network, attempt.address, connection, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialer.TunnelDialContext(ctx, "tcp", dialer.address); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled dial = %v", err)
	}
	if broker.calls != 0 {
		t.Fatalf("unauthorized attempts reached broker: %d", broker.calls)
	}
}

func TestFixedAliasTracksAndExactlyForgetsBrokerTunnel(t *testing.T) {
	dialer, broker, guard, peer := testFixedAlias(t)
	defer peer.Close()
	connection, err := dialer.TunnelDialContext(context.Background(), "tcp", dialer.address)
	if err != nil || connection == nil || broker.calls != 1 || broker.alias != "action-history" || broker.lease != time.Minute || guard.tracked != 1 {
		t.Fatalf("tunnel = %v, %v; broker=%+v tracker=%+v", connection, err, broker, guard)
	}
	_ = connection.Close()
	_ = connection.Close()
	if guard.forgotten != 1 {
		t.Fatalf("broker tunnel forgotten %d times", guard.forgotten)
	}
}

func TestFixedAliasNeverReturnsPlaintextCapacityTunnel(t *testing.T) {
	dialer, broker, _, peer := testFixedAlias(t)
	defer peer.Close()
	dialer.protocol = "tls"
	if connection, err := dialer.TunnelDialContext(context.Background(), "tcp", dialer.address); connection != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("plaintext capacity tunnel = %v, %v", connection, err)
	}
	if broker.calls != 0 {
		t.Fatal("plaintext capacity attempt reached broker")
	}
}

func TestFixedAliasRejectsUntrackedOrFailedBrokerTunnel(t *testing.T) {
	for _, name := range []string{"tracker", "broker", "plaintext"} {
		t.Run(name, func(t *testing.T) {
			dialer, broker, guard, peer := testFixedAlias(t)
			defer peer.Close()
			switch name {
			case "tracker":
				guard.reject = true
			case "broker":
				broker.err = ErrUnavailable
			case "plaintext":
				left, right := net.Pipe()
				defer right.Close()
				broker.connection = left
			}
			connection, err := dialer.TunnelDialContext(context.Background(), "tcp", dialer.address)
			if connection != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("failed tunnel = %v, %v", connection, err)
			}
		})
	}
}

func TestFixedAliasSelectsOnlyRoleOwnedExternalTargets(t *testing.T) {
	profile := phase6security.Profile{
		External: []phase6security.ExternalService{
			{Name: "action-history-postgres", URI: "spiffe://test/witness", DNSNames: []string{"witness.test"}},
			{Name: "capacity-valkey", URI: "spiffe://test/capacity", DNSNames: []string{"capacity.test"}},
		},
		EgressPolicies: []phase6security.EgressPolicy{
			{ID: "browser-action-ingress-egress", Principal: "browser-action-ingress-runtime", LeaseSeconds: 60,
				Targets: []phase6security.EgressTarget{{Alias: "action-history", Host: "witness.test", Port: 5432, Protocol: "postgres"},
					{Alias: "capacity", Host: "capacity.test", Port: 6379, Protocol: "tls"}}},
			{ID: "gateway-egress", Principal: "gateway-runtime", LeaseSeconds: 60,
				Targets: []phase6security.EgressTarget{{Alias: "capacity", Host: "capacity.test", Port: 6379, Protocol: "tls"}}},
		},
	}
	for _, selection := range []struct{ role, alias, service string }{
		{"gateway-runtime", "capacity", "capacity-valkey"},
		{"browser-action-ingress-runtime", "capacity", "capacity-valkey"},
		{"browser-action-ingress-runtime", "action-history", "action-history-postgres"},
	} {
		_, service, lease, err := selectTarget(profile, selection.role, selection.alias)
		if err != nil || service.Name != selection.service || lease != time.Minute {
			t.Fatalf("select %s/%s = %s, %s, %v", selection.role, selection.alias, service.Name, lease, err)
		}
	}
	for _, selection := range []struct{ role, alias string }{
		{"gateway-runtime", "action-history"},
		{"provider-browser-runtime", "capacity"},
		{"browser-action-ingress-runtime", "product-postgres"},
	} {
		if _, _, _, err := selectTarget(profile, selection.role, selection.alias); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("selected unauthorized %s/%s", selection.role, selection.alias)
		}
	}
	profile.EgressPolicies[1].Targets[0].Host = "alternate.test"
	if _, _, _, err := selectTarget(profile, "gateway-runtime", "capacity"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("alternate capacity target accepted")
	}
}

func TestExternalPeerIdentityChecksPreHandshakeCertificateState(t *testing.T) {
	uri, err := url.Parse("spiffe://sandbox-runtime.test/external/action-history-postgres")
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{URIs: []*url.URL{uri}, DNSNames: []string{"witness.sandbox-runtime.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains: [][]*x509.Certificate{{leaf, &x509.Certificate{}}}}
	dialer := &FixedAlias{uri: uri.String(), remote: &tls.Config{ServerName: "witness.sandbox-runtime.test"}}
	if state.HandshakeComplete || dialer.ExternalTLSConfig().VerifyConnection(state) != nil {
		t.Fatal("valid pre-handshake verified peer was rejected")
	}
	leaf.DNSNames[0] = "alternate.sandbox-runtime.test"
	if err := dialer.ExternalTLSConfig().VerifyConnection(state); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("alternate peer accepted: %v", err)
	}
}
