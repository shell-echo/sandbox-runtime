//go:build integration

package phase6egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

// This is a controlled PostgreSQL service diagnostic, not the final Vault CRL
// publication or nine-owner gate. It tests actual new TLS handshakes, not a
// config reload acknowledgement or an on-disk CRL digest alone.
func TestRealPostgresClientCRLActivation(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_POSTGRES_CRL_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_POSTGRES_CRL_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := exec.CommandContext(ctx, "docker", "image", "inspect", postgresClientHBAImage).Output(); err != nil {
		t.Fatalf("pinned PostgreSQL image unavailable: %v", err)
	}
	name := fmt.Sprintf("p6-pg-crl-%d-%d", os.Getpid(), time.Now().UnixNano())
	volume, preparer := name+"-config", name+"-prepare"
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", name).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", preparer).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "volume", "rm", volume).Run()
		if exec.CommandContext(cleanupCtx, "docker", "inspect", name).Run() == nil ||
			exec.CommandContext(cleanupCtx, "docker", "volume", "inspect", volume).Run() == nil {
			t.Error("PostgreSQL CRL diagnostic retained its container or config volume")
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	clientCA, clientKey, _ := integrationCA(t, now, "postgres-client-crl-ca")
	serverCA, serverKey, serverRoot := integrationCA(t, now, "postgres-server-crl-ca")
	server := integrationLeaf(t, now, serverCA, serverKey, "", "spiffe://sandbox-runtime.test/external/postgres",
		"postgres.sandbox-runtime.test", x509.ExtKeyUsageServerAuth)
	t.Run("same-ca-wrong-uri", func(t *testing.T) {
		wrong := integrationLeaf(t, now, serverCA, serverKey, "",
			"spiffe://sandbox-runtime.test/external/other", "postgres.sandbox-runtime.test",
			x509.ExtKeyUsageServerAuth)
		left, right := net.Pipe()
		serverDone := make(chan error, 1)
		go func() {
			serverDone <- tls.Server(right, &tls.Config{MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{wrong.Certificate}}).Handshake()
		}()
		var identityCallbacks atomic.Int32
		client := tls.Client(left, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			ServerName: "postgres.sandbox-runtime.test", RootCAs: serverRoot,
			VerifyConnection: func(state tls.ConnectionState) error {
				if state.HandshakeComplete || len(state.VerifiedChains) != 1 {
					return ErrUnavailable
				}
				identityCallbacks.Add(1)
				return directPostgresVerifyServer(state, "spiffe://sandbox-runtime.test/external/postgres",
					"postgres.sandbox-runtime.test")
			}})
		handshakeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		err := client.HandshakeContext(handshakeCtx)
		stop()
		_ = client.Close()
		_ = right.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Fatal("synthetic TLS server did not close after identity refusal")
		}
		if err == nil || identityCallbacks.Load() != 1 {
			t.Fatalf("same-CA server with wrong URI was admitted or bypassed: callback=%d error=%v",
				identityCallbacks.Load(), err)
		}
	})
	serverCRL := postgresTestCRL(t, now, serverCA, serverKey, 1, nil)
	serverList, err := x509.ParseRevocationList(serverCRL)
	if err != nil {
		t.Fatal(err)
	}
	verifiedServerCRL, err := workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{
		DER: serverCRL, ThisUpdate: serverList.ThisUpdate, NextUpdate: serverList.NextUpdate}, serverCA.Raw, now)
	if err != nil {
		t.Fatal("synthetic server CRL was not complete and valid")
	}
	clientURI := "spiffe://sandbox-runtime.test/provider-browser-runtime"
	bad := integrationLeaf(t, now, clientCA, clientKey, "browser_provider_runtime", clientURI, "", x509.ExtKeyUsageClientAuth)
	good := integrationLeaf(t, now, clientCA, clientKey, "browser_provider_runtime", clientURI, "", x509.ExtKeyUsageClientAuth)
	badLeaf, err := x509.ParseCertificate(bad.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	firstCRL := postgresTestCRL(t, now, clientCA, clientKey, 1, nil)
	bridgeGateway := strings.TrimSpace(runPostgresDocker(t, ctx, "network", "inspect", "-f",
		"{{range .IPAM.Config}}{{.Gateway}}{{end}}", "bridge"))
	if net.ParseIP(bridgeGateway) == nil {
		t.Fatalf("Docker bridge gateway unavailable: %q", bridgeGateway)
	}
	directory := t.TempDir()
	for file, data := range map[string][]byte{
		"server.crt":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate.Certificate[0]}),
		"server.key":    server.PrivateKeyPEM,
		"client-ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw}),
		"client.crl":    pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: firstCRL}),
		"pg_hba.conf": []byte("local all postgres peer\n" +
			"hostssl provider_browser browser_provider_runtime " + bridgeGateway + "/32 scram-sha-256 clientcert=verify-full\n" +
			"host all all 0.0.0.0/0 reject\n" +
			"host all all ::/0 reject\n"),
	} {
		if err := os.WriteFile(filepath.Join(directory, file), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runPostgresDocker(t, ctx, "volume", "create", volume)
	install := func(files ...string) {
		runPostgresDocker(t, ctx, "run", "-d", "--name", preparer, "-u", "0", "-v", volume+":/pg",
			postgresClientHBAImage, "sh", "-c", "sleep 120")
		for _, file := range files {
			runPostgresDocker(t, ctx, "cp", filepath.Join(directory, file), preparer+":/pg/"+file)
		}
		runPostgresDocker(t, ctx, "exec", "-u", "0", preparer, "sh", "-c",
			"chown -R postgres:postgres /pg && chmod 0600 /pg/server.key")
		runPostgresDocker(t, ctx, "rm", "-f", preparer)
	}
	install("server.crt", "server.key", "client-ca.crt", "client.crl", "pg_hba.conf")
	runPostgresDocker(t, ctx, "run", "-d", "--name", name, "-p", "127.0.0.1::5432", "-v", volume+":/pg:ro",
		"-e", "POSTGRES_PASSWORD=admin-only", "-e", "POSTGRES_DB=provider_browser",
		postgresClientHBAImage, "postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/pg/server.crt",
		"-c", "ssl_key_file=/pg/server.key", "-c", "ssl_ca_file=/pg/client-ca.crt",
		"-c", "ssl_crl_file=/pg/client.crl", "-c", "hba_file=/pg/pg_hba.conf")
	portOutput := strings.TrimSpace(runPostgresDocker(t, ctx, "port", name, "5432/tcp"))
	_, port, err := net.SplitHostPort(portOutput)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 80; attempt++ {
		logs, _ := exec.CommandContext(ctx, "docker", "logs", name).CombinedOutput()
		if !strings.Contains(string(logs), "PostgreSQL init process complete; ready for start up.") ||
			strings.Count(string(logs), "database system is ready to accept connections") < 2 {
			if attempt == 79 {
				t.Fatalf("PostgreSQL CRL server did not finish initialization: %.1024s", logs)
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
		probe := exec.CommandContext(ctx, "docker", "exec", "-u", "postgres", name,
			"psql", "-At", "-d", "postgres", "-c", "SELECT 1")
		if output, probeErr := probe.CombinedOutput(); probeErr == nil && strings.TrimSpace(string(output)) == "1" {
			break
		} else if attempt == 79 {
			logs := runPostgresDocker(t, ctx, "logs", name)
			t.Fatalf("PostgreSQL CRL server did not start: %v %.512s; logs %.1024s", probeErr, output, logs)
		}
		time.Sleep(250 * time.Millisecond)
	}
	for _, sql := range []string{
		"CREATE ROLE browser_provider_runtime LOGIN PASSWORD 'runtime-secret'",
		"REVOKE CONNECT ON DATABASE provider_browser FROM PUBLIC",
		"GRANT CONNECT ON DATABASE provider_browser TO browser_provider_runtime",
	} {
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", sql)
	}
	if configured := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
		"psql", "-At", "-d", "postgres", "-c", "SHOW ssl_crl_file")); configured != "/pg/client.crl" {
		t.Fatalf("PostgreSQL did not activate controlled client CRL path: %q", configured)
	}
	connect := func(certificate tls.Certificate) error {
		configuration, err := pgx.ParseConfig("postgres://browser_provider_runtime:runtime-secret@127.0.0.1:" + port + "/provider_browser?sslmode=verify-full")
		if err != nil {
			return err
		}
		configuration.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			ServerName: "postgres.sandbox-runtime.test", RootCAs: serverRoot, Certificates: []tls.Certificate{certificate}}
		connectionCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		connection, err := pgx.ConnectConfig(connectionCtx, configuration)
		if err != nil {
			return err
		}
		defer connection.Close(connectionCtx)
		var identity string
		if err := connection.QueryRow(connectionCtx, "SELECT current_user").Scan(&identity); err != nil || identity != "browser_provider_runtime" {
			return ErrUnavailable
		}
		return nil
	}
	if err := connect(bad.Certificate); err != nil {
		t.Fatalf("unrevoked control certificate rejected: %v", err)
	}
	if err := connect(good.Certificate); err != nil {
		t.Fatalf("healthy control certificate rejected: %v", err)
	}
	clientIdentity := workloadpki.PostgresClientIdentity{OwnerDeployment: "provider-browser-runtime",
		DatabaseName: "provider_browser", RuntimeRole: "browser_provider_runtime", ServiceName: "postgres",
		URI: clientURI, CommonName: "browser_provider_runtime", MaxTTL: time.Hour}
	makeSnapshot := func(certificate integrationCertificate) workloadtlsagent.Snapshot {
		leaf, parseErr := x509.ParseCertificate(certificate.Certificate.Certificate[0])
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		publicDER, marshalErr := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return workloadtlsagent.Snapshot{Generation: 1, IssuerRevision: "controlled-test-ca",
			Serial: postgresOwnSerial(leaf), CertificateDER: certificate.Certificate.Certificate,
			PublicKeyDER: publicDER, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
			RevocationSafeTo: time.Now().Add(20 * time.Second)}
	}
	clientSource := &fakePostgresOwnSource{snapshot: makeSnapshot(bad)}
	ownGuard := &PostgresOwnGuard{source: clientSource, identity: clientIdentity, issuerDER: clientCA.Raw,
		maximumStaleness: 30 * time.Second, timeout: 2 * time.Second, interval: 2 * time.Second,
		closeBudget: time.Second, now: time.Now, active: make(map[net.Conn]postgresOwnSelection)}
	defer ownGuard.Close()
	if err := ownGuard.Refresh(ctx); err != nil {
		t.Fatalf("client signer guard bootstrap failed: %v", err)
	}
	poolConfig, err := pgxpool.ParseConfig("postgres://browser_provider_runtime:runtime-secret@postgres.sandbox-runtime.test:5432/provider_browser?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	selectedCertificate := bad.Certificate
	poolConfig.MaxConns = 1
	var incompleteCallbacks atomic.Int32
	poolConfig.ConnConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: "postgres.sandbox-runtime.test", RootCAs: serverRoot,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &selectedCertificate, nil },
		VerifyConnection: func(state tls.ConnectionState) error {
			if !state.HandshakeComplete {
				incompleteCallbacks.Add(1)
			}
			return directPostgresVerifyServer(state, "spiffe://sandbox-runtime.test/external/postgres",
				"postgres.sandbox-runtime.test")
		}}
	poolConfig.ConnConfig.DialFunc = func(dialContext context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "postgres.sandbox-runtime.test:5432" {
			return nil, ErrUnavailable
		}
		return (&net.Dialer{}).DialContext(dialContext, "tcp", net.JoinHostPort("127.0.0.1", port))
	}
	poolConfig.ConnConfig.LookupFunc = func(_ context.Context, host string) ([]string, error) {
		if host != "postgres.sandbox-runtime.test" {
			return nil, ErrUnavailable
		}
		return []string{host}, nil
	}
	peerGuard := &combinedPostgresPeerGuard{crl: verifiedServerCRL}
	peerAuthority := phase6security.Slice6PostgresAuthority{Owner: "provider-browser-runtime",
		PeerEdgeID: "provider-browser-postgres", ServerHost: "postgres.sandbox-runtime.test",
		ServerPort: 5432, Database: "provider_browser", SQLRole: "browser_provider_runtime",
		ServerAnchor: phase6security.TrustAnchor{ID: "external-server-ca"}}
	if err := BindPostgresPeerGuard(poolConfig, peerAuthority, peerGuard); err != nil {
		t.Fatalf("server peer guard binding failed: %v", err)
	}
	if err := BindPostgresOwnGuard(poolConfig, ownGuard); err != nil {
		t.Fatalf("client signer guard binding failed: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	poolClosed := false
	defer func() {
		if !poolClosed {
			pool.Close()
		}
	}()
	owned, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("actual guarded PostgreSQL connection failed before SQL: incompleteTLSCallbacks=%d peerChecks=%d: %v",
			incompleteCallbacks.Load(), peerGuard.checks.Load(), err)
	}
	if incompleteCallbacks.Load() != 1 || peerGuard.checks.Load() != 1 || peerGuard.tracks.Load() != 1 {
		owned.Release()
		t.Fatalf("first physical PostgreSQL connection bypassed incomplete TLS callback or peer guard: callback=%d checks=%d tracks=%d",
			incompleteCallbacks.Load(), peerGuard.checks.Load(), peerGuard.tracks.Load())
	}
	var actualRole string
	if err := owned.QueryRow(ctx, "SELECT current_user").Scan(&actualRole); err != nil || actualRole != "browser_provider_runtime" {
		owned.Release()
		t.Fatalf("actual guarded PostgreSQL query failed: %v %s", err, actualRole)
	}
	revokedCRL := postgresTestCRL(t, now.Add(time.Second), clientCA, clientKey, 2,
		[]x509.RevocationListEntry{{SerialNumber: badLeaf.SerialNumber, RevocationTime: now}})
	if err := os.WriteFile(filepath.Join(directory, "client.crl"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: revokedCRL}), 0o600); err != nil {
		t.Fatal(err)
	}
	install("client.crl")
	if result := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-At", "-d", "postgres",
		"-c", "SELECT pg_reload_conf()")); result != "t" {
		t.Fatalf("PostgreSQL rejected CRL reload signal: %q", result)
	}
	rejected := false
	for attempt := 0; attempt < 40; attempt++ {
		if err := connect(good.Certificate); err != nil {
			t.Fatalf("healthy control failed after CRL update: %v", err)
		}
		if err := connect(bad.Certificate); err != nil {
			rejected = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !rejected {
		t.Fatal("revoked client certificate still admitted by real PostgreSQL after CRL reload")
	}
	clientSource.mu.Lock()
	clientSource.snapshot = makeSnapshot(good)
	clientSource.mu.Unlock()
	selectedCertificate = good.Certificate
	if err := ownGuard.Refresh(ctx); err != nil {
		owned.Release()
		t.Fatalf("client signer rotation refresh failed: %v", err)
	}
	if err := owned.QueryRow(ctx, "SELECT current_user").Scan(&actualRole); err == nil {
		owned.Release()
		t.Fatal("old-client-leaf PostgreSQL connection survived conservative rotation drain")
	}
	owned.Release()
	if err := pool.QueryRow(ctx, "SELECT current_user").Scan(&actualRole); err != nil || actualRole != "browser_provider_runtime" {
		t.Fatalf("rotated healthy client leaf did not reconnect: %v %s", err, actualRole)
	}
	borrowed, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	queryDone := make(chan error, 1)
	go func() {
		_, queryErr := borrowed.Exec(ctx, "SELECT pg_sleep(30)")
		borrowed.Release()
		queryDone <- queryErr
	}()
	observedActive := false
	for attempt := 0; attempt < 40; attempt++ {
		active := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
			"psql", "-At", "-d", "postgres", "-c",
			"SELECT count(*) FROM pg_stat_activity WHERE usename='browser_provider_runtime' AND state='active' AND query='SELECT pg_sleep(30)'"))
		if active == "1" {
			observedActive = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !observedActive {
		ownGuard.Close()
		select {
		case <-queryDone:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("real PostgreSQL long query did not become active before drain")
	}
	drainStarted := time.Now()
	ownGuard.Close()
	select {
	case queryErr := <-queryDone:
		if queryErr == nil || time.Since(drainStarted) > 2*time.Second {
			t.Fatalf("active PostgreSQL query did not stop within the local drain bound: %v", queryErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active PostgreSQL query survived client guard close")
	}
	pool.Close()
	poolClosed = true
	if len(ownGuard.active) != 0 {
		t.Fatal("PostgreSQL pool close retained guarded client connections")
	}
	if peerGuard.tracks.Load() < 2 || peerGuard.forgets.Load() != peerGuard.tracks.Load() {
		t.Fatalf("combined peer/client guard close retained connection: tracks=%d forgets=%d",
			peerGuard.tracks.Load(), peerGuard.forgets.Load())
	}
	// The same disposable PostgreSQL instance now exercises failed first
	// connections through both production binding functions. All certificates
	// and CRLs are synthetic; no Vault signer or business schema is involved.
	goodOnly := &fakePostgresOwnSource{snapshot: makeSnapshot(good)}
	secondOwn := &PostgresOwnGuard{source: goodOnly, identity: clientIdentity, issuerDER: clientCA.Raw,
		maximumStaleness: 30 * time.Second, timeout: 2 * time.Second, interval: 2 * time.Second,
		closeBudget: time.Second, now: time.Now, active: make(map[net.Conn]postgresOwnSelection)}
	defer secondOwn.Close()
	if err := secondOwn.Refresh(ctx); err != nil {
		t.Fatal("synthetic own-client guard did not refresh")
	}
	otherGood := integrationLeaf(t, now, clientCA, clientKey, "browser_provider_runtime", clientURI, "", x509.ExtKeyUsageClientAuth)
	serverLeaf, err := x509.ParseCertificate(server.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	revokedServerCRL := postgresTestCRL(t, now, serverCA, serverKey, 2,
		[]x509.RevocationListEntry{{SerialNumber: serverLeaf.SerialNumber, RevocationTime: now}})
	revokedList, err := x509.ParseRevocationList(revokedServerCRL)
	if err != nil {
		t.Fatal(err)
	}
	verifiedRevoked, err := workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{
		DER: revokedServerCRL, ThisUpdate: revokedList.ThisUpdate,
		NextUpdate: revokedList.NextUpdate}, serverCA.Raw, now)
	if err != nil {
		t.Fatal("synthetic revoked server CRL was not complete and valid")
	}
	for _, scenario := range []struct {
		name             string
		certificate      tls.Certificate
		crl              workloadpki.VerifiedCRL
		wrongRoot        bool
		expectedIdentity int32
		expectedChecks   int32
		expectedTracks   int32
		expectedForgets  int32
	}{
		{name: "server-identity", certificate: good.Certificate, crl: verifiedServerCRL, wrongRoot: true},
		{name: "server-revoked", certificate: good.Certificate, crl: verifiedRevoked,
			expectedIdentity: 1, expectedChecks: 1},
		{name: "own-leaf-mismatch", certificate: otherGood.Certificate, crl: verifiedServerCRL,
			expectedIdentity: 1, expectedChecks: 1, expectedTracks: 1, expectedForgets: 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			negative, parseErr := pgxpool.ParseConfig("postgres://browser_provider_runtime:runtime-secret@postgres.sandbox-runtime.test:5432/provider_browser?sslmode=verify-full")
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			negative.MaxConns = 1
			roots := serverRoot
			if scenario.wrongRoot {
				_, _, roots = integrationCA(t, now, "untrusted-server-ca")
			}
			var identityCallbacks atomic.Int32
			negative.ConnConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				ServerName: "postgres.sandbox-runtime.test", RootCAs: roots,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &scenario.certificate, nil
				}, VerifyConnection: func(state tls.ConnectionState) error {
					if state.HandshakeComplete {
						return ErrUnavailable
					}
					identityCallbacks.Add(1)
					return directPostgresVerifyServer(state, "spiffe://sandbox-runtime.test/external/postgres",
						"postgres.sandbox-runtime.test")
				}}
			negative.ConnConfig.LookupFunc = poolConfig.ConnConfig.LookupFunc
			negative.ConnConfig.DialFunc = poolConfig.ConnConfig.DialFunc
			peer := &combinedPostgresPeerGuard{crl: scenario.crl}
			if err := BindPostgresPeerGuard(negative, peerAuthority, peer); err != nil {
				t.Fatal(err)
			}
			if err := BindPostgresOwnGuard(negative, secondOwn); err != nil {
				t.Fatal(err)
			}
			var afterSQL atomic.Int32
			negative.AfterConnect = func(context.Context, *pgx.Conn) error {
				afterSQL.Add(1)
				return nil
			}
			candidate, createErr := pgxpool.NewWithConfig(ctx, negative)
			if createErr != nil {
				t.Fatal(createErr)
			}
			attemptCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			connection, acquireErr := candidate.Acquire(attemptCtx)
			stop()
			if connection != nil {
				connection.Release()
			}
			candidate.Close()
			if acquireErr == nil || afterSQL.Load() != 0 || identityCallbacks.Load() != scenario.expectedIdentity ||
				peer.checks.Load() != scenario.expectedChecks ||
				peer.tracks.Load() != scenario.expectedTracks ||
				peer.forgets.Load() != scenario.expectedForgets {
				t.Fatalf("negative first connection did not fail at its closed boundary: error=%v identity=%d peer=%d/%d/%d afterSQL=%d",
					acquireErr, identityCallbacks.Load(), peer.checks.Load(), peer.tracks.Load(), peer.forgets.Load(), afterSQL.Load())
			}
		})
	}
}

// This test peer source uses the same complete signed-CRL verifier as the
// production guard, but not its Vault/Unix client or freshness state machine.
// It isolates the actual pgx TLS callback and dual binding order.
type combinedPostgresPeerGuard struct {
	crl                     workloadpki.VerifiedCRL
	checks, tracks, forgets atomic.Int32
}

func (g *combinedPostgresPeerGuard) CheckHandshake(ctx context.Context, state tls.ConnectionState) error {
	g.checks.Add(1)
	return g.check(ctx, state)
}

func (g *combinedPostgresPeerGuard) Track(_ net.Conn, state tls.ConnectionState) error {
	if err := g.check(context.Background(), state); err != nil {
		return err
	}
	g.tracks.Add(1)
	return nil
}

func (g *combinedPostgresPeerGuard) check(ctx context.Context, state tls.ConnectionState) error {
	if ctx.Err() != nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) != 1 ||
		len(state.VerifiedChains[0]) != 2 || len(state.PeerCertificates) == 0 ||
		!state.PeerCertificates[0].Equal(state.VerifiedChains[0][0]) {
		return ErrUnavailable
	}
	return g.crl.CheckPeer(state.VerifiedChains[0][0].Raw, state.VerifiedChains[0][1].Raw, time.Now())
}

func (g *combinedPostgresPeerGuard) Forget(net.Conn) { g.forgets.Add(1) }
func (g *combinedPostgresPeerGuard) Ready() bool     { return g.crl.Number() != nil }

func postgresTestCRL(t *testing.T, now time.Time, issuer *x509.Certificate, key *ecdsa.PrivateKey,
	number int64, revoked []x509.RevocationListEntry) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(30 * time.Minute),
		RevokedCertificateEntries: revoked}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
