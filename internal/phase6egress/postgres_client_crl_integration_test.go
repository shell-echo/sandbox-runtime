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
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
	server := integrationLeaf(t, now, serverCA, serverKey, "postgres.sandbox-runtime.test", "",
		"postgres.sandbox-runtime.test", x509.ExtKeyUsageServerAuth)
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
	poolConfig, err := pgxpool.ParseConfig("postgres://browser_provider_runtime:runtime-secret@127.0.0.1:" + port + "/provider_browser?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	selectedCertificate := bad.Certificate
	poolConfig.MaxConns = 1
	poolConfig.ConnConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: "postgres.sandbox-runtime.test", RootCAs: serverRoot,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &selectedCertificate, nil }}
	poolConfig.BeforeConnect = func(context.Context, *pgx.ConnConfig) error { return nil }
	poolConfig.ConnConfig.AfterNetConnect = func(_ context.Context, _ *pgconn.Config, connection net.Conn) (net.Conn, error) {
		return connection, nil
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
		t.Fatalf("actual guarded PostgreSQL connection failed: %v", err)
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
}

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
