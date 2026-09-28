//go:build integration

package phase6egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

const postgresClientHBAImage = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"

func TestRealPostgresRequiresExactClientCNAndScramRole(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_POSTGRES_CLIENT_HBA_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_POSTGRES_CLIENT_HBA_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	name := fmt.Sprintf("sr-pg-client-hba-%d-%d", os.Getpid(), time.Now().UnixNano())
	volume := name + "-config"
	preparer := name + "-prepare"
	remoteClient := name + "-other-source"
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = exec.Command("docker", "rm", "-f", remoteClient).Run()
			_ = exec.Command("docker", "rm", "-f", preparer).Run()
			_ = exec.Command("docker", "rm", "-f", name).Run()
			_ = exec.Command("docker", "volume", "rm", volume).Run()
		}
	})
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	clientCA, clientKey, clientRoot := integrationCA(t, now, "postgres-client-ca")
	serverCA, serverKey, serverRoot := integrationCA(t, now, "postgres-server-ca")
	server := integrationLeaf(t, now, serverCA, serverKey, "postgres.sandbox-runtime.test", "", "postgres.sandbox-runtime.test", x509.ExtKeyUsageServerAuth)
	browserCN := workloadpki.PostgresClientCommonName("browser_provider_runtime")
	desktopCN := workloadpki.PostgresClientCommonName("desktop_provider_runtime")
	browser := integrationLeaf(t, now, clientCA, clientKey, browserCN,
		"spiffe://sandbox-runtime.test/provider-browser-runtime", "", x509.ExtKeyUsageClientAuth)
	desktop := integrationLeaf(t, now, clientCA, clientKey, desktopCN,
		"spiffe://sandbox-runtime.test/provider-desktop-runtime", "", x509.ExtKeyUsageClientAuth)
	wrongCN := integrationLeaf(t, now, clientCA, clientKey, "unmapped-provider",
		"spiffe://sandbox-runtime.test/provider-browser-runtime", "", x509.ExtKeyUsageClientAuth)
	ordinary := integrationLeaf(t, now, clientCA, clientKey, "",
		"spiffe://sandbox-runtime.test/provider-browser-runtime", "", x509.ExtKeyUsageClientAuth)
	wrongPurpose := integrationLeaf(t, now, clientCA, clientKey, browserCN,
		"spiffe://sandbox-runtime.test/provider-browser-runtime", "", x509.ExtKeyUsageServerAuth)
	otherCA, otherKey, _ := integrationCA(t, now, "untrusted-postgres-client-ca")
	wrongIssuer := integrationLeaf(t, now, otherCA, otherKey, browserCN,
		"spiffe://sandbox-runtime.test/provider-browser-runtime", "", x509.ExtKeyUsageClientAuth)
	wrongURI := integrationLeaf(t, now, clientCA, clientKey, browserCN,
		"spiffe://sandbox-runtime.test/provider-desktop-runtime", "", x509.ExtKeyUsageClientAuth)
	browserIdentity := workloadpki.PostgresClientIdentity{OwnerDeployment: "provider-browser-runtime",
		DatabaseName: "provider_browser", RuntimeRole: "browser_provider_runtime", ServiceName: "postgres",
		URI: "spiffe://sandbox-runtime.test/provider-browser-runtime", CommonName: browserCN, MaxTTL: time.Hour}
	if validatePostgresClientCertificate(browser.Certificate, clientRoot, browserIdentity, now) != nil ||
		validatePostgresClientCertificate(wrongURI.Certificate, clientRoot, browserIdentity, now) == nil {
		t.Fatal("local PostgreSQL client admission failed to bind the URI that PostgreSQL itself cannot inspect")
	}
	approvedHBA := func(sourceCIDR string) []byte {
		policy := phase6security.PostgresServerAuthPolicy{ID: "provider-postgres-auth",
			Scope: "provider_databases_only", IngressCIDR: sourceCIDR}
		document, err := policy.RenderProviderHBA([]phase6security.ProviderDatabaseBinding{
			{OwnerDeployment: "provider-browser-runtime", DatabaseName: "provider_browser",
				RuntimeRole: "browser_provider_runtime", ServerAuthPolicyID: policy.ID},
			{OwnerDeployment: "provider-desktop-runtime", DatabaseName: "provider_desktop",
				RuntimeRole: "desktop_provider_runtime", ServerAuthPolicyID: policy.ID},
		})
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	bridgeGateway := strings.TrimSpace(runPostgresDocker(t, ctx, "network", "inspect", "-f",
		"{{range .IPAM.Config}}{{.Gateway}}{{end}}", "bridge"))
	if parsed := net.ParseIP(bridgeGateway); parsed == nil || parsed.To4() == nil {
		t.Fatalf("Docker bridge gateway cannot be used as a preapproved PostgreSQL ingress source: %q", bridgeGateway)
	}
	approvedSourceCIDR := bridgeGateway + "/32"
	approvedHBABytes := approvedHBA(approvedSourceCIDR)
	clientCABytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw})
	for file, data := range map[string][]byte{
		"server.crt":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate.Certificate[0]}),
		"server.key":         server.PrivateKeyPEM,
		"server-ca.crt":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw}),
		"client-ca.crt":      clientCABytes,
		"browser-client.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: browser.Certificate.Certificate[0]}),
		"browser-client.key": browser.PrivateKeyPEM,
		"pg_hba.conf":        approvedHBABytes,
	} {
		if err := os.WriteFile(filepath.Join(directory, file), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runPostgresDocker(t, ctx, "volume", "create", volume)
	runPostgresDocker(t, ctx, "run", "-d", "--name", preparer, "-u", "0", "-v", volume+":/pg",
		postgresClientHBAImage, "sh", "-c", "sleep 120")
	runPostgresDocker(t, ctx, "cp", directory+"/.", preparer+":/pg/")
	runPostgresDocker(t, ctx, "exec", "-u", "0", preparer, "sh", "-c",
		"chown -R postgres:postgres /pg && chmod 0600 /pg/server.key /pg/browser-client.key")
	runPostgresDocker(t, ctx, "rm", "-f", preparer)
	runPostgresDocker(t, ctx, "run", "-d", "--name", name, "-p", "127.0.0.1::5432", "-v", volume+":/pg:ro",
		"-e", "POSTGRES_PASSWORD=postgres-hba-admin", "-e", "POSTGRES_DB=provider_browser",
		postgresClientHBAImage, "postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/pg/server.crt",
		"-c", "ssl_key_file=/pg/server.key", "-c", "ssl_ca_file=/pg/client-ca.crt",
		"-c", "hba_file=/pg/pg_hba.conf")
	portOutput := strings.TrimSpace(runPostgresDocker(t, ctx, "port", name, "5432/tcp"))
	_, port, err := net.SplitHostPort(portOutput)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 60; attempt++ {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if !strings.Contains(string(logs), "PostgreSQL init process complete; ready for start up.") ||
			strings.Count(string(logs), "database system is ready to accept connections") < 2 {
			if attempt == 59 {
				t.Fatalf("PostgreSQL final server did not start: %.2048s", logs)
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
		probe := exec.CommandContext(ctx, "docker", "exec", "-u", "postgres", name,
			"psql", "-At", "-d", "postgres", "-c", "SELECT 1")
		if output, probeErr := probe.CombinedOutput(); probeErr == nil && strings.TrimSpace(string(output)) == "1" {
			break
		} else if attempt == 59 {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Fatalf("PostgreSQL failed to start with strict TLS/HBA configuration: %v %s; logs: %.2048s", probeErr, output, logs)
		}
		time.Sleep(250 * time.Millisecond)
	}
	for _, statement := range []string{
		"CREATE DATABASE provider_desktop",
		"CREATE ROLE browser_provider_runtime LOGIN PASSWORD 'browser-secret'",
		"CREATE ROLE desktop_provider_runtime LOGIN PASSWORD 'desktop-secret'",
		"REVOKE CONNECT ON DATABASE provider_browser FROM PUBLIC",
		"REVOKE CONNECT ON DATABASE provider_desktop FROM PUBLIC",
		"GRANT CONNECT ON DATABASE provider_browser TO browser_provider_runtime",
		"GRANT CONNECT ON DATABASE provider_desktop TO desktop_provider_runtime",
	} {
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", statement)
	}
	for _, query := range []string{
		"SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL",
	} {
		output := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
			"psql", "-At", "-d", "postgres", "-c", query))
		if output != "0" {
			t.Fatalf("PostgreSQL rejected strict authentication configuration: %s = %s", query, output)
		}
	}
	var observedSourceCIDR string
	connect := func(database, role, password string, certificate *tls.Certificate) error {
		configuration, parseErr := pgx.ParseConfig(fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=verify-full", role, password, port, database))
		if parseErr != nil {
			return parseErr
		}
		configuration.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: serverRoot, ServerName: "postgres.sandbox-runtime.test"}
		if certificate != nil {
			configuration.TLSConfig.Certificates = []tls.Certificate{*certificate}
		}
		connectionCtx, stop := context.WithTimeout(ctx, 4*time.Second)
		defer stop()
		connection, connectErr := pgx.ConnectConfig(connectionCtx, configuration)
		if connectErr != nil {
			return connectErr
		}
		defer connection.Close(connectionCtx)
		var observedDatabase, observedRole, observedAddress string
		if err := connection.QueryRow(connectionCtx, "SELECT current_database(), current_user, inet_client_addr()::text").Scan(
			&observedDatabase, &observedRole, &observedAddress); err != nil {
			return err
		}
		t.Logf("observed PostgreSQL session: database=%s role=%s source=%s", observedDatabase, observedRole, observedAddress)
		address, _, found := strings.Cut(observedAddress, "/")
		if !found || observedDatabase != database || observedRole != role || net.ParseIP(address) == nil {
			return ErrUnavailable
		}
		observedSourceCIDR = observedAddress
		return nil
	}
	if err := connect("provider_browser", "browser_provider_runtime", "browser-secret", &browser.Certificate); err != nil {
		t.Fatalf("exact Browser certificate + SCRAM login failed: %v", err)
	}
	if observedSourceCIDR != approvedSourceCIDR {
		t.Fatalf("PostgreSQL saw source %q, not the preapproved ingress %q", observedSourceCIDR, approvedSourceCIDR)
	}
	replaceHBA := func(document []byte) {
		if err := os.WriteFile(filepath.Join(directory, "pg_hba.conf"), document, 0o600); err != nil {
			t.Fatal(err)
		}
		runPostgresDocker(t, ctx, "run", "-d", "--name", preparer, "-u", "0", "-v", volume+":/pg",
			postgresClientHBAImage, "sh", "-c", "sleep 120")
		runPostgresDocker(t, ctx, "cp", filepath.Join(directory, "pg_hba.conf"), preparer+":/pg/pg_hba.conf")
		runPostgresDocker(t, ctx, "exec", "-u", "0", preparer, "chown", "postgres:postgres", "/pg/pg_hba.conf")
		runPostgresDocker(t, ctx, "rm", "-f", preparer)
	}
	if mount := strings.TrimSpace(runPostgresDocker(t, ctx, "inspect", "-f",
		"{{range .Mounts}}{{if eq .Destination \"/pg\"}}{{.Name}}|{{.RW}}{{end}}{{end}}", name)); mount != volume+"|false" {
		t.Fatalf("PostgreSQL configuration is not the expected read-only volume: %q", mount)
	}
	for setting, expectedPath := range map[string]string{"hba_file": "/pg/pg_hba.conf", "ssl_ca_file": "/pg/client-ca.crt"} {
		actual := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
			"psql", "-At", "-d", "postgres", "-c", "SHOW "+setting))
		if actual != expectedPath {
			t.Fatalf("PostgreSQL %s does not refer to the controlled artifact: %q", setting, actual)
		}
	}
	verifyRawArtifacts := func(stage string) {
		hbaSum, caSum := sha256.Sum256(approvedHBABytes), sha256.Sum256(clientCABytes)
		policy := phase6security.PostgresServerAuthPolicy{ID: "provider-postgres-auth",
			Scope: "provider_databases_only", IngressCIDR: approvedSourceCIDR,
			HBADigest:        "sha256:" + hex.EncodeToString(hbaSum[:]),
			ClientCAAnchorID: "postgres-client-ca"}
		anchor := phase6security.TrustAnchor{ID: "postgres-client-ca", Purpose: "client_verification",
			BundleDigest: "sha256:" + hex.EncodeToString(caSum[:])}
		databases := []phase6security.ProviderDatabaseBinding{
			{OwnerDeployment: "provider-browser-runtime", DatabaseName: "provider_browser",
				RuntimeRole: "browser_provider_runtime", ServerAuthPolicyID: policy.ID},
			{OwnerDeployment: "provider-desktop-runtime", DatabaseName: "provider_desktop",
				RuntimeRole: "desktop_provider_runtime", ServerAuthPolicyID: policy.ID},
		}
		actualHBA := []byte(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "cat", "/pg/pg_hba.conf"))
		actualCA := []byte(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "cat", "/pg/client-ca.crt"))
		if err := policy.VerifyRawServerArtifacts(databases, anchor, actualHBA, actualCA, time.Now()); err != nil {
			t.Fatalf("%s PostgreSQL raw HBA/CA artifacts differ from the approved policy: %v", stage, err)
		}
		if err := policy.VerifyRawServerArtifacts(databases, anchor, append(append([]byte(nil), actualHBA...), ' '), actualCA, time.Now()); err == nil {
			t.Fatal("changed PostgreSQL HBA bytes admitted")
		}
		if err := policy.VerifyRawServerArtifacts(databases, anchor, actualHBA, append(append([]byte(nil), actualCA...), ' '), time.Now()); err == nil {
			t.Fatal("changed PostgreSQL client CA bytes admitted")
		}
	}
	verifyRawArtifacts("initial")
	for file, document := range map[string][]byte{
		"pg_hba.conf":   approvedHBABytes,
		"client-ca.crt": clientCABytes,
	} {
		sum := sha256.Sum256(document)
		expected := hex.EncodeToString(sum[:])
		fields := strings.Fields(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "sha256sum", "/pg/"+file))
		if len(fields) != 2 || fields[0] != expected || fields[1] != "/pg/"+file {
			t.Fatalf("PostgreSQL %s bytes differ from controlled artifact", file)
		}
	}
	lockedRules := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
		"psql", "-At", "-d", "postgres", "-c",
		"SELECT string_agg(type || '|' || array_to_string(database, ',') || '|' || array_to_string(user_name, ',') || '|' || coalesce(address, '') || '|' || coalesce(netmask, '') || '|' || auth_method || '|' || coalesce(array_to_string(options, ','), ''), E'\\n' ORDER BY rule_number) FROM pg_hba_file_rules"))
	address, _, _ := strings.Cut(observedSourceCIDR, "/")
	expectedRules := "local|all|postgres|||peer|\n" +
		"hostssl|provider_browser|browser_provider_runtime|" + address + "|255.255.255.255|scram-sha-256|clientcert=verify-full\n" +
		"hostssl|provider_desktop|desktop_provider_runtime|" + address + "|255.255.255.255|scram-sha-256|clientcert=verify-full\n" +
		"host|all|all|0.0.0.0|0.0.0.0|reject|\n" +
		"host|all|all|::|::|reject|"
	if lockedRules != expectedRules {
		t.Fatalf("parsed PostgreSQL HBA file differs from exact scoped authority:\n%s", lockedRules)
	}
	t.Logf("final parsed source-restricted PostgreSQL HBA file:\n%s", lockedRules)
	if err := connect("provider_browser", "browser_provider_runtime", "browser-secret", &browser.Certificate); err != nil {
		t.Fatalf("source-restricted Browser certificate + SCRAM login failed: %v", err)
	}
	if err := connect("provider_desktop", "desktop_provider_runtime", "desktop-secret", &desktop.Certificate); err != nil {
		t.Fatalf("exact Desktop certificate + SCRAM login failed: %v", err)
	}
	serverIP := strings.TrimSpace(runPostgresDocker(t, ctx, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name))
	if net.ParseIP(serverIP) == nil {
		t.Fatal("PostgreSQL container address unavailable for alternate-source check")
	}
	runPostgresDocker(t, ctx, "run", "-d", "--name", remoteClient, "--network", "bridge",
		"--add-host", "postgres.sandbox-runtime.test:"+serverIP,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"-u", "postgres", "-v", volume+":/pg:ro", postgresClientHBAImage, "sh", "-c", "sleep 120")
	remoteIP := strings.TrimSpace(runPostgresDocker(t, ctx, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", remoteClient))
	if net.ParseIP(remoteIP) == nil || remoteIP == address {
		t.Fatalf("alternate source is not distinct from approved PostgreSQL source: %q", remoteIP)
	}
	t.Logf("alternate PostgreSQL client source=%s, approved source=%s", remoteIP, address)
	rejectRemote := func() {
		remote := exec.CommandContext(ctx, "docker", "exec", remoteClient, "env", "PGPASSWORD=browser-secret",
			"psql", "host=postgres.sandbox-runtime.test port=5432 dbname=provider_browser user=browser_provider_runtime sslmode=verify-full sslrootcert=/pg/server-ca.crt sslcert=/pg/browser-client.crt sslkey=/pg/browser-client.key",
			"-At", "-c", "SELECT 1")
		if output, err := remote.CombinedOutput(); err == nil || !strings.Contains(string(output), "pg_hba.conf rejects connection") {
			t.Fatalf("alternate-source PostgreSQL connection was not denied by HBA: %v %.512s", err, output)
		}
	}
	rejectRemote()
	for name, attempt := range map[string]struct {
		database, role, password string
		certificate              *tls.Certificate
		rejection                string
	}{
		"missing certificate":           {"provider_browser", "browser_provider_runtime", "browser-secret", nil, "connection requires a valid client certificate (SQLSTATE 28000)"},
		"wrong CN":                      {"provider_browser", "browser_provider_runtime", "browser-secret", &wrongCN.Certificate, "password authentication failed for user \"browser_provider_runtime\" (SQLSTATE 28P01)"},
		"ordinary workload certificate": {"provider_browser", "browser_provider_runtime", "browser-secret", &ordinary.Certificate, "password authentication failed for user \"browser_provider_runtime\" (SQLSTATE 28P01)"},
		"wrong issuer":                  {"provider_browser", "browser_provider_runtime", "browser-secret", &wrongIssuer.Certificate, "connection requires a valid client certificate (SQLSTATE 28000)"},
		"wrong purpose":                 {"provider_browser", "browser_provider_runtime", "browser-secret", &wrongPurpose.Certificate, "tls: unsupported certificate"},
		"cross owner":                   {"provider_browser", "browser_provider_runtime", "browser-secret", &desktop.Certificate, "password authentication failed for user \"browser_provider_runtime\" (SQLSTATE 28P01)"},
		"cross database":                {"provider_desktop", "browser_provider_runtime", "browser-secret", &browser.Certificate, "pg_hba.conf rejects connection"},
		"wrong SCRAM password":          {"provider_browser", "browser_provider_runtime", "wrong", &browser.Certificate, "password authentication failed for user \"browser_provider_runtime\" (SQLSTATE 28P01)"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := connect(attempt.database, attempt.role, attempt.password, attempt.certificate); err == nil {
				t.Fatal("PostgreSQL admitted a mismatched client certificate or SQL role")
			} else if !strings.Contains(err.Error(), attempt.rejection) {
				t.Fatalf("PostgreSQL rejected for an unexpected reason: %v", err)
			}
		})
	}
	malformedHBA := []byte("local all postgres peer\n" +
		"hostssl provider_browser browser_provider_runtime " + observedSourceCIDR + " not-an-auth-method\n" +
		"host all all 0.0.0.0/0 reject\n")
	replaceHBA(malformedHBA)
	if errors := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
		"psql", "-At", "-d", "postgres", "-c", "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")); errors == "0" {
		t.Fatal("malformed disk HBA was not visible in parsed file view")
	}
	if result := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
		"psql", "-At", "-d", "postgres", "-c", "SELECT pg_reload_conf()")); result != "t" {
		t.Fatalf("PostgreSQL did not accept malformed HBA reload signal: %q", result)
	}
	for attempt := 0; attempt < 20; attempt++ {
		logs := runPostgresDocker(t, ctx, "logs", name)
		if strings.Contains(logs, "invalid authentication method") && strings.Contains(logs, "pg_hba.conf") {
			break
		}
		if attempt == 19 {
			t.Fatal("PostgreSQL did not report the malformed HBA reload")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := connect("provider_browser", "browser_provider_runtime", "browser-secret", &browser.Certificate); err != nil {
		t.Fatalf("malformed on-disk HBA unexpectedly displaced the prior loaded rule: %v", err)
	}
	rejectRemote()
	replaceHBA(approvedHBA(observedSourceCIDR))
	if result := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
		"psql", "-At", "-d", "postgres", "-c", "SELECT pg_reload_conf()")); result != "t" {
		t.Fatalf("PostgreSQL approved HBA restore signal failed: %q", result)
	}
	if errors := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
		"psql", "-At", "-d", "postgres", "-c", "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")); errors != "0" {
		t.Fatalf("restored PostgreSQL HBA still has parse errors: %q", errors)
	}
	if err := connect("provider_browser", "browser_provider_runtime", "browser-secret", &browser.Certificate); err != nil {
		t.Fatalf("approved HBA restore did not admit the Browser certificate and role: %v", err)
	}
	rejectRemote()
	runPostgresDocker(t, ctx, "restart", name)
	for attempt := 0; attempt < 60; attempt++ {
		probe := exec.CommandContext(ctx, "docker", "exec", "-u", "postgres", name,
			"psql", "-At", "-d", "postgres", "-c", "SELECT 1")
		if output, err := probe.CombinedOutput(); err == nil && strings.TrimSpace(string(output)) == "1" {
			break
		} else if attempt == 59 {
			t.Fatalf("restarted PostgreSQL did not become locally ready: %v %.512s", err, output)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if mount := strings.TrimSpace(runPostgresDocker(t, ctx, "inspect", "-f",
		"{{range .Mounts}}{{if eq .Destination \"/pg\"}}{{.Name}}|{{.RW}}{{end}}{{end}}", name)); mount != volume+"|false" {
		t.Fatalf("restarted PostgreSQL lost the controlled read-only volume: %q", mount)
	}
	verifyRawArtifacts("restarted")
	for file, document := range map[string][]byte{
		"pg_hba.conf":   approvedHBABytes,
		"client-ca.crt": clientCABytes,
	} {
		sum := sha256.Sum256(document)
		fields := strings.Fields(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "sha256sum", "/pg/"+file))
		if len(fields) != 2 || fields[0] != hex.EncodeToString(sum[:]) || fields[1] != "/pg/"+file {
			t.Fatalf("restarted PostgreSQL %s bytes differ from controlled artifact", file)
		}
	}
	if rules := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", name,
		"psql", "-At", "-d", "postgres", "-c",
		"SELECT string_agg(type || '|' || array_to_string(database, ',') || '|' || array_to_string(user_name, ',') || '|' || coalesce(address, '') || '|' || coalesce(netmask, '') || '|' || auth_method || '|' || coalesce(array_to_string(options, ','), ''), E'\\n' ORDER BY rule_number) FROM pg_hba_file_rules")); rules != expectedRules {
		t.Fatalf("restarted PostgreSQL parsed a different HBA file:\n%s", rules)
	}
	restartedPortOutput := strings.TrimSpace(runPostgresDocker(t, ctx, "port", name, "5432/tcp"))
	_, restartedPort, err := net.SplitHostPort(restartedPortOutput)
	if err != nil {
		t.Fatalf("restarted PostgreSQL published port unavailable: %v", err)
	}
	port = restartedPort
	for attempt := 0; attempt < 60; attempt++ {
		err := connect("provider_browser", "browser_provider_runtime", "browser-secret", &browser.Certificate)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "connection refused") || attempt == 59 {
			t.Fatalf("restarted PostgreSQL did not admit Browser role: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := connect("provider_desktop", "desktop_provider_runtime", "desktop-secret", &desktop.Certificate); err != nil {
		t.Fatalf("restarted PostgreSQL did not admit Desktop role: %v", err)
	}
	rejectRemote()
	runPostgresDocker(t, ctx, "rm", "-f", remoteClient)
	if retained := strings.TrimSpace(runPostgresDocker(t, ctx, "ps", "-aq", "--filter", "name=^/"+remoteClient+"$")); retained != "" {
		t.Fatal("alternate-source client container retained")
	}
	runPostgresDocker(t, context.Background(), "rm", "-f", name)
	runPostgresDocker(t, context.Background(), "volume", "rm", volume)
	cleaned = true
	if retained := strings.TrimSpace(runPostgresDocker(t, context.Background(), "ps", "-aq", "--filter", "name=^/"+name+"$")); retained != "" {
		t.Fatal("PostgreSQL integration container retained")
	}
	if _, err := exec.Command("docker", "volume", "inspect", volume).Output(); err == nil {
		t.Fatal("PostgreSQL integration config volume retained")
	}
}

type integrationCertificate struct {
	Certificate   tls.Certificate
	PrivateKeyPEM []byte
}

func integrationCA(t *testing.T, now time.Time, commonName string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: keyID[:20]}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certificate, key, roots
}

func integrationLeaf(t *testing.T, now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	commonName, uri, dns string, usage x509.ExtKeyUsage) integrationCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial,
		Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if uri != "" {
		parsed, parseErr := url.Parse(uri)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		template.URIs = []*url.URL{parsed}
	}
	if dns != "" {
		template.DNSNames = []string{dns}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return integrationCertificate{Certificate: tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key},
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})}
}

func runPostgresDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %.512s", args[0], err, output)
	}
	return string(output)
}
