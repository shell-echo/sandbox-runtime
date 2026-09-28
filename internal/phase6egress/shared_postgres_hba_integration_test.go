//go:build integration

package phase6egress

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This opt-in diagnostic runs one real PostgreSQL 16 instance on all nine
// dedicated isolated service bridges. It proves the final raw HBA's source,
// CN and SCRAM behavior, not Vault issuance, SQL grants, command startup or
// the complete Slice 6 release gate.
func TestRealSharedPostgresNineSourceHBA(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_SHARED_POSTGRES_HBA_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_SHARED_POSTGRES_HBA_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rules, err := phase6security.Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil || len(rules) != 9 {
		t.Fatalf("final HBA source rules: %v", err)
	}
	hba, err := phase6security.RenderSlice6DesiredFinalSharedPostgresHBA()
	if err != nil {
		t.Fatal(err)
	}
	stamp := fmt.Sprintf("p6-shared-hba-%d-%d", os.Getpid(), time.Now().UnixNano())
	serverName := stamp + "-postgres"
	networkNames, volumeNames, containerNames := []string{}, []string{}, []string{}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		for i := len(containerNames) - 1; i >= 0; i-- {
			name := containerNames[i]
			_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", name).Run()
			if err := exec.CommandContext(cleanupCtx, "docker", "inspect", name).Run(); err == nil {
				t.Errorf("diagnostic container %s remains", name)
			}
		}
		for i := len(networkNames) - 1; i >= 0; i-- {
			name := networkNames[i]
			if output, err := exec.CommandContext(cleanupCtx, "docker", "network", "rm", name).CombinedOutput(); err != nil {
				t.Errorf("remove exact diagnostic network %s: %v %.256s", name, err, output)
			}
			if err := exec.CommandContext(cleanupCtx, "docker", "network", "inspect", name).Run(); err == nil {
				t.Errorf("diagnostic network %s remains", name)
			}
		}
		for i := len(volumeNames) - 1; i >= 0; i-- {
			name := volumeNames[i]
			if output, err := exec.CommandContext(cleanupCtx, "docker", "volume", "rm", name).CombinedOutput(); err != nil {
				t.Errorf("remove exact diagnostic volume %s: %v %.256s", name, err, output)
			}
			if err := exec.CommandContext(cleanupCtx, "docker", "volume", "inspect", name).Run(); err == nil {
				t.Errorf("diagnostic volume %s remains", name)
			}
		}
	})
	if _, err := exec.CommandContext(ctx, "docker", "image", "inspect", postgresClientHBAImage).Output(); err != nil {
		t.Fatalf("pinned PostgreSQL image unavailable: %v", err)
	}
	bridges := make(map[string]phase6security.Network)
	for _, bridge := range phase6security.Slice6DesiredFinalServiceBridges() {
		bridges[bridge.Name] = bridge
	}
	paths := phase6security.Slice6DesiredFinalExternalTransports()
	type endpoint struct {
		bridge, network, clientIP, serverIP, volume, container string
		phase6security.Slice6PostgresHBARule
	}
	endpoints := make([]endpoint, 0, len(rules))
	for index, rule := range rules {
		var path phase6security.Slice6ExternalTransportPath
		for _, candidate := range paths {
			if candidate.LogicalCaller == rule.Owner && candidate.Service == "postgres" {
				path = candidate
			}
		}
		bridge, ok := bridges[path.Network]
		clientIP, clientErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, rule.Dialer)
		serverIP, serverErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, "postgres")
		if !ok || clientErr != nil || serverErr != nil ||
			rule.SourceCIDR != clientIP+"/32" || bridge.GatewayModeIPv4 != "isolated" ||
			len(bridge.Principals) != 1 || bridge.Principals[0] != rule.Dialer {
			t.Fatalf("unreviewed shared PostgreSQL bridge for %s", rule.Owner)
		}
		name := fmt.Sprintf("%s-net-%d", stamp, index)
		runPostgresDocker(t, ctx, "network", "create", "--driver", "bridge", "--internal",
			"--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
			"--subnet", bridge.IPv4Subnet, name)
		networkNames = append(networkNames, name)
		endpoints = append(endpoints, endpoint{bridge: path.Network, network: name, clientIP: clientIP,
			serverIP: serverIP, Slice6PostgresHBARule: rule})
	}
	makeVolume := func(name string, files map[string][]byte) {
		directory := t.TempDir()
		for filename, document := range files {
			if err := os.WriteFile(filepath.Join(directory, filename), document, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		runPostgresDocker(t, ctx, "volume", "create", name)
		volumeNames = append(volumeNames, name)
		preparer := name + "-prepare"
		runPostgresDocker(t, ctx, "run", "-d", "--name", preparer, "-u", "0", "-v", name+":/pg",
			postgresClientHBAImage, "sh", "-c", "sleep 120")
		containerNames = append(containerNames, preparer)
		runPostgresDocker(t, ctx, "cp", directory+"/.", preparer+":/pg/")
		runPostgresDocker(t, ctx, "exec", "-u", "0", preparer, "sh", "-c",
			"chown -R postgres:postgres /pg && chmod 0600 /pg/*.key")
		runPostgresDocker(t, ctx, "rm", "-f", preparer)
	}
	now := time.Now().UTC().Truncate(time.Second)
	clientCA, clientKey, _ := integrationCA(t, now, "postgres-client-ca")
	serverCA, serverKey, _ := integrationCA(t, now, "postgres-server-ca")
	serverCert := integrationLeaf(t, now, serverCA, serverKey, "postgres.sandbox-runtime.test", "",
		"postgres.sandbox-runtime.test", x509.ExtKeyUsageServerAuth)
	clientCABundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw})
	serverCABundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw})
	serverVolume := stamp + "-server-volume"
	makeVolume(serverVolume, map[string][]byte{
		"pg_hba.conf": hba, "client-ca.crt": clientCABundle,
		"server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate.Certificate[0]}),
		"server.key": serverCert.PrivateKeyPEM,
	})
	runPostgresDocker(t, ctx, "run", "-d", "--name", serverName,
		"--network", endpoints[0].network, "--ip", endpoints[0].serverIP,
		"-v", serverVolume+":/pg:ro", "-e", "POSTGRES_PASSWORD=postgres-hba-admin",
		"-e", "POSTGRES_DB=product", postgresClientHBAImage,
		"postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/pg/server.crt",
		"-c", "ssl_key_file=/pg/server.key", "-c", "ssl_ca_file=/pg/client-ca.crt",
		"-c", "hba_file=/pg/pg_hba.conf")
	containerNames = append(containerNames, serverName)
	for _, item := range endpoints[1:] {
		runPostgresDocker(t, ctx, "network", "connect", "--ip", item.serverIP, item.network, serverName)
	}
	for attempt := 0; attempt < 80; attempt++ {
		logs := runPostgresDocker(t, ctx, "logs", serverName)
		if !strings.Contains(logs, "PostgreSQL init process complete; ready for start up.") ||
			strings.Count(logs, "database system is ready to accept connections") < 2 {
			if attempt == 79 {
				t.Fatalf("shared PostgreSQL did not complete final startup: %.1024s", logs)
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
		probe := exec.CommandContext(ctx, "docker", "exec", "-u", "postgres", serverName,
			"psql", "-At", "-d", "postgres", "-c", "SELECT 1")
		if output, err := probe.CombinedOutput(); err == nil && strings.TrimSpace(string(output)) == "1" {
			break
		} else if attempt == 79 {
			logs := runPostgresDocker(t, ctx, "logs", serverName)
			t.Fatalf("shared PostgreSQL did not start: %v %.512s; logs %.1024s", err, output, logs)
		}
		time.Sleep(250 * time.Millisecond)
	}
	for _, database := range []string{"provider", "provider_browser", "provider_desktop"} {
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
			"psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", "CREATE DATABASE "+database)
	}
	for _, database := range []string{"product", "provider", "provider_browser", "provider_desktop"} {
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
			"psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", "REVOKE CONNECT ON DATABASE "+database+" FROM PUBLIC")
	}
	for index := range endpoints {
		item := &endpoints[index]
		password := item.SQLRole + "-pw"
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
			"psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", item.SQLRole, password))
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
			"psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", item.Database, item.SQLRole))
		leaf := integrationLeaf(t, now, clientCA, clientKey, item.SQLRole,
			"spiffe://sandbox-runtime.test/"+item.Owner, "", x509.ExtKeyUsageClientAuth)
		item.volume = fmt.Sprintf("%s-client-volume-%d", stamp, index)
		files := map[string][]byte{
			"client.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate.Certificate[0]}),
			"client.key": leaf.PrivateKeyPEM, "server-ca.crt": serverCABundle,
		}
		if index == 0 {
			wrongCN := integrationLeaf(t, now, clientCA, clientKey, "other_role",
				"spiffe://sandbox-runtime.test/"+item.Owner, "", x509.ExtKeyUsageClientAuth)
			files["wrong-cn.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongCN.Certificate.Certificate[0]})
			files["wrong-cn.key"] = wrongCN.PrivateKeyPEM
		}
		makeVolume(item.volume, files)
		item.container = fmt.Sprintf("%s-client-%d", stamp, index)
		runPostgresDocker(t, ctx, "run", "-d", "--name", item.container, "--network", item.network,
			"--ip", item.clientIP, "--add-host", "postgres.sandbox-runtime.test:"+item.serverIP,
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
			"-u", "postgres", "-v", item.volume+":/pg:ro", postgresClientHBAImage, "sh", "-c", "sleep 120")
		containerNames = append(containerNames, item.container)
	}
	serverID := strings.TrimSpace(runPostgresDocker(t, ctx, "inspect", "-f", "{{.Id}}", serverName))
	for _, item := range endpoints {
		clientID := strings.TrimSpace(runPostgresDocker(t, ctx, "inspect", "-f", "{{.Id}}", item.container))
		bridge := bridges[item.bridge]
		bridge.Name = item.network
		observed, err := phase6security.ObserveDockerNetworkWithExternal(
			[]byte(runPostgresDocker(t, ctx, "network", "inspect", item.network)), bridge,
			map[string]string{item.Dialer: clientID}, map[string]string{"postgres": serverID})
		if err != nil || observed.HostGateway != "" || len(observed.Endpoints) != 2 {
			t.Fatalf("shared PostgreSQL bridge %s has unexpected raw topology: %v", item.bridge, err)
		}
	}
	if parsed := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
		"psql", "-At", "-d", "postgres", "-c", "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")); parsed != "0" {
		t.Fatalf("shared PostgreSQL rejected HBA: %s", parsed)
	}
	if parsed := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
		"psql", "-At", "-d", "postgres", "-c", "SELECT count(*) FROM pg_hba_file_rules")); parsed != "12" {
		t.Fatalf("shared PostgreSQL parsed %s HBA rules, not the exact twelve", parsed)
	}
	if mounted := strings.TrimSpace(runPostgresDocker(t, ctx, "inspect", "-f",
		"{{range .Mounts}}{{if eq .Destination \"/pg\"}}{{.Name}}|{{.RW}}{{end}}{{end}}", serverName)); mounted != serverVolume+"|false" {
		t.Fatalf("shared PostgreSQL HBA/CA mount is not the exact read-only volume: %q", mounted)
	}
	if actual := runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName, "cat", "/pg/pg_hba.conf"); actual != string(hba) {
		t.Fatal("shared PostgreSQL raw HBA bytes differ from final policy")
	}
	for setting, want := range map[string]string{"hba_file": "/pg/pg_hba.conf", "ssl_ca_file": "/pg/client-ca.crt"} {
		if actual := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
			"psql", "-At", "-d", "postgres", "-c", "SHOW "+setting)); actual != want {
			t.Fatalf("shared PostgreSQL %s = %q, want %q", setting, actual, want)
		}
	}
	connect := func(item endpoint, database, role, password, certificatePath string) (string, error) {
		connection := "host=postgres.sandbox-runtime.test port=5432 dbname=" + database + " user=" + role +
			" sslmode=verify-full sslrootcert=/pg/server-ca.crt"
		if certificatePath != "" {
			connection += " sslcert=" + certificatePath + " sslkey=" + strings.TrimSuffix(certificatePath, ".crt") + ".key"
		}
		args := []string{"exec", item.container, "env", "PGPASSWORD=" + password,
			"psql", connection,
			"-At", "-c", "SELECT current_database() || '|' || current_user || '|' || host(inet_client_addr())"}
		output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		return strings.TrimSpace(string(output)), err
	}
	for _, item := range endpoints {
		output, err := connect(item, item.Database, item.SQLRole, item.SQLRole+"-pw", "/pg/client.crt")
		want := item.Database + "|" + item.SQLRole + "|" + item.clientIP
		if err != nil || output != want {
			t.Fatalf("shared PostgreSQL %s source/login mismatch: %v %.512s, want %s", item.Owner, err, output, want)
		}
	}
	first := endpoints[0]
	for name, attempt := range map[string]struct{ database, role, password, certificate, rejection string }{
		"wrong SQL role":       {first.Database, endpoints[1].SQLRole, endpoints[1].SQLRole + "-pw", "/pg/client.crt", "pg_hba.conf rejects connection"},
		"wrong database":       {"provider_desktop", first.SQLRole, first.SQLRole + "-pw", "/pg/client.crt", "pg_hba.conf rejects connection"},
		"wrong SCRAM password": {first.Database, first.SQLRole, "wrong-password", "/pg/client.crt", "password authentication failed"},
		"missing certificate":  {first.Database, first.SQLRole, first.SQLRole + "-pw", "", "connection requires a valid client certificate"},
		"wrong CN":             {first.Database, first.SQLRole, first.SQLRole + "-pw", "/pg/wrong-cn.crt", "password authentication failed"},
	} {
		t.Run(name, func(t *testing.T) {
			if output, err := connect(first, attempt.database, attempt.role, attempt.password, attempt.certificate); err == nil {
				t.Fatalf("shared PostgreSQL admitted %s: %.512s", name, output)
			} else if !strings.Contains(output, attempt.rejection) {
				t.Fatalf("shared PostgreSQL %s failed for an unexpected reason: %.512s", name, output)
			}
		})
	}
	for _, item := range endpoints {
		prefix, err := netip.ParsePrefix(item.SourceCIDR)
		if err != nil || prefix.Bits() != 32 || prefix.Addr().String() != item.clientIP {
			t.Fatalf("wrong observed source rule for %s", item.Owner)
		}
	}
	runPostgresDocker(t, ctx, "restart", serverName)
	for attempt := 0; attempt < 60; attempt++ {
		output, err := connect(first, first.Database, first.SQLRole, first.SQLRole+"-pw", "/pg/client.crt")
		if err == nil && output == first.Database+"|"+first.SQLRole+"|"+first.clientIP {
			break
		}
		if attempt == 59 {
			t.Fatalf("restarted shared PostgreSQL lost exact source authority: %v %.512s", err, output)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if parsed := strings.TrimSpace(runPostgresDocker(t, ctx, "exec", "-u", "postgres", serverName,
		"psql", "-At", "-d", "postgres", "-c", "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")); parsed != "0" {
		t.Fatalf("restarted shared PostgreSQL HBA is invalid: %s", parsed)
	}
}
