//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6NonDevVaultBridgeEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_NONDEV_VAULT_BRIDGE"

// This joins the non-dev, two-issuer Vault component to the reviewed isolated
// controller bridge. Its temporary operator TLS keys and Vault-local bootstrap
// are not the managed certificate-controller/agent chain or Slice 6 evidence.
func TestPhase6Slice6NonDevVaultIsolatedBridge(t *testing.T) {
	if os.Getenv(slice6NonDevVaultBridgeEnv) != "1" {
		t.Skip("set " + slice6NonDevVaultBridgeEnv + "=1 for real non-dev Vault bridge")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	var network phase6security.Network
	for _, candidate := range phase6security.Slice6DesiredFinalNetworks() {
		if candidate.Name == "network-certificate-controller" {
			network = candidate
		}
	}
	if network.Name == "" || !network.Internal || network.GatewayModeIPv4 != "isolated" ||
		len(network.Principals) != 1 || network.Principals[0] != "certificate-controller" ||
		len(network.ExternalServices) != 1 || network.ExternalServices[0] != "vault" {
		t.Fatal("reviewed isolated certificate-controller/Vault bridge changed")
	}
	vaultAddress, err := phase6security.Slice6DesiredServiceEndpointAddress(network.Name, "vault")
	if err != nil {
		t.Fatal(err)
	}
	controllerAddress, err := phase6security.Slice6DesiredServiceEndpointAddress(network.Name, "certificate-controller")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(".", ".sr-vault-nondev-bridge-")
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	containerUser := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove exact temporary Vault bridge files: %v", err)
		}
	})
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact non-dev Vault bridge cleanup: %v", err)
		}
	})
	writeSlice6VaultBridgeTLS(t, directory, vaultAddress)
	created, err := createSlice6ProfileNetwork(ctx, run, network)
	if err != nil {
		t.Fatal(err)
	}
	serverName := "sr-p6-vault-nondev-" + run.id
	server, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", serverName,
		"--label", run.label(), "--network", created.NetworkID, "--ip", vaultAddress,
		"--user", containerUser,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=256m", "--cpus=1", "--pids-limit=64",
		"--mount", "type=bind,source="+directory+",target=/vault/config,readonly",
		slice6VaultTestImage, "server")
	serverID := strings.TrimSpace(string(server))
	if err != nil || len(serverID) != 64 || !lowerHexSlice6(serverID) {
		t.Fatalf("non-dev Vault could not start on isolated bridge: %v", err)
	}
	if err := waitSlice6VaultUninitialized(ctx, run, serverID); err != nil {
		state, stateErr := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}:{{.State.Error}}", serverID)
		logs, logsErr := run.docker(ctx, "logs", "--tail=30", serverID)
		t.Logf("Vault startup state=%q (%v), logs=%.2048q (%v)", strings.TrimSpace(string(state)), stateErr, logs, logsErr)
		t.Fatal(err)
	}
	var initialized struct {
		UnsealKeysBase64 []string `json:"unseal_keys_b64"`
		RootToken        string   `json:"root_token"`
	}
	init, err := run.docker(ctx, slice6VaultExec(serverID, false, "operator", "init", "-format=json", "-key-shares=1", "-key-threshold=1")...)
	if err != nil {
		t.Logf("Vault init command error=%v, response bytes=%d", err, len(init))
		t.Fatal("non-dev Vault initialization has an unknown outcome")
	}
	parseErr := json.Unmarshal(init, &initialized)
	if parseErr != nil || len(initialized.UnsealKeysBase64) != 1 || initialized.RootToken == "" {
		t.Logf("Vault init response parse=%v, key count=%d, token present=%v", parseErr, len(initialized.UnsealKeysBase64), initialized.RootToken != "")
		t.Fatal("non-dev Vault initialization has an unknown outcome")
	}
	if output, err := slice6VaultUnseal(ctx, serverID, initialized.UnsealKeysBase64[0]); err != nil || !bytesContainUnsealedVault(output) {
		t.Logf("Vault unseal error=%v, response bytes=%d", err, len(output))
		t.Fatal("non-dev Vault unseal did not complete")
	}
	initialized.UnsealKeysBase64 = nil
	rootTokenPath := filepath.Join(directory, "root-token")
	if err := os.WriteFile(rootTokenPath, []byte(initialized.RootToken), 0o600); err != nil {
		t.Fatal("private non-dev Vault root token material unavailable")
	}
	clear(init)
	initialized.RootToken = ""
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "secrets", "enable", "-path=pki", "pki")...); err != nil {
		t.Fatal("non-dev Vault PKI mount unavailable")
	}
	general, err := run.docker(ctx, slice6VaultExec(serverID, true,
		"write", "-format=json", "pki/root/generate/internal", "common_name=sandbox-runtime general", "ttl=1h", "key_type=ec", "key_bits=256")...)
	if err != nil {
		t.Fatal("non-dev Vault general issuer generation failed")
	}
	generalID := slice6VaultIssuerID(general)
	broker, err := run.docker(ctx, slice6VaultExec(serverID, true,
		"write", "-format=json", "pki/issuers/generate/root/internal", "common_name=sandbox-runtime broker only",
		"issuer_name=broker-only", "ttl=1h", "key_type=ec", "key_bits=256")...)
	if err != nil {
		t.Fatal("non-dev Vault broker issuer generation failed")
	}
	brokerID := slice6VaultIssuerID(broker)
	if !phase6security.ValidSlice6IssuerID(generalID) || !phase6security.ValidSlice6IssuerID(brokerID) || generalID == brokerID {
		t.Fatal("non-dev Vault issuer UUIDs are missing, equal or invalid")
	}
	probeName := "sr-p6-vault-controller-probe-" + run.id
	probe, err := run.docker(ctx, "create", "--pull=never", "--name", probeName,
		"--label", run.label(), "--network", created.NetworkID, "--ip", controllerAddress,
		"--user", containerUser,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=96m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=bind,source="+directory+",target=/probe,readonly",
		slice6VaultTestImage, "status", "-address=https://"+vaultAddress+":8200",
		"-ca-cert=/probe/server-ca.pem", "-client-cert=/probe/client.pem", "-client-key=/probe/client-key.pem",
		"-tls-server-name=vault.sandbox-runtime.test")
	probeID := strings.TrimSpace(string(probe))
	if err != nil || len(probeID) != 64 || !lowerHexSlice6(probeID) {
		t.Fatal("separate controller-address mTLS probe was not created")
	}
	status, err := run.docker(ctx, "start", "-a", probeID)
	if err != nil || !strings.Contains(string(status), "Sealed          false") {
		t.Fatalf("separate controller-address mTLS status failed: %v: %.256s", err, status)
	}
	if _, err := run.docker(ctx, "rm", probeID); err != nil {
		t.Fatal("remove exact controller-address probe")
	}
	unauthenticated, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-vault-no-client-"+run.id,
		"--label", run.label(), "--network", created.NetworkID, "--ip", controllerAddress,
		"--user", containerUser, "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=96m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=bind,source="+directory+",target=/probe,readonly",
		slice6VaultTestImage, "status", "-address=https://"+vaultAddress+":8200",
		"-ca-cert=/probe/server-ca.pem", "-tls-server-name=vault.sandbox-runtime.test")
	unauthenticatedID := strings.TrimSpace(string(unauthenticated))
	if err != nil || len(unauthenticatedID) != 64 || !lowerHexSlice6(unauthenticatedID) {
		t.Fatal("no-client-certificate Vault probe was not created")
	}
	denied, deniedErr := run.docker(ctx, "start", "-a", unauthenticatedID)
	denial := string(denied)
	if deniedErr == nil || strings.Contains(denial, "Sealed          false") ||
		!(strings.Contains(denial, "certificate required") || strings.Contains(denial, "connection reset by peer")) {
		t.Logf("no-client-certificate probe error=%v, response=%.1024q", deniedErr, denied)
		t.Fatal("no-client-certificate probe did not produce an attributable TLS denial")
	}
	if _, err := run.docker(ctx, "rm", unauthenticatedID); err != nil {
		t.Fatal("remove exact rejected no-client-certificate probe")
	}
	stillLive, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-vault-after-denial-"+run.id,
		"--label", run.label(), "--network", created.NetworkID, "--ip", controllerAddress,
		"--user", containerUser, "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=96m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=bind,source="+directory+",target=/probe,readonly",
		slice6VaultTestImage, "status", "-address=https://"+vaultAddress+":8200",
		"-ca-cert=/probe/server-ca.pem", "-client-cert=/probe/client.pem", "-client-key=/probe/client-key.pem",
		"-tls-server-name=vault.sandbox-runtime.test")
	stillLiveID := strings.TrimSpace(string(stillLive))
	if err != nil || len(stillLiveID) != 64 || !lowerHexSlice6(stillLiveID) {
		t.Fatal("post-denial authenticated Vault probe was not created")
	}
	postDenial, err := run.docker(ctx, "start", "-a", stillLiveID)
	if err != nil || !strings.Contains(string(postDenial), "Sealed          false") {
		t.Fatal("Vault listener was not reachable after rejecting a client certificate omission")
	}
	if _, err := run.docker(ctx, "rm", stillLiveID); err != nil {
		t.Fatal("remove exact post-denial authenticated Vault probe")
	}
	partial := network
	partial.Principals = nil
	observed, err := observeSlice6ProfileNetworkWithExternal(ctx, run, created.NetworkID, partial, serverID)
	if err != nil || len(observed.Endpoints) != 1 || observed.Endpoints[0].IPv4Address != vaultAddress {
		t.Fatal("non-dev Vault is not the sole remaining isolated bridge member")
	}
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "token", "revoke", "-self")...); err != nil {
		t.Fatal("initial non-dev Vault root token was not revoked")
	}
	if err := os.Remove(rootTokenPath); err != nil {
		t.Fatal("remove exact ephemeral Vault root token file")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("exact non-dev Vault bridge cleanup: %v", err)
	}
	t.Log("real non-dev Vault, two internal issuers, isolated controller-address mTLS and exact Docker cleanup passed; managed controller/agent chain remains absent")
}

func slice6VaultExec(containerID string, authenticated bool, arguments ...string) []string {
	result := []string{"exec", "-e", "VAULT_ADDR=https://127.0.0.1:8200",
		"-e", "VAULT_CACERT=/vault/config/server-ca.pem", "-e", "VAULT_CLIENT_CERT=/vault/config/client.pem",
		"-e", "VAULT_CLIENT_KEY=/vault/config/client-key.pem", "-e", "VAULT_TLS_SERVER_NAME=vault.sandbox-runtime.test"}
	if authenticated {
		return append(append(result, containerID, "sh", "-c", "VAULT_TOKEN=\"$(cat /vault/config/root-token)\" exec vault \"$@\"", "--"), arguments...)
	}
	return append(append(result, containerID, "vault"), arguments...)
}

func slice6VaultUnseal(ctx context.Context, containerID, key string) ([]byte, error) {
	arguments := slice6VaultExec(containerID, false, "operator", "unseal", "-format=json")
	arguments = append([]string{arguments[0], "-it"}, arguments[1:]...)
	command := exec.CommandContext(ctx, "docker", arguments...)
	terminal, err := pty.Start(command)
	if err != nil {
		return nil, err
	}
	defer terminal.Close()
	const prompt = "Unseal Key (will be hidden):"
	prefix := make([]byte, 0, 512)
	buffer := make([]byte, 1)
	for !bytes.Contains(prefix, []byte(prompt)) && len(prefix) < 64<<10 {
		count, readErr := terminal.Read(buffer)
		prefix = append(prefix, buffer[:count]...)
		if readErr != nil {
			_ = command.Wait()
			return nil, readErr
		}
	}
	if !bytes.Contains(prefix, []byte(prompt)) {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errors.New("Vault unseal prompt did not arrive")
	}
	if _, err := io.WriteString(terminal, key+"\n"); err != nil {
		_ = command.Wait()
		return nil, err
	}
	response, readErr := io.ReadAll(io.LimitReader(terminal, 64<<10))
	waitErr := command.Wait()
	if readErr != nil && !errors.Is(readErr, syscall.EIO) {
		return nil, readErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	start := bytes.IndexByte(response, '{')
	if start < 0 {
		return nil, errors.New("Vault unseal JSON response is absent")
	}
	var status json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(response[start:])).Decode(&status); err != nil {
		return nil, errors.New("Vault unseal JSON response is invalid")
	}
	return status, nil
}

func waitSlice6VaultUninitialized(ctx context.Context, run slice6DockerRun, containerID string) error {
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && ctx.Err() == nil; {
		output, _ := run.docker(ctx, slice6VaultExec(containerID, false, "status", "-format=json")...)
		var status struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
		}
		if json.Unmarshal(output, &status) == nil && !status.Initialized && status.Sealed {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("non-dev Vault did not reach the uninitialized TLS state")
}

func bytesContainUnsealedVault(document []byte) bool {
	var status struct {
		Sealed *bool `json:"sealed"`
	}
	return json.Unmarshal(document, &status) == nil && status.Sealed != nil && !*status.Sealed
}

func slice6VaultIssuerID(document []byte) string {
	var result struct {
		Data struct {
			IssuerID string `json:"issuer_id"`
		} `json:"data"`
	}
	if json.Unmarshal(document, &result) != nil {
		return ""
	}
	return result.Data.IssuerID
}

func observeSlice6ProfileNetworkWithExternal(ctx context.Context, run slice6DockerRun, networkID string,
	expected phase6security.Network, containerID string) (phase6security.NetworkObservation, error) {
	raw, err := run.docker(ctx, "network", "inspect", networkID)
	if err != nil {
		return phase6security.NetworkObservation{}, err
	}
	return phase6security.ObserveDockerNetworkWithExternal(raw, expected, nil, map[string]string{"vault": containerID})
}

func writeSlice6VaultBridgeTLS(t *testing.T, directory, vaultIP string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	serverCA, serverCAKey := slice6VaultBridgeCA(t, now, "temporary Vault server CA")
	clientCA, clientCAKey := slice6VaultBridgeCA(t, now, "temporary Vault client CA")
	serverCert, serverKey := slice6VaultBridgeLeaf(t, now, serverCA, serverCAKey, false, vaultIP)
	clientCert, clientKey := slice6VaultBridgeLeaf(t, now, clientCA, clientCAKey, true, vaultIP)
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	config := `ui = false
disable_mlock = true
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/config/server.pem"
  tls_key_file = "/vault/config/server-key.pem"
  tls_client_ca_file = "/vault/config/client-ca.pem"
  tls_min_version = "tls13"
  tls_require_and_verify_client_cert = true
}
storage "inmem" {}
`
	files := map[string][]byte{
		"vault.hcl":      []byte(config),
		"server.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}),
		"server-key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
		"server-ca.pem":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw}),
		"client.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw}),
		"client-key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}),
		"client-ca.pem":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw}),
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func slice6VaultBridgeCA(t *testing.T, now time.Time, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, serialErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serialErr != nil {
		t.Fatal("temporary Vault bridge CA generation failed")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func slice6VaultBridgeLeaf(t *testing.T, now time.Time, ca *x509.Certificate,
	caKey *ecdsa.PrivateKey, client bool, vaultIP string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, serialErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serialErr != nil {
		t.Fatal("temporary Vault bridge leaf generation failed")
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(30 * time.Minute), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		identity, _ := url.Parse("spiffe://sandbox-runtime.test/certificate-controller")
		template.URIs = []*url.URL{identity}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"vault.sandbox-runtime.test"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(vaultIP)}
		identity, _ := url.Parse("spiffe://sandbox-runtime.test/external/vault")
		template.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}
