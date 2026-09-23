//go:build integration

package phase6security

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This checkpoint starts the production authority executable, but the
// broker-side peer is still a protocol probe, not the production broker.
func TestDockerProductionPolicyAuthorityAndRevocationReceipt(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_AUTHORITY_PROCESS_DOCKER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_AUTHORITY_PROCESS_DOCKER=1")
	}
	const image = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
	const authorityUID, authorityGID, brokerUID, brokerGID = 59001, 59011, 59002, 59012
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	architecture, err := dockerTopology(ctx, "version", "--format", "{{.Server.Arch}}")
	architecture = strings.TrimSpace(architecture)
	if err != nil || (architecture != "arm64" && architecture != "amd64") {
		t.Fatalf("Docker architecture %q unavailable: %v", architecture, err)
	}
	if _, err := dockerTopology(ctx, "image", "inspect", image); err != nil {
		t.Fatalf("pinned fixture image unavailable: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := validProfile()
	for index := range profile.Principals {
		switch profile.Principals[index].Name {
		case "egress-policy-authority-product":
			profile.Principals[index].UID, profile.Principals[index].GID = authorityUID, authorityGID
		case "egress-broker-product":
			profile.Principals[index].UID, profile.Principals[index].GID = brokerUID, brokerGID
		}
	}
	for index := range profile.TLSAgentBindings {
		if profile.TLSAgentBindings[index].SubjectDeployment == "egress-broker-product" {
			profile.TLSAgentBindings[index].SubjectUID = brokerUID
			profile.TLSAgentBindings[index].SubjectGID = brokerGID
		}
	}
	profile.EgressPolicies[0].Authority.PublicKeyDigest = OperatorPublicKeyDigest(publicKey)
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("process profile invalid: %v", err)
	}
	profileDocument, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	clientDocument, err := json.Marshal(struct {
		Profile   json.RawMessage `json:"profile"`
		PublicKey []byte          `json:"public_key"`
	}{profileDocument, publicKey})
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	authorityBinary := filepath.Join(workspace, "authority")
	clientBinary := filepath.Join(workspace, "current-client")
	for _, item := range []struct{ source, target string }{
		{"./../../cmd/egress-policy-state-authority", authorityBinary},
		{"./testdata/currentclient", clientBinary},
	} {
		command := exec.CommandContext(ctx, "go", "build", "-o", item.target, item.source)
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+architecture, "CGO_ENABLED=0")
		if output, buildErr := command.CombinedOutput(); buildErr != nil {
			t.Fatalf("build authority fixture %s: %v: %.2048s", item.source, buildErr, output)
		}
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	ledgerVolume, socketVolume, container := "p6-real-authority-ledger-"+suffix,
		"p6-real-authority-socket-"+suffix, "p6-real-authority-"+suffix
	createdVolumes := []string{}
	containerCreated := false
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if containerCreated {
			_, _ = dockerTopology(cleanupContext, "rm", "-f", container)
			if _, err := dockerTopology(cleanupContext, "inspect", container); err == nil {
				t.Error("authority container remained after cleanup")
			}
		}
		for _, volume := range createdVolumes {
			if _, err := dockerTopology(cleanupContext, "volume", "rm", volume); err != nil {
				t.Errorf("remove exact volume %s: %v", volume, err)
			}
			if _, err := dockerTopology(cleanupContext, "volume", "inspect", volume); err == nil {
				t.Errorf("volume %s remained after cleanup", volume)
			}
		}
	})
	for _, volume := range []string{ledgerVolume, socketVolume} {
		if _, err := dockerTopology(ctx, "volume", "create", volume); err != nil {
			t.Fatal(err)
		}
		createdVolumes = append(createdVolumes, volume)
	}
	ledgerMount := "type=volume,src=" + ledgerVolume + ",dst=/var/lib/egress-authority"
	socketMount := "type=volume,src=" + socketVolume + ",dst=/run/egress-authority"
	setup := "chown 59001:59011 /ledger && chmod 0700 /ledger && chown 59001:59012 /socket && chmod 0710 /socket"
	if _, err := dockerTopology(ctx, "run", "--rm", "--network", "none", "-v", ledgerVolume+":/ledger",
		"-v", socketVolume+":/socket", image, "sh", "-c", setup); err != nil {
		t.Fatal(err)
	}
	copyLedger := func(name string, data []byte, mode string) {
		t.Helper()
		copyDockerPolicyFile(t, ctx, data, "-v", ledgerVolume+":/work", image,
			"cat > /work/"+name+" && chown 59001:59011 /work/"+name+" && chmod "+mode+" /work/"+name)
	}
	copySocket := func(name string, data []byte) {
		t.Helper()
		copyDockerPolicyFile(t, ctx, data, "-v", socketVolume+":/work", image,
			"cat > /work/"+name+" && chown 59001:59012 /work/"+name+" && chmod 0750 /work/"+name)
	}
	authorityBytes, err := os.ReadFile(authorityBinary)
	if err != nil {
		t.Fatal(err)
	}
	clientBytes, err := os.ReadFile(clientBinary)
	if err != nil {
		t.Fatal(err)
	}
	copyLedger("authority", authorityBytes, "0500")
	copyLedger("key.bin", privateKey, "0600")
	copyLedger("profile.json", profileDocument, "0600")
	copySocket("current-client", clientBytes)
	for _, mode := range []string{"initialize", "serve", "inspect"} {
		config := authorityProcessConfig{Protocol: "sandbox-runtime.egress-policy-state-authority-config.v1", Mode: mode,
			SecurityProfilePath: "/var/lib/egress-authority/profile.json", PolicyID: "product-egress",
			LedgerPath: "/var/lib/egress-authority/ledger.json", SocketPath: "/run/egress-authority/current.sock",
			OperatorKeyID: "operator-product-1", OperatorPublicKey: publicKey,
			ExpectedBrokerUID: brokerUID, ExpectedBrokerGID: brokerGID, MaxConnections: 4,
			StateRefreshMillis: 500, PolicyStateMaxAgeSeconds: 5}
		encoded, encodeErr := json.Marshal(config)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		copyLedger(mode+".json", encoded, "0600")
	}
	authorityInvocation := func(mode string, detached bool) (string, error) {
		arguments := []string{"run"}
		if detached {
			arguments = append(arguments, "-d", "--name", container)
		} else {
			arguments = append(arguments, "--rm")
		}
		arguments = append(arguments, "--network", "none", "--user", "59001:59011", "--read-only", "--cap-drop", "ALL",
			"--security-opt", "no-new-privileges", "--mount", ledgerMount, "--mount", socketMount, image, "sh", "-c",
			"exec 3</var/lib/egress-authority/key.bin; exec /var/lib/egress-authority/authority < /var/lib/egress-authority/"+mode+".json")
		return dockerTopology(ctx, arguments...)
	}
	if _, err := authorityInvocation("initialize", false); err != nil {
		t.Fatalf("explicit production initialization: %v", err)
	}
	if _, err := authorityInvocation("serve", true); err != nil {
		t.Fatalf("production authority process startup: %v", err)
	}
	containerCreated = true
	client := func() (string, error) {
		return dockerPolicyInput(ctx, clientDocument, "run", "--rm", "-i", "--network", "none", "--user", "59002:59012",
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", socketMount+",readonly",
			image, "/run/egress-authority/current-client")
	}
	awaitActive := func() {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			status, currentErr := client()
			if currentErr == nil && status == "active" {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		status, currentErr := client()
		t.Fatalf("production authority did not serve active Current: %q %v", status, currentErr)
	}
	inspect := func() (string, error) {
		return dockerTopology(ctx, "run", "--rm", "--network", "none", "--user", "59001:59011", "--read-only",
			"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", ledgerMount+",readonly",
			image, "sh", "-c", "exec /var/lib/egress-authority/authority < /var/lib/egress-authority/inspect.json")
	}
	awaitActive()
	if _, err := inspect(); err == nil {
		t.Fatal("active policy emitted permanent revocation receipt")
	}
	if _, err := dockerPolicyInput(ctx, clientDocument, "run", "--rm", "-i", "--network", "none", "--user", "59003:59012",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", socketMount+",readonly",
		image, "/run/egress-authority/current-client"); err == nil {
		t.Fatal("wrong-UID client obtained signed Current")
	}
	if _, err := dockerTopology(ctx, "run", "--rm", "--network", "none", "--user", "59002:59012", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", ledgerMount+",readonly",
		image, "cat", "/var/lib/egress-authority/ledger.json"); err == nil {
		t.Fatal("broker UID read authority-private ledger")
	}
	for _, signal := range []struct {
		name string
		exit string
	}{{"TERM", "0"}, {"KILL", "137"}} {
		if _, err := dockerTopology(ctx, "kill", "--signal="+signal.name, container); err != nil {
			t.Fatal(err)
		}
		exitCode, err := dockerTopology(ctx, "wait", container)
		if err != nil || strings.TrimSpace(exitCode) != signal.exit {
			t.Fatalf("SIG%s authority process exit = %q, %v", signal.name, exitCode, err)
		}
		if _, err := inspect(); err == nil {
			t.Fatalf("SIG%s emitted permanent revocation receipt", signal.name)
		}
		if _, err := client(); err == nil {
			t.Fatalf("SIG%s left an available Current authority", signal.name)
		}
		if _, err := dockerTopology(ctx, "rm", container); err != nil {
			t.Fatal(err)
		}
		containerCreated = false
		if _, err := authorityInvocation("serve", true); err != nil {
			t.Fatalf("restart after SIG%s: %v", signal.name, err)
		}
		containerCreated = true
		awaitActive()
	}
	if _, err := dockerTopology(ctx, "kill", "--signal=USR1", container); err != nil {
		t.Fatal(err)
	}
	exitCode, err := dockerTopology(ctx, "wait", container)
	if err != nil || strings.TrimSpace(exitCode) != "0" {
		t.Fatalf("SIGUSR1 authority process exit = %q, %v", exitCode, err)
	}
	receiptDocument, err := inspect()
	if err != nil {
		t.Fatalf("independent production inspect: %v", err)
	}
	var receipt struct {
		Protocol     string `json:"protocol"`
		PolicyID     string `json:"policy_id"`
		Generation   uint64 `json:"generation"`
		Status       string `json:"status"`
		LedgerDigest string `json:"ledger_digest"`
	}
	if err := json.Unmarshal([]byte(receiptDocument), &receipt); err != nil ||
		receipt.Protocol != "sandbox-runtime.egress-policy-revocation-receipt.v1" ||
		receipt.PolicyID != "product-egress" || receipt.Generation < 2 || receipt.Status != "revoked" || receipt.LedgerDigest == "" {
		t.Fatalf("invalid production receipt: %#v, %v", receipt, err)
	}
	if _, err := dockerTopology(ctx, "rm", container); err != nil {
		t.Fatal(err)
	}
	containerCreated = false
	if _, err := authorityInvocation("serve", false); err == nil {
		t.Fatal("revoked production authority restarted active")
	}
	t.Log("production authority command: explicit initialize, distinct-UID fresh Current, wrong UID/private-ledger denial, SIGTERM/SIGKILL recover without false revocation, SIGUSR1 successful exit, independent revoked receipt, revoked restart rejection, exact cleanup")
}

type authorityProcessConfig struct {
	Protocol                 string `json:"protocol"`
	Mode                     string `json:"mode"`
	SecurityProfilePath      string `json:"security_profile_path"`
	PolicyID                 string `json:"policy_id"`
	LedgerPath               string `json:"ledger_path"`
	SocketPath               string `json:"socket_path"`
	OperatorKeyID            string `json:"operator_key_id"`
	OperatorPublicKey        []byte `json:"operator_public_key"`
	ExpectedBrokerUID        uint32 `json:"expected_broker_uid"`
	ExpectedBrokerGID        uint32 `json:"expected_broker_gid"`
	MaxConnections           int    `json:"max_connections"`
	StateRefreshMillis       int    `json:"state_refresh_millis"`
	PolicyStateMaxAgeSeconds int    `json:"policy_state_max_age_seconds"`
}

func copyDockerPolicyFile(t *testing.T, ctx context.Context, document []byte, mountFlag, mount, image, command string) {
	t.Helper()
	output, err := dockerPolicyInput(ctx, document, "run", "--rm", "-i", "--network", "none", mountFlag, mount,
		image, "sh", "-c", command)
	if err != nil {
		t.Fatalf("copy exact Docker policy fixture: %v: %.2048s", err, output)
	}
}

func dockerPolicyInput(ctx context.Context, document []byte, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Stdin = bytes.NewReader(document)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker input fixture: %w: %.2048s", err, output)
	}
	return strings.TrimSpace(string(output)), nil
}
