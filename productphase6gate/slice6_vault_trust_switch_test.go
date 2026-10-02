//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6VaultTrustSwitchEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_VAULT_TRUST_SWITCH"

// This is real Docker component evidence for the operator bootstrap trust
// cutover. It is not the managed certificate-controller/agent path or a Slice 6
// release scenario.
func TestPhase6Slice6VaultPersistentTrustSwitch(t *testing.T) {
	if os.Getenv(slice6VaultTrustSwitchEnv) != "1" {
		t.Skip("set " + slice6VaultTrustSwitchEnv + "=1 for the real Vault trust switch")
	}
	if os.Getuid() == 0 {
		t.Fatal("Vault trust switch must not use a root host UID")
	}
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") == "1" {
		sourceRoot, err := filepath.EvalSymlinks(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT"))
		if err != nil {
			t.Fatal("source-bound Vault composition needs a readable clean source checkout")
		}
		currentPath, err := filepath.Abs("..")
		if err != nil {
			t.Fatal("Vault diagnostic checkout path is unavailable")
		}
		currentRoot, err := filepath.EvalSymlinks(currentPath)
		if err != nil || sourceRoot == currentRoot {
			t.Fatal("source-bound Vault composition needs an independent clean checkout: this test creates run-private files in its own package directory")
		}
	}
	budget := 5 * time.Minute
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") == "1" {
		budget = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	// Build the finite operator from its own clean source checkpoint before
	// this test creates any run-private files or short-lived Vault authority.
	var terminalBinaryPath, terminalBinaryDigest string
	if os.Getenv(slice6TerminalOperatorEnv) == "1" {
		operatorSource, sourceErr := filepath.EvalSymlinks(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_OPERATOR_SOURCE_ROOT"))
		if sourceErr != nil || !filepath.IsAbs(operatorSource) {
			t.Fatal("terminal operator source path unavailable")
		}
		// Docker Desktop shares the workspace host tree, not Go's system
		// test temp directory. This sibling is still outside the clean source.
		operatorDirectory, directoryErr := os.MkdirTemp(filepath.Dir(operatorSource), ".sr-p6-terminal-operator-")
		if directoryErr != nil {
			t.Fatal("create exact private operator build directory")
		}
		t.Cleanup(func() {
			if removeErr := os.RemoveAll(operatorDirectory); removeErr != nil {
				t.Errorf("remove exact private operator build directory: %v", removeErr)
			}
		})
		terminalBinaryPath, terminalBinaryDigest = slice6BuildTerminalOperator(t, ctx, operatorDirectory)
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact Vault trust-switch Docker cleanup: %v", err)
		}
	})
	var network phase6security.Network
	for _, candidate := range phase6security.Slice6DesiredFinalNetworks() {
		if candidate.Name == "network-certificate-controller" {
			network = candidate
		}
	}
	if network.Name == "" || !network.Internal || network.GatewayModeIPv4 != "isolated" ||
		len(network.Principals) != 1 || network.Principals[0] != "certificate-controller" ||
		len(network.ExternalServices) != 1 || network.ExternalServices[0] != "vault" {
		t.Fatal("reviewed Vault/controller isolated bridge changed")
	}
	var credentialNetwork phase6security.Network
	for _, candidate := range phase6security.Slice6DesiredFinalNetworks() {
		if candidate.Name == "service-workload-credential-controller-vault" {
			credentialNetwork = candidate
		}
	}
	if credentialNetwork.Name == "" || !credentialNetwork.Internal ||
		credentialNetwork.GatewayModeIPv4 != "isolated" ||
		len(credentialNetwork.Principals) != 1 || credentialNetwork.Principals[0] != "workload-credential-controller" ||
		len(credentialNetwork.ExternalServices) != 1 || credentialNetwork.ExternalServices[0] != "vault" {
		t.Fatal("reviewed credential-controller/Vault isolated bridge changed")
	}
	vaultIP, err := phase6security.Slice6DesiredServiceEndpointAddress(network.Name, "vault")
	if err != nil {
		t.Fatal(err)
	}
	controllerIP, err := phase6security.Slice6DesiredServiceEndpointAddress(network.Name, "certificate-controller")
	if err != nil {
		t.Fatal(err)
	}
	credentialVaultIP, err := phase6security.Slice6DesiredServiceEndpointAddress(credentialNetwork.Name, "vault")
	if err != nil {
		t.Fatal(err)
	}
	credentialControllerIP, err := phase6security.Slice6DesiredServiceEndpointAddress(credentialNetwork.Name, "workload-credential-controller")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(".", ".sr-vault-trust-switch-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove exact Vault trust-switch local files: %v", err)
		}
	})
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "data")
	for _, directory := range []string{root, configDir, dataDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeSlice6VaultBridgeTLS(t, configDir, vaultIP)
	writeSlice6VaultPrivateFile(t, configDir, "vault.hcl", slice6VaultFileConfig())
	observerPath := filepath.Join(root, "vault-issuer-observer")
	observerBuild := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", observerPath, "./internal/phase6vaultbootstrap/testdata/observer")
	observerBuild.Dir, err = filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	observerBuild.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	if _, err := observerBuild.CombinedOutput(); err != nil {
		t.Fatal("build fixed independent Vault issuer observer")
	}
	created, err := createSlice6ProfileNetwork(ctx, run, network)
	if err != nil {
		t.Fatal(err)
	}
	credentialCreated, err := createSlice6ProfileNetwork(ctx, run, credentialNetwork)
	if err != nil {
		t.Fatal(err)
	}
	user := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	server, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", "sr-p6-vault-switch-"+run.id,
		"--label", run.label(), "--network", created.NetworkID, "--ip", vaultIP,
		"--network-alias", "vault.sandbox-runtime.test", "--user", user,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=256m", "--cpus=1", "--pids-limit=64",
		"--mount", "type=bind,source="+configDir+",target=/vault/config,readonly",
		"--mount", "type=bind,source="+dataDir+",target=/vault/data",
		slice6VaultTestImage, "server")
	serverID := strings.TrimSpace(string(server))
	if err != nil || len(serverID) != 64 || !lowerHexSlice6(serverID) {
		t.Fatalf("non-dev persistent Vault start failed: %v", err)
	}
	implicitVaultVolumes, err := slice6VaultImplicitVolumes(ctx, run, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.docker(ctx, "network", "connect", "--ip", credentialVaultIP,
		"--alias", "vault.sandbox-runtime.test", credentialCreated.NetworkID, serverID); err != nil {
		t.Fatal("connect real Vault to exact credential-controller bridge")
	}
	credentialEmpty := credentialNetwork
	credentialEmpty.Principals = nil
	credentialObserved, err := observeSlice6ProfileNetworkWithExternal(ctx, run, credentialCreated.NetworkID,
		credentialEmpty, serverID)
	if err != nil || len(credentialObserved.Endpoints) != 1 ||
		credentialObserved.Endpoints[0].IPv4Address != credentialVaultIP {
		t.Fatal("real Vault credential-controller bridge membership drifted")
	}
	if err := waitSlice6VaultUninitialized(ctx, run, serverID); err != nil {
		t.Fatal(err)
	}
	firstStart := slice6VaultStartedAt(t, ctx, run, serverID)
	var initialized struct {
		UnsealKeysBase64 []string `json:"unseal_keys_b64"`
		RootToken        string   `json:"root_token"`
	}
	init, err := run.docker(ctx, slice6VaultExec(serverID, false, "operator", "init", "-format=json", "-key-shares=1", "-key-threshold=1")...)
	if err != nil || json.Unmarshal(init, &initialized) != nil || len(initialized.UnsealKeysBase64) != 1 || initialized.RootToken == "" {
		t.Fatal("persistent Vault initialization had an unknown outcome")
	}
	unsealKey := initialized.UnsealKeysBase64[0]
	writeSlice6VaultPrivateFile(t, configDir, "root-token", []byte(initialized.RootToken))
	clear(init)
	initialized.RootToken = ""
	initialized.UnsealKeysBase64 = nil
	if output, err := slice6VaultUnseal(ctx, serverID, unsealKey); err != nil || !bytesContainUnsealedVault(output) {
		t.Fatal("persistent Vault initial unseal failed")
	}
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "secrets", "enable", "-path=pki", "pki")...); err != nil {
		t.Fatal("persistent Vault PKI mount failed")
	}
	general := slice6VaultGenerateRoot(t, ctx, run, serverID, false)
	broker := slice6VaultGenerateRoot(t, ctx, run, serverID, true)
	if general.ID == broker.ID || !phase6security.ValidSlice6IssuerID(general.ID) || !phase6security.ValidSlice6IssuerID(broker.ID) ||
		bytes.Equal(general.Certificate.Raw, broker.Certificate.Raw) {
		t.Fatal("persistent Vault issuer identities are invalid or aliased")
	}
	serverCSR, serverKey := slice6VaultSwitchCSR(t, false)
	clientCSR, clientKey := slice6VaultSwitchCSR(t, true)
	writeSlice6VaultPrivateFile(t, configDir, "final-server.csr", serverCSR)
	writeSlice6VaultPrivateFile(t, configDir, "final-client.csr", clientCSR)
	writeSlice6VaultPrivateFile(t, configDir, "final-server-key.pem", serverKey)
	writeSlice6VaultPrivateFile(t, configDir, "final-client-key.pem", clientKey)
	serverLeaf := slice6VaultSignFinalLeaf(t, ctx, run, serverID, general, false)
	clientLeaf := slice6VaultSignFinalLeaf(t, ctx, run, serverID, general, true)
	slice6VaultAssertLeafKey(t, serverLeaf, serverKey)
	slice6VaultAssertLeafKey(t, clientLeaf, clientKey)
	slice6VaultAssertRoleIssuer(t, ctx, run, serverID, "final-vault-server", general.ID)
	slice6VaultAssertRoleIssuer(t, ctx, run, serverID, "final-controller-client", general.ID)
	beforeGeneralCRL := slice6VaultReadCRL(t, ctx, run, serverID, general)
	beforeBrokerCRL := slice6VaultReadCRL(t, ctx, run, serverID, broker)
	beforeNetwork := slice6VaultNetworkObserve(t, ctx, run, created.NetworkID, controllerIP, vaultIP, user,
		configDir, observerPath, "before", general, broker)
	for old, preserved := range map[string]string{
		"server-ca.pem":  "bootstrap-server-ca.pem",
		"client.pem":     "bootstrap-client.pem",
		"client-key.pem": "bootstrap-client-key.pem",
	} {
		contents, readErr := os.ReadFile(filepath.Join(configDir, old))
		if readErr != nil {
			t.Fatal(readErr)
		}
		writeSlice6VaultPrivateFile(t, configDir, preserved, contents)
		clear(contents)
	}
	if _, err := run.docker(ctx, "stop", "-t", "10", serverID); err != nil {
		t.Fatal("controlled Vault stop failed")
	}
	writeSlice6VaultPrivateFile(t, configDir, "server.pem", serverLeaf)
	writeSlice6VaultPrivateFile(t, configDir, "server-key.pem", serverKey)
	writeSlice6VaultPrivateFile(t, configDir, "server-ca.pem", general.PEM)
	writeSlice6VaultPrivateFile(t, configDir, "client-ca.pem", general.PEM)
	writeSlice6VaultPrivateFile(t, configDir, "client.pem", clientLeaf)
	writeSlice6VaultPrivateFile(t, configDir, "client-key.pem", clientKey)
	if _, err := run.docker(ctx, "start", serverID); err != nil {
		t.Fatal("controlled Vault restart failed")
	}
	if secondStart := slice6VaultStartedAt(t, ctx, run, serverID); firstStart == secondStart {
		t.Fatal("Vault process identity did not change at trust cutover")
	}
	if err := waitSlice6VaultInitializedSealed(ctx, run, serverID); err != nil {
		t.Fatal(err)
	}
	if output, err := slice6VaultUnseal(ctx, serverID, unsealKey); err != nil || !bytesContainUnsealedVault(output) {
		t.Fatal("persistent Vault final-trust unseal failed")
	}
	unsealKey = ""
	if observed := slice6VaultReadIssuer(t, ctx, run, serverID, general.ID); !bytes.Equal(observed.Raw, general.Certificate.Raw) {
		t.Fatal("general issuer changed across the controlled restart")
	}
	if observed := slice6VaultReadIssuer(t, ctx, run, serverID, broker.ID); !bytes.Equal(observed.Raw, broker.Certificate.Raw) {
		t.Fatal("broker issuer changed across the controlled restart")
	}
	slice6VaultAssertRoleIssuer(t, ctx, run, serverID, "final-vault-server", general.ID)
	slice6VaultAssertRoleIssuer(t, ctx, run, serverID, "final-controller-client", general.ID)
	afterGeneralCRL := slice6VaultReadCRL(t, ctx, run, serverID, general)
	afterBrokerCRL := slice6VaultReadCRL(t, ctx, run, serverID, broker)
	if afterGeneralCRL.Cmp(beforeGeneralCRL) < 0 || afterBrokerCRL.Cmp(beforeBrokerCRL) < 0 {
		t.Fatal("a complete issuer CRL number regressed across the trust restart")
	}
	afterNetwork := slice6VaultNetworkObserve(t, ctx, run, created.NetworkID, controllerIP, vaultIP, user,
		configDir, observerPath, "after", general, broker)
	for index := range beforeNetwork {
		beforeNumber, beforeOK := new(big.Int).SetString(beforeNetwork[index].CRLNumber, 10)
		afterNumber, afterOK := new(big.Int).SetString(afterNetwork[index].CRLNumber, 10)
		if !beforeOK || !afterOK || afterNumber.Cmp(beforeNumber) < 0 ||
			beforeNetwork[index].IssuerID != afterNetwork[index].IssuerID ||
			beforeNetwork[index].IssuerDigest != afterNetwork[index].IssuerDigest {
			t.Fatal("network-observed fixed issuer or complete CRL regressed at trust cutover")
		}
	}
	slice6VaultProbe(t, ctx, run, created.NetworkID, controllerIP, vaultIP, user, configDir,
		"final-positive", "server-ca.pem", "client.pem", "client-key.pem", true)
	slice6VaultProbe(t, ctx, run, created.NetworkID, controllerIP, vaultIP, user, configDir,
		"old-client-denied", "server-ca.pem", "bootstrap-client.pem", "bootstrap-client-key.pem", false)
	slice6VaultProbe(t, ctx, run, created.NetworkID, controllerIP, vaultIP, user, configDir,
		"old-server-denied", "bootstrap-server-ca.pem", "client.pem", "client-key.pem", false)
	slice6VaultProbe(t, ctx, run, created.NetworkID, controllerIP, vaultIP, user, configDir,
		"after-denials", "server-ca.pem", "client.pem", "client-key.pem", true)
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_VAULT_POLICY_PROBE") == "1" &&
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INSTALL_VAULT_ACCESS") != "1" {
		slice6VaultScopedPolicyCommandDiagnostic(t, ctx, run, serverID, configDir)
	}
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INSTALL_VAULT_ACCESS") == "1" &&
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") != "1" {
		t.Fatal("real Vault access installation requires same-run source-bound profile composition")
	}
	if os.Getenv(slice6ControllerPrivateConfigEnv) == "1" &&
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") != "1" {
		t.Fatal("real controller private-config preparation requires same-run source-bound profile composition")
	}
	if os.Getenv(slice6CredentialProcessEnv) == "1" &&
		(os.Getenv(slice6ControllerPrivateConfigEnv) != "1" ||
			os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INSTALL_VAULT_ACCESS") != "1") {
		t.Fatal("real credential controller process requires same-run private volumes and scoped Vault access")
	}
	if os.Getenv(slice6CertificateProcessEnv) == "1" && os.Getenv(slice6CredentialProcessEnv) != "1" {
		t.Fatal("real certificate controller process requires live credential controller")
	}
	if os.Getenv(slice6TerminalOperatorEnv) == "1" &&
		(os.Getenv(slice6CertificateProcessEnv) != "1" || os.Getenv(slice6QuiesceProcessEnv) != "1") {
		t.Fatal("terminal operator requires two real quiesced controller processes")
	}
	if os.Getenv(slice6BreakGlassProcessEnv) == "1" &&
		(os.Getenv(slice6ControllerPrivateConfigEnv) != "1" || os.Getenv(slice6CertificateProcessEnv) != "1") {
		t.Fatal("break-glass v2 process requires complete same-run controller socket and private-volume supply")
	}
	if os.Getenv(slice6GuestMaterialEnv) == "1" &&
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INSTALL_VAULT_ACCESS") != "1" {
		t.Fatal("real Guest material requires same-run scoped Vault access")
	}
	rootRevoked := false
	revokeBootstrapRoot := func() {
		t.Helper()
		if rootRevoked {
			return
		}
		if _, revokeErr := run.docker(ctx, slice6VaultExec(serverID, true, "token", "revoke", "-self")...); revokeErr != nil {
			t.Fatal("bootstrap Vault root token revocation failed")
		}
		for _, name := range []string{"root-token", "bootstrap-server-ca.pem", "bootstrap-client.pem", "bootstrap-client-key.pem"} {
			if removeErr := os.Remove(filepath.Join(configDir, name)); removeErr != nil {
				t.Fatal("remove exact bootstrap trust material")
			}
		}
		rootRevoked = true
	}
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") == "1" {
		composed := slice6VaultComposeCandidateProfile(t, ctx, root, run.id, general, broker)
		var socketVolumes map[string]string
		var certificateSocketVolumes map[string]string
		var breakGlassSocketVolumes map[string]string
		var guestSocketVolumes map[string]string
		var anchorFiles map[string]string
		if os.Getenv(slice6ControllerPrivateConfigEnv) == "1" {
			slice6PrepareControllerPrivateConfigs(t, ctx, run, composed)
			slice6PrepareControllerLedgerVolumes(t, ctx, run, composed.Profile)
			socketVolumes = slice6PrepareCredentialControllerSocketVolumes(t, ctx, run, composed.Profile)
			t.Logf("same-run credential controller socket allocations=%d; isolated client directories are empty and no listener is active", len(socketVolumes))
			if os.Getenv(slice6CertificateProcessEnv) == "1" {
				certificateSocketVolumes = slice6PrepareCertificateControllerSocketVolumes(t, ctx, run, composed.Profile, socketVolumes)
				t.Logf("same-run combined controller socket allocations=%d; no certificate listener is active", len(certificateSocketVolumes))
			}
			priorSockets := socketVolumes
			if len(certificateSocketVolumes) != 0 {
				priorSockets = certificateSocketVolumes
			}
			breakGlassSocketVolumes = slice6PrepareBreakGlassSocketVolumes(t, ctx, run, composed.Profile, priorSockets)
			t.Logf("same-run break-glass socket allocations=15 combined=%d; no break-glass listener is active", len(breakGlassSocketVolumes))
			if os.Getenv(slice6GuestMaterialEnv) == "1" {
				guestSocketVolumes = slice6PrepareGuestAgentInputs(t, ctx, run, composed, breakGlassSocketVolumes)
				t.Logf("same-run Guest signer/material socket allocations=2 combined=%d; exact private config readers prepared, no Guest agent launched", len(guestSocketVolumes))
			}
			anchorFiles = slice6PrepareTrustAnchorVolumes(t, ctx, run, composed)
			t.Logf("same-run trust-anchor allocations=%d; one root-owned read-only file per Profile storage ID, exact digests and non-root bind reads", len(anchorFiles))
		}
		if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INSTALL_VAULT_ACCESS") == "1" {
			management := slice6VaultInstallScopedAccess(t, ctx, run, serverID, configDir, composed.Profile, general, broker)
			defer clear(management.Token)
			if os.Getenv(slice6GuestMaterialEnv) == "1" {
				slice6VaultInstallGuestMaterial(t, ctx, run, serverID, configDir, composed.Profile)
				guestTLSConfig, configErr := slice6BuildGuestTLSAgentConfig(composed)
				if configErr != nil {
					t.Fatalf("same-run Guest TLS-agent startup input failed: %v", configErr)
				}
				t.Logf("same-run Guest TLS-agent canonical v3 config assembled: bytes=%d; signer process not yet launched", len(guestTLSConfig))
				clear(guestTLSConfig)
				guestMaterialConfig, materialConfigErr := slice6BuildGuestMaterialAgentConfig(composed)
				if materialConfigErr != nil {
					t.Fatalf("same-run Guest material-agent startup input failed: %v", materialConfigErr)
				}
				t.Logf("same-run Guest material-agent canonical v2 config assembled: bytes=%d; agent process not yet launched", len(guestMaterialConfig))
				clear(guestMaterialConfig)
			}
			if os.Getenv(slice6ControllerPrivateConfigEnv) == "1" {
				credentialLeaf, credentialKey := slice6VaultSignControllerBootstrap(t, ctx, run,
					serverID, configDir, composed.Profile, general,
					"workload-credential-controller",
					composed.Profile.CertificateController.CredentialController.VaultRole,
					composed.Profile.CertificateController.CredentialController.PolicyID,
					composed.CertificateKeys[composed.Profile.CertificateController.CredentialController.RequestKeyID])
				defer clear(credentialKey)
				controllerConfig, buildErr := slice6BuildCredentialControllerConfig(composed, credentialLeaf)
				if buildErr != nil {
					t.Fatalf("same-run credential controller config assembly failed: %v", buildErr)
				}
				defer clear(controllerConfig)
				t.Logf("same-run real-Vault credential controller startup inputs assembled: canonical_config_bytes=%d signing_clients=%d bootstrap_chain_bytes=%d",
					len(controllerConfig), len(composed.CredentialKeys), len(credentialLeaf))
				certificateLeaf, certificateKey := slice6VaultSignControllerBootstrap(t, ctx, run,
					serverID, configDir, composed.Profile, general,
					"certificate-controller", composed.Profile.CertificateController.ManagedVaultRole,
					composed.Profile.CertificateController.ManagedPolicyID,
					composed.CertificateKeys[composed.Profile.CertificateController.ManagedRequestKeyID])
				defer clear(certificateKey)
				certificateConfig, certificateErr := slice6BuildCertificateControllerConfig(composed, certificateLeaf)
				if certificateErr != nil {
					t.Fatalf("same-run certificate controller config assembly failed: %v", certificateErr)
				}
				defer clear(certificateConfig)
				t.Logf("same-run real-Vault certificate controller startup inputs assembled: canonical_config_bytes=%d signing_policies=%d bootstrap_chain_bytes=%d; no certificate process yet",
					len(certificateConfig), len(composed.CertificateKeys)-1, len(certificateLeaf))
				var terminalOperator *slice6TerminalOperatorCredential
				if os.Getenv(slice6TerminalOperatorEnv) == "1" {
					prepared := slice6VaultPrepareTerminalOperator(t, ctx, run, serverID, configDir, composed.Profile, general)
					terminalOperator = &prepared
					defer terminalOperator.clear()
				}
				if os.Getenv(slice6CredentialProcessEnv) == "1" {
					// All role/PKI material and bootstrap leaves are now fixed. The
					// controller chain must run with the orphan management token,
					// never with the bootstrap root authority still live.
					revokeBootstrapRoot()
					var onCredentialReady func(func())
					if os.Getenv(slice6CertificateProcessEnv) == "1" {
						onCredentialReady = func(stopCredential func()) {
							var onTerminated func()
							var onManagedReady func()
							if os.Getenv(slice6GuestMaterialEnv) == "1" {
								onManagedReady = func() {
									slice6RunGuestTLSAgentStartup(t, ctx, run, composed, guestSocketVolumes, anchorFiles, nil)
								}
							}
							if terminalOperator != nil {
								onTerminated = func() {
									slice6RunTerminalOperator(t, ctx, run, composed, serverID,
										terminalBinaryPath, terminalBinaryDigest,
										management.Accessor, general, terminalOperator)
								}
							}
							slice6RunCertificateControllerStartup(t, ctx, run, composed, created.NetworkID,
								controllerIP, certificateSocketVolumes, anchorFiles, certificateConfig, certificateKey,
								onManagedReady, stopCredential, onTerminated)
						}
					}
					slice6RunCredentialControllerBootstrap(t, ctx, run, composed, credentialCreated.NetworkID,
						credentialControllerIP, socketVolumes, anchorFiles, controllerConfig, management.Token,
						credentialKey, onCredentialReady)
				}
			}
		}
		if os.Getenv(slice6BreakGlassProcessEnv) == "1" {
			revokeBootstrapRoot()
			slice6RunBreakGlassControllerStartup(t, ctx, run, composed, breakGlassSocketVolumes)
		}
	}
	revokeBootstrapRoot()
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("exact persistent Vault Docker cleanup: %v", err)
	}
	if err := slice6CheckImplicitVolumesRemoved(ctx, run, implicitVaultVolumes); err != nil {
		t.Fatalf("exact persistent Vault anonymous-volume cleanup: %v", err)
	}
	if os.Getenv(slice6CertificateProcessEnv) == "1" {
		t.Log("real file-backed non-dev Vault and two controller PID1 processes reached managed issuance with exact Docker cleanup; final release scenarios remain unproved")
	} else if os.Getenv(slice6CredentialProcessEnv) == "1" {
		t.Log("real file-backed non-dev Vault, same-run credential controller bootstrap PID1, ledger and private socket passed with exact Docker cleanup; certificate controller, managed switch and full Slice 6 gate remain unproved")
	} else {
		t.Log("real file-backed non-dev Vault retained two fixed issuers and complete CRLs across final mTLS trust restart as independently observed at the controller address; both temporary trust directions were rejected and exact Docker cleanup passed; no managed controller process launched")
	}
}

func slice6VaultFileConfig() []byte {
	return []byte(`ui = false
disable_mlock = true
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/config/server.pem"
  tls_key_file = "/vault/config/server-key.pem"
  tls_client_ca_file = "/vault/config/client-ca.pem"
  tls_min_version = "tls13"
  tls_require_and_verify_client_cert = true
}
storage "file" { path = "/vault/data" }
`)
}

func writeSlice6VaultPrivateFile(t *testing.T, directory, name string, contents []byte) {
	t.Helper()
	if name == "" || filepath.Base(name) != name {
		t.Fatal("invalid private Vault file name")
	}
	if err := os.WriteFile(filepath.Join(directory, name), contents, 0o600); err != nil {
		t.Fatal("write private Vault bootstrap material")
	}
}

type slice6VaultRoot struct {
	ID          string
	PEM         []byte
	Certificate *x509.Certificate
}

func slice6VaultGenerateRoot(t *testing.T, ctx context.Context, run slice6DockerRun, serverID string, broker bool) slice6VaultRoot {
	t.Helper()
	path := "pki/root/generate/internal"
	name := "sandbox-runtime general"
	arguments := []string{"write", "-format=json", path, "common_name=" + name, "ttl=1h", "key_type=ec", "key_bits=256"}
	if broker {
		path = "pki/issuers/generate/root/internal"
		arguments = []string{"write", "-format=json", path, "common_name=sandbox-runtime broker only", "issuer_name=broker-only", "ttl=1h", "key_type=ec", "key_bits=256"}
	}
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, arguments...)...)
	var document struct {
		Data struct {
			IssuerID    string `json:"issuer_id"`
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &document) != nil {
		t.Fatal("persistent Vault root generation failed")
	}
	certificate := slice6VaultParsePEMCertificate(t, []byte(document.Data.Certificate))
	return slice6VaultRoot{ID: document.Data.IssuerID, PEM: []byte(document.Data.Certificate), Certificate: certificate}
}

func slice6VaultParsePEMCertificate(t *testing.T, document []byte) *x509.Certificate {
	t.Helper()
	block, remainder := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatal("Vault returned a non-canonical PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("Vault returned an invalid certificate")
	}
	return certificate
}

func slice6VaultSwitchCSR(t *testing.T, client bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("final Vault leaf key generation failed")
	}
	uri := "spiffe://sandbox-runtime.test/external/vault"
	if client {
		uri = "spiffe://sandbox-runtime.test/certificate-controller"
	}
	identity, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{URIs: []*url.URL{identity}}
	if !client {
		template.DNSNames = []string{"vault.sandbox-runtime.test"}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal("final Vault leaf CSR generation failed")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func slice6VaultSignFinalLeaf(t *testing.T, ctx context.Context, run slice6DockerRun, serverID string, root slice6VaultRoot, client bool) []byte {
	t.Helper()
	role := "final-vault-server"
	csr := "final-server.csr"
	uri := "spiffe://sandbox-runtime.test/external/vault"
	flags := []string{"client_flag=false", "server_flag=true", "ext_key_usage=ServerAuth", "allowed_domains=vault.sandbox-runtime.test", "allow_bare_domains=true"}
	if client {
		role = "final-controller-client"
		csr = "final-client.csr"
		uri = "spiffe://sandbox-runtime.test/certificate-controller"
		flags = []string{"client_flag=true", "server_flag=false", "ext_key_usage=ClientAuth"}
	}
	roleArguments := append([]string{"write", "pki/roles/" + role,
		"issuer_ref=" + root.ID, "allowed_uri_sans=" + uri, "require_cn=false",
		"use_csr_common_name=false", "use_csr_sans=true", "allow_subdomains=false", "allow_ip_sans=false",
		"enforce_hostnames=true", "max_ttl=20m", "key_type=ec", "key_bits=256",
		"key_usage=DigitalSignature", "code_signing_flag=false", "email_protection_flag=false"}, flags...)
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, roleArguments...)...); err != nil {
		t.Fatal("final Vault leaf signing role creation failed")
	}
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json", "pki/sign/"+role,
		"csr=@/vault/config/"+csr, "ttl=10m")...)
	var signed struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &signed) != nil {
		t.Fatal("final Vault leaf CSR signing failed")
	}
	leaf := slice6VaultParsePEMCertificate(t, []byte(signed.Data.Certificate))
	issuer := slice6VaultParsePEMCertificate(t, []byte(signed.Data.IssuingCA))
	if !bytes.Equal(issuer.Raw, root.Certificate.Raw) || leaf.CheckSignatureFrom(issuer) != nil {
		t.Fatal("final Vault leaf did not bind to the general issuer")
	}
	wantURI := "spiffe://sandbox-runtime.test/external/vault"
	wantEKU := x509.ExtKeyUsageServerAuth
	if client {
		wantURI = "spiffe://sandbox-runtime.test/certificate-controller"
		wantEKU = x509.ExtKeyUsageClientAuth
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantURI || !reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{wantEKU}) ||
		(client && len(leaf.DNSNames) != 0) || (!client && !reflect.DeepEqual(leaf.DNSNames, []string{"vault.sandbox-runtime.test"})) {
		t.Fatal("final Vault leaf identity/EKU does not match its exact role")
	}
	return []byte(signed.Data.Certificate)
}

func slice6VaultReadIssuer(t *testing.T, ctx context.Context, run slice6DockerRun, serverID, issuerID string) *x509.Certificate {
	t.Helper()
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "read", "-format=json", "pki/issuer/"+issuerID)...)
	var document struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &document) != nil {
		t.Fatal("persistent Vault issuer could not be re-read")
	}
	return slice6VaultParsePEMCertificate(t, []byte(document.Data.Certificate))
}

func slice6VaultAssertLeafKey(t *testing.T, leafPEM, keyPEM []byte) {
	t.Helper()
	leaf := slice6VaultParsePEMCertificate(t, leafPEM)
	block, remainder := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatal("final Vault leaf private key is not canonical PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || !private.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("final Vault leaf certificate does not match its private key")
	}
}

func slice6VaultAssertRoleIssuer(t *testing.T, ctx context.Context, run slice6DockerRun, serverID, role, issuerID string) {
	t.Helper()
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "read", "-format=json", "pki/roles/"+role)...)
	var document struct {
		Data struct {
			IssuerRef string `json:"issuer_ref"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &document) != nil || document.Data.IssuerRef != issuerID {
		t.Fatal("Vault role issuer_ref changed or is not the fixed general issuer")
	}
}

func slice6VaultReadCRL(t *testing.T, ctx context.Context, run slice6DockerRun, serverID string, root slice6VaultRoot) *big.Int {
	t.Helper()
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "read", "-format=json", "pki/issuer/"+root.ID+"/crl")...)
	var document struct {
		Data struct {
			CRL string `json:"crl"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &document) != nil {
		t.Fatal("complete Vault issuer CRL could not be read")
	}
	block, remainder := pem.Decode([]byte(document.Data.CRL))
	if block == nil || block.Type != "X509 CRL" || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatal("complete Vault issuer CRL is not canonical PEM")
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || list.Number == nil || list.CheckSignatureFrom(root.Certificate) != nil {
		t.Fatal("complete Vault issuer CRL signature or number is invalid")
	}
	now := time.Now()
	if list.ThisUpdate.After(now) || !list.NextUpdate.After(now) {
		t.Fatal("complete Vault issuer CRL validity does not cover the trust cutover")
	}
	return new(big.Int).Set(list.Number)
}

type slice6NetworkIssuerObservation struct {
	IssuerID      string `json:"issuer_id"`
	IssuerDigest  string `json:"issuer_digest"`
	CRLNumber     string `json:"crl_number"`
	CRLThisUpdate string `json:"crl_this_update"`
	CRLNextUpdate string `json:"crl_next_update"`
}

func slice6VaultNetworkObserve(t *testing.T, ctx context.Context, run slice6DockerRun, networkID, controllerIP, vaultIP,
	user, directory, observerPath, phase string, general, broker slice6VaultRoot) []slice6NetworkIssuerObservation {
	t.Helper()
	created, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-vault-issuer-"+phase+"-"+run.id,
		"--label", run.label(), "--network", networkID, "--ip", controllerIP, "--user", user,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=96m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=bind,source="+directory+",target=/probe,readonly",
		"--mount", "type=bind,source="+observerPath+",target=/issuer-observer,readonly",
		"--entrypoint", "/issuer-observer",
		"docker.io/library/alpine@sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c",
		"https://"+vaultIP+":8200", general.ID, broker.ID)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("independent fixed-issuer observer container was not created")
	}
	response, err := run.docker(ctx, "start", "-a", id)
	var observed []slice6NetworkIssuerObservation
	if err != nil || json.Unmarshal(response, &observed) != nil || len(observed) != 2 {
		t.Fatalf("independent fixed-issuer observer failed: %v: %.512s", err, response)
	}
	for index, root := range []slice6VaultRoot{general, broker} {
		digest := sha256.Sum256(root.Certificate.Raw)
		if observed[index].IssuerID != root.ID || observed[index].IssuerDigest != "sha256:"+hex.EncodeToString(digest[:]) ||
			observed[index].CRLNumber == "" {
			t.Fatal("independent issuer observation differs from Vault internal root material")
		}
		thisUpdate, thisErr := time.Parse(time.RFC3339Nano, observed[index].CRLThisUpdate)
		nextUpdate, nextErr := time.Parse(time.RFC3339Nano, observed[index].CRLNextUpdate)
		if thisErr != nil || nextErr != nil || thisUpdate.After(time.Now()) || !nextUpdate.After(time.Now()) {
			t.Fatal("independent complete CRL validity does not cover trust cutover")
		}
	}
	if _, err := run.docker(ctx, "rm", id); err != nil {
		t.Fatal("remove exact fixed-issuer observer container")
	}
	return observed
}

func slice6VaultStartedAt(t *testing.T, ctx context.Context, run slice6DockerRun, serverID string) string {
	t.Helper()
	output, err := run.docker(ctx, "inspect", "--format", "{{.State.StartedAt}}", serverID)
	if err != nil || len(bytes.TrimSpace(output)) < 20 {
		t.Fatal("Vault process start identity unavailable")
	}
	return strings.TrimSpace(string(output))
}

func waitSlice6VaultInitializedSealed(ctx context.Context, run slice6DockerRun, serverID string) error {
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && ctx.Err() == nil; {
		response, _ := run.docker(ctx, slice6VaultExec(serverID, false, "status", "-format=json")...)
		var status struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
		}
		if json.Unmarshal(response, &status) == nil && status.Initialized && status.Sealed {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("persistent Vault did not restart sealed and initialized under final trust")
}

func slice6VaultProbe(t *testing.T, ctx context.Context, run slice6DockerRun, networkID, controllerIP, vaultIP,
	user, directory, suffix, serverCA, clientCert, clientKey string, wantSuccess bool) {
	t.Helper()
	maxAttempts := 1
	if !wantSuccess {
		maxAttempts = 3 // A reset/broken pipe alone is ambiguous; require an explicit TLS error.
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		arguments := []string{"create", "--pull=never", "--name", fmt.Sprintf("sr-p6-vault-%s-%d-%s", suffix, attempt, run.id),
			"--label", run.label(), "--network", networkID, "--ip", controllerIP, "--user", user,
			"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
			"--memory=96m", "--cpus=0.5", "--pids-limit=16",
			"--mount", "type=bind,source=" + directory + ",target=/probe,readonly",
			slice6VaultTestImage, "status", "-address=https://" + vaultIP + ":8200",
			"-ca-cert=/probe/" + serverCA, "-client-cert=/probe/" + clientCert,
			"-client-key=/probe/" + clientKey, "-tls-server-name=vault.sandbox-runtime.test"}
		created, err := run.docker(ctx, arguments...)
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("final-trust controller-address probe creation failed")
		}
		response, probeErr := run.docker(ctx, "start", "-a", id)
		if _, removeErr := run.docker(ctx, "rm", id); removeErr != nil {
			t.Fatal(fmt.Errorf("remove exact Vault probe: %w", removeErr))
		}
		if wantSuccess {
			if probeErr != nil || !strings.Contains(string(response), "Sealed          false") {
				t.Fatalf("final-trust controller-address probe failed: %v: %.512s", probeErr, response)
			}
			return
		}
		if probeErr == nil || strings.Contains(string(response), "Sealed          false") {
			t.Fatalf("temporary-trust probe unexpectedly succeeded: %v: %.512s", probeErr, response)
		}
		if strings.Contains(string(response), "certificate required") ||
			strings.Contains(string(response), "unknown authority") ||
			strings.Contains(string(response), "unknown certificate authority") ||
			strings.Contains(string(response), "bad certificate") {
			return
		}
		if attempt+1 == maxAttempts {
			t.Fatalf("temporary-trust probe was not attributable to TLS rejection after %d attempts: %v: %.512s",
				maxAttempts, probeErr, response)
		}
	}
}
