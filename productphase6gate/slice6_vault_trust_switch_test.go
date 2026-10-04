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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const slice6VaultTrustSwitchEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_VAULT_TRUST_SWITCH"
const slice6ProductPostgresDSNEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_POSTGRES_DSN"
const slice6ProductObserverRevisionEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_OBSERVER_SOURCE_REVISION"
const slice6ProductObserverExpectedDigestEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_OBSERVER_EXPECTED_DIGEST"
const slice6GuestReceiptEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_RECEIPT"

// Nested callbacks may already have recorded the primary failure before an
// enclosing process returns its cleanup result. Never replace that failure
// with nil or duplicate it when the returned error already wraps it.
func slice6PreserveFirstFailure(first, next error) error {
	if first == nil {
		return next
	}
	if next == nil || errors.Is(first, next) {
		return first
	}
	if errors.Is(next, first) {
		return next
	}
	return errors.Join(first, next)
}

func TestSlice6PreserveFirstFailureAcrossNestedCallbacks(t *testing.T) {
	guest := errors.New("Guest cleanup-only failure")
	callback := errors.New("primary callback failure")
	cleanup := errors.New("material cleanup failure")
	if got := slice6PreserveFirstFailure(guest, nil); !errors.Is(got, guest) {
		t.Fatal("nil outer return erased Guest failure")
	}
	got := slice6PreserveFirstFailure(callback, errors.Join(callback, cleanup))
	if !errors.Is(got, callback) || !errors.Is(got, cleanup) {
		t.Fatal("outer material result erased callback or cleanup failure")
	}
	got = slice6PreserveFirstFailure(guest, cleanup)
	if !errors.Is(got, guest) || !errors.Is(got, cleanup) {
		t.Fatal("independent Guest and material failures were not combined")
	}
}

// This is real Docker component evidence for the operator bootstrap trust
// cutover. It is not the managed certificate-controller/agent path or a Slice 6
// release scenario.
func TestPhase6Slice6VaultPersistentTrustSwitch(t *testing.T) {
	if os.Getenv(slice6VaultTrustSwitchEnv) != "1" {
		t.Skip("set " + slice6VaultTrustSwitchEnv + "=1 for the real Vault trust switch")
	}
	if os.Getenv(slice6GuestMaterialEnv) == "1" && os.Getenv(slice6BreakGlassProcessEnv) != "1" {
		t.Fatal("live Guest material agent requires the same-run break-glass consume listener")
	}
	if os.Getenv(slice6ProductTLSSignerEnv) == "1" && os.Getenv(slice6GuestMaterialEnv) != "1" {
		t.Fatal("Product TLS signer component requires the same-run Guest/Vault controller chain")
	}
	if os.Getenv(slice6ProductMaterialInputsEnv) == "1" && os.Getenv(slice6ProductTLSSignerEnv) != "1" {
		t.Fatal("Product material-agent inputs require the same-run Product TLS signer")
	}
	if os.Getenv(slice6PostgresServerLeafEnv) == "1" &&
		(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INSTALL_VAULT_ACCESS") != "1" ||
			os.Getenv(slice6TerminalOperatorEnv) != "1" ||
			os.Getenv(slice6ProductMaterialInputsEnv) != "1" ||
			os.Getenv(slice6CertificateProcessEnv) != "1" ||
			os.Getenv(slice6QuiesceProcessEnv) != "1") {
		t.Fatal("external PostgreSQL server certificate requires complete same-run Product/controller chain and v2 terminal operator")
	}
	if os.Getenv(slice6ProductPostgresDSNEnv) == "1" && os.Getenv(slice6PostgresServerLeafEnv) != "1" {
		t.Fatal("Product PostgreSQL DSN bootstrap requires the same-run external PostgreSQL and terminal operator")
	}
	if os.Getenv(slice6ProductMigrationJobEnv) == "1" &&
		(os.Getenv(slice6ProductMigrationSignersEnv) != "1" ||
			os.Getenv(slice6ProductMigrationInputsEnv) != "1" ||
			os.Getenv(slice6ProductPostgresDSNEnv) != "1") {
		t.Fatal("Product migration PID1 requires same-run PostgreSQL, private inputs and both signers")
	}
	if os.Getenv(slice6ProductRuntimeInputsEnv) == "1" &&
		(os.Getenv(slice6ProductMigrationInputsEnv) != "1" ||
			os.Getenv(slice6ProductMaterialInputsEnv) != "1") {
		t.Fatal("Product runtime inputs require the complete migration and runtime material socket supply")
	}
	if os.Getenv(slice6ProductRuntimeProcessEnv) == "1" &&
		(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") != "1" ||
			os.Getenv(slice6ControllerPrivateConfigEnv) != "1" ||
			os.Getenv(slice6CredentialProcessEnv) != "1" ||
			os.Getenv(slice6CertificateProcessEnv) != "1" ||
			os.Getenv(slice6ProductRuntimeInputsEnv) != "1" ||
			os.Getenv(slice6ProductMigrationJobEnv) != "1" ||
			os.Getenv(slice6ProductPostgresDSNEnv) != "1") {
		t.Fatal("Product serve PID1 requires completed same-run migration, PostgreSQL and exact runtime inputs")
	}
	if os.Getenv(slice6GuestBindingFixtureEnv) == "1" &&
		(os.Getenv(slice6ProductRuntimeProcessEnv) != "1" ||
			os.Getenv(slice6GuestMaterialEnv) != "1") {
		t.Fatal("Guest binding fixture requires same-run Product runtime and real Vault Guest public key")
	}
	if os.Getenv(slice6GuestRuntimeProcessEnv) == "1" &&
		os.Getenv(slice6GuestBindingFixtureEnv) != "1" {
		t.Fatal("Guest PID1 requires a same-run durable Product binding fixture")
	}
	if os.Getenv(slice6GuestLiveRevokeEnv) == "1" &&
		os.Getenv(slice6GuestRuntimeProcessEnv) != "1" {
		t.Fatal("live Guest revoke requires connected Product and Guest PID1")
	}
	if os.Getenv(slice6GuestReceiptEnv) != "1" && os.Getenv(slice6GuestReceiptEvidenceRootEnv) != "" {
		t.Fatal("private Guest evidence root requires the complete receipt chain")
	}
	var receiptRoot *slice6ReceiptEvidenceRoot
	if os.Getenv(slice6GuestReceiptEnv) == "1" {
		var rootErr error
		receiptRoot, rootErr = slice6OpenReceiptEvidenceRoot(os.Getenv(slice6GuestReceiptEvidenceRootEnv))
		if rootErr != nil {
			t.Fatal("pre-issuer private Guest evidence root unavailable")
		}
		t.Cleanup(func() {
			if err := receiptRoot.close(); err != nil {
				t.Error("private Guest evidence root close unconfirmed")
			}
		})
	}
	if os.Getenv(slice6ProductMigrationPreDDLFailureEnv) == "1" && os.Getenv(slice6ProductMigrationJobEnv) != "1" {
		t.Fatal("controlled pre-DDL failure requires the real Product migration chain")
	}
	if os.Getuid() == 0 {
		t.Fatal("Vault trust switch must not use a root host UID")
	}
	var migrationFailure error
	var runtimeFailure error
	var terminalFailure error
	var capacityFailure error
	var capacityStopFailure error
	var closeCapacityMonitor func()
	static := slice6VaultStaticInputsFromEnvironment()
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") == "1" {
		sourceRoot, err := filepath.EvalSymlinks(static.sourceRoot)
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
	var guestCandidateImage string
	var verifiedImages phase6profilebuilder.ImageSupply
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_COMPOSE_PROFILE") == "1" {
		external, images, err := slice6VaultLoadStaticInputs(ctx, static)
		if err != nil {
			t.Fatalf("pre-issuer static source and complete archive preflight: %v", err)
		}
		if err := slice6VaultPreflightAllStoredImages(ctx, external, images); err != nil {
			t.Fatalf("pre-issuer fixed Docker image inventory: %v", err)
		}
		verifiedImages = images
		if os.Getenv(slice6GuestRuntimeProcessEnv) == "1" {
			binding, ok := images.LocalRoleTargets["core"]
			if !ok || binding.Reference != binding.Digest {
				t.Fatal("pre-issuer selected Guest core image identity unavailable")
			}
			guestCandidateImage = binding.Reference
		}
		t.Log("pre-issuer source, role/Desktop/Browser candidates, four complete external OCI archives and all fixed Docker launch references verified")
	}
	var productRuntimeObserver slice6ProductRuntimeObserver
	if os.Getenv(slice6ProductRuntimeProcessEnv) == "1" {
		observerRoot, err := filepath.Abs("..")
		observerRevision := os.Getenv(slice6ProductObserverRevisionEnv)
		if err != nil || runtime.Version() != "go1.26.8" ||
			len(observerRevision) != 40 || !lowerHexSlice6(observerRevision) ||
			verifyCleanSlice6Source(ctx, observerRoot, observerRevision) != nil {
			t.Fatal("Product runtime observer requires clean E source and locked Go 1.26.8 before issuer allocation")
		}
		productRuntimeObserver, err = slice6BuildProductRuntimeObserver(t, ctx, observerRoot)
		if err != nil || slice6ApproveProductRuntimeObserver(
			os.Getenv(slice6ProductObserverExpectedDigestEnv), &productRuntimeObserver) != nil {
			t.Fatal("Product runtime observer binary differs from externally approved digest before issuer allocation")
		}
		if err := slice6ProbeProductRuntimeObserverMount(ctx, productRuntimeObserver); err != nil {
			t.Fatal("Product runtime observer non-root mount preflight failed before issuer allocation")
		}
		t.Logf("pre-issuer Product runtime observer source=%s binary=sha256:%x go=%s",
			observerRevision, productRuntimeObserver.Digest, runtime.Version())
	}
	var guestBindingFixture slice6GuestBindingFixtureArtifact
	if os.Getenv(slice6GuestBindingFixtureEnv) == "1" {
		fixtureRoot := os.Getenv(slice6GuestFixtureSourceRootEnv)
		fixtureRevision := os.Getenv(slice6GuestFixtureSourceRevisionEnv)
		if slice6VerifyGuestFixtureSourcePair(ctx, static.sourceRoot, static.sourceRevision,
			fixtureRoot, fixtureRevision) != nil {
			t.Fatal("pre-issuer runtime to fixture source pair rejected")
		}
		fixture, fixtureErr := slice6BuildGuestBindingFixture(t, ctx,
			fixtureRoot, fixtureRevision)
		guestBindingFixture = fixture
		if fixtureErr != nil || slice6ApproveGuestBindingFixture(&guestBindingFixture,
			os.Getenv(slice6GuestBindingFixtureExpectedDigestEnv)) != nil {
			t.Fatal("Guest binding fixture source or externally approved binary unavailable before issuer allocation")
		}
		identity := phase6security.Slice6DesiredUIDGID()["product-runtime"]
		if err := slice6ProbeGuestBindingFixtureMount(ctx, guestBindingFixture,
			identity[0], identity[1]); err != nil {
			t.Fatal("Guest binding fixture non-root executable probe failed before issuer allocation")
		}
		t.Logf("pre-issuer Guest binding fixture source=%s binary=%s go=%s",
			guestBindingFixture.SourceRevision, guestBindingFixture.Digest, runtime.Version())
	}
	// Build the finite operator from its own clean source checkpoint before
	// this test creates any run-private files or short-lived Vault authority.
	var terminalBinaryPath, terminalBinaryDigest string
	if os.Getenv(slice6TerminalOperatorEnv) == "1" {
		operatorSource, sourceErr := filepath.EvalSymlinks(static.terminalSourceRoot)
		if sourceErr != nil || !filepath.IsAbs(operatorSource) {
			t.Fatal("terminal operator source path unavailable")
		}
		// Docker Desktop shares the workspace host tree, not Go's system
		// test temp directory. This sibling is still outside the clean source.
		operatorDirectory := slice6PrivateSourceSibling(t, operatorSource, ".sr-p6-terminal-operator-")
		terminalBinaryPath, terminalBinaryDigest = slice6BuildTerminalOperator(t, ctx, operatorDirectory,
			static.terminalSourceRoot, static.sourceRevision)
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	var receiptEvidence *slice6ReceiptEvidenceRun
	if receiptRoot != nil {
		receiptEvidence, err = receiptRoot.newRun(run.id)
		if err != nil {
			t.Fatal("pre-issuer exclusive private Guest evidence run unavailable")
		}
		t.Cleanup(func() {
			if err := receiptEvidence.close(); err != nil {
				t.Error("private Guest evidence run durability or incomplete marker unconfirmed")
			}
		})
	}
	t.Logf("exact Vault trust-switch Docker run label=%s", run.label())
	cleanupGuard := &slice6BoundedRunCleanup{budget: 45 * time.Second}
	var serverID string
	var vaultCreateAttempted bool
	var implicitVaultVolumes []string
	t.Cleanup(func() {
		cleanup := cleanupGuard.Context()
		defer cleanupGuard.Close()
		if vaultCreateAttempted && serverID == "" {
			recovered, err := slice6RecoverVaultContainer(cleanup, run, "sr-p6-vault-switch-"+run.id)
			if err != nil || recovered == "" {
				t.Errorf("exact Vault create outcome and anonymous-volume ownership remain unknown: %v", err)
			} else {
				serverID = recovered
			}
		}
		if serverID != "" && len(implicitVaultVolumes) != 2 {
			volumes, err := slice6VaultImplicitVolumes(cleanup, run, serverID)
			if err != nil {
				t.Errorf("exact Vault anonymous-volume IDs unconfirmed before cleanup: %v", err)
			} else {
				implicitVaultVolumes = volumes
			}
		}
		if err := cleanupGuard.Finish(run.cleanup); err != nil {
			t.Errorf("exact Vault trust-switch Docker cleanup: %v", err)
		}
		if serverID != "" {
			if err := slice6CheckImplicitVolumesRemoved(cleanup, run, implicitVaultVolumes); err != nil {
				t.Errorf("exact Vault anonymous-volume cleanup unconfirmed: %v", err)
			} else {
				t.Logf("exact Vault anonymous-volume IDs absent after cleanup: %v", implicitVaultVolumes)
			}
		}
		if migrationFailure != nil {
			t.Errorf("Product migration attempt failed after strict terminal and exact Docker cleanup: %v", migrationFailure)
		}
		if runtimeFailure != nil {
			t.Errorf("Product runtime component failed after strict terminal and exact Docker cleanup: %v", runtimeFailure)
		}
		if terminalFailure != nil {
			t.Errorf("strict terminal cleanup remained unconfirmed after exact Docker cleanup: %v", terminalFailure)
		}
		if capacityFailure != nil || capacityStopFailure != nil {
			t.Errorf("continuous capacity interlock failed: reason=%v stop=%v", capacityFailure, capacityStopFailure)
		}
	})
	var preIssuerGuestShellDigest string
	if os.Getenv(slice6GuestRuntimeProcessEnv) == "1" {
		identity := phase6security.Slice6DesiredUIDGID()["guest-runtime"]
		selected := phase6security.Principal{Name: "guest-runtime", ImageReference: guestCandidateImage,
			ImageDigest: guestCandidateImage, UID: identity[0], GID: identity[1]}
		preIssuerGuestShellDigest, err = slice6MeasureGuestShell(ctx, run, selected)
		if err != nil || preIssuerGuestShellDigest == "" || slice6ProbeGuestUtilities(ctx, run, selected) != nil {
			t.Fatal("selected Guest shell or bounded HTTP/df utilities unavailable before issuer allocation")
		}
		monitorID, monitorErr := slice6StartCapacityObserver(ctx, run)
		if monitorErr != nil {
			t.Fatal("pre-issuer capacity observer unavailable")
		}
		rootPath, pathErr := filepath.Abs("..")
		if pathErr != nil {
			t.Fatal("capacity monitor host source unavailable")
		}
		var stopMu sync.Mutex
		var stopErr error
		var stopContext context.Context
		var stopCancel context.CancelFunc
		monitor, monitorErr := startSlice6CapacityMonitor(ctx, slice6GuestStorageCapacityBudget(0),
			time.Second, 2*time.Second,
			func(sampleContext context.Context) (slice6CapacityObservation, error) {
				return sampleSlice6RunningCapacity(sampleContext, run, rootPath, monitorID)
			}, func(reason error) {
				cancel()
				bounded, release := context.WithTimeout(context.Background(), 90*time.Second)
				stopMu.Lock()
				stopContext, stopCancel = bounded, release
				stopMu.Unlock()
				stopped := slice6StopRunOwnedWritersContext(bounded, run, monitorID)
				stopMu.Lock()
				stopErr = stopped
				stopMu.Unlock()
			})
		if monitorErr != nil {
			t.Fatalf("pre-issuer continuous capacity admission unavailable: %v", monitorErr)
		}
		closeCapacityMonitor = monitor.Close
		defer monitor.Close()
		t.Cleanup(func() {
			// All nested process runners have returned and their deferred Docker
			// creates/starts are over by this point. This bounded second sweep is
			// the lifecycle barrier after the asynchronous emergency stop and
			// before the earlier-registered exact run cleanup.
			var finalStopErr error
			if monitor.Reason() != nil {
				stopMu.Lock()
				bounded := stopContext
				release := stopCancel
				stopMu.Unlock()
				if bounded == nil || release == nil {
					finalStopErr = errors.New("capacity stop budget unavailable")
				} else {
					finalStopErr = slice6StopRunOwnedWritersContext(bounded, run, monitorID)
					release()
				}
			}
			stopMu.Lock()
			capacityStopFailure = errors.Join(stopErr, finalStopErr)
			stopMu.Unlock()
			capacityFailure = monitor.Reason()
		})
		t.Log("pre-issuer selected Guest shell/utilities and continuous host/Docker capacity interlock admitted")
	}
	if os.Getenv(slice6PostgresServerLeafEnv) == "1" {
		slice6RequireTerminalOperatorV2Capability(t, ctx, run, terminalBinaryPath, terminalBinaryDigest)
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
	root := slice6PrivateSourceSibling(t, static.sourceRoot, ".sr-vault-trust-switch-")
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
	vaultName := "sr-p6-vault-switch-" + run.id
	vaultCreateAttempted = true
	server, createErr := run.docker(ctx, "create", "--pull=never", "--name", vaultName,
		"--label", run.label(), "--network", created.NetworkID, "--ip", vaultIP,
		"--network-alias", "vault.sandbox-runtime.test", "--user", user,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=256m", "--cpus=1", "--pids-limit=64",
		"--mount", "type=bind,source="+configDir+",target=/vault/config,readonly",
		"--mount", "type=bind,source="+dataDir+",target=/vault/data",
		slice6VaultTestImage, "server")
	recovered, recoverErr := slice6RecoverVaultContainer(ctx, run, vaultName)
	if recoverErr != nil || recovered == "" {
		t.Fatalf("non-dev persistent Vault create outcome unresolved: create=%v recovery=%v", createErr, recoverErr)
	}
	serverID = recovered
	implicitVaultVolumes, err = slice6VaultImplicitVolumes(ctx, run, serverID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("exact Vault container=%s anonymous-volume IDs=%v", serverID, implicitVaultVolumes)
	if err := slice6StartVaultFromCreateReceipt(ctx, server, createErr, serverID,
		implicitVaultVolumes, run.docker); err != nil {
		t.Fatalf("non-dev persistent Vault create/start failed; exact container retained for cleanup: %v", err)
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
	if os.Getenv(slice6GuestReceiptEnv) == "1" &&
		(os.Getenv(slice6GuestLiveRevokeEnv) != "1" ||
			os.Getenv(slice6GuestRuntimeProcessEnv) != "1" ||
			os.Getenv(slice6ProductRuntimeProcessEnv) != "1") {
		t.Fatal("private Guest receipt requires the same-run Product, Guest and live revoke chain")
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
		composed := slice6VaultComposeCandidateProfile(t, ctx, root, run.id, general, broker, static)
		composed.PrivateGuestReceipt = os.Getenv(slice6GuestReceiptEnv) == "1"
		composed.GuestReceiptEvidence = receiptEvidence
		if err := slice6VerifyComposedTaskCarrier(composed.Profile); err != nil {
			t.Fatal(err)
		}
		var socketVolumes map[string]string
		var certificateSocketVolumes map[string]string
		var breakGlassSocketVolumes map[string]string
		var guestSocketVolumes map[string]string
		var guestRuntimeSocketVolumes map[string]string
		var productSocketVolumes map[string]string
		var productMaterialSocketVolumes map[string]string
		var productMigrationSocketVolumes map[string]string
		var productRuntimeSocketVolumes map[string]string
		var guestPublicMaterial slice6GuestPublicMaterial
		var productIdentityDigest string
		var productRuntimeDSNDigest string
		var postgresLeaf slice6PostgresServerLeaf
		var postgresClientCRL []byte
		var postgresRecord *phase6terminalcleanup.ExternalPostgresRecord
		var postgresServerID string
		var postgresStop func() error
		postgresTerminalConfirmed := false
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
				if os.Getenv(slice6GuestRuntimeProcessEnv) == "1" {
					guestRuntimeSocketVolumes = slice6PrepareGuestRuntimeTLSAgentInputs(t, ctx, run, composed, guestSocketVolumes)
					t.Logf("same-run Guest runtime dedicated TLS signer socket allocation=1 combined=%d; direct signer not yet launched", len(guestRuntimeSocketVolumes))
				}
				if os.Getenv(slice6ProductTLSSignerEnv) == "1" {
					productSocketVolumes = slice6PrepareProductTLSAgentInputs(t, ctx, run, composed, guestSocketVolumes)
					productTLSConfig, configErr := slice6BuildOrdinaryTLSAgentConfig(composed,
						"product-runtime", "product-tls-agent")
					if configErr != nil {
						t.Fatal("Product TLS signer source-bound startup input unavailable")
					}
					clear(productTLSConfig)
					t.Logf("same-run Product signer socket allocation=1 combined=%d; Product runtime process not launched", len(productSocketVolumes))
					if os.Getenv(slice6ProductMaterialInputsEnv) == "1" {
						productMaterialSocketVolumes = slice6PrepareProductMaterialAgentInputs(t, ctx, run, composed, productSocketVolumes)
						materialTLSConfig, tlsErr := slice6BuildOrdinaryTLSAgentConfig(composed,
							"product-runtime-agent", "product-runtime-agent-tls-agent")
						if tlsErr != nil {
							t.Fatal("Product material signer source-bound config unavailable")
						}
						clear(materialTLSConfig)
						materialConfig, materialErr := slice6BuildRuntimeMaterialAgentConfig(composed,
							"product-runtime-agent", "product-runtime", secretref.RoleProduct,
							[]secretref.Purpose{secretref.PurposeIdentityKeyRing, secretref.PurposePostgresRuntimeDSN})
						if materialErr != nil {
							t.Fatal("Product material-agent source-bound config unavailable")
						}
						clear(materialConfig)
						t.Logf("same-run Product material signer/material socket allocations=2 combined=%d; material agent not launched", len(productMaterialSocketVolumes))
						if os.Getenv(slice6ProductMigrationInputsEnv) == "1" {
							productMigrationSocketVolumes = slice6PrepareProductMigrationInputs(t, ctx, run, composed, productMaterialSocketVolumes)
							migrationTLSConfig, tlsErr := slice6BuildOrdinaryTLSAgentConfig(composed,
								"product-migration-agent", "product-migration-agent-tls-agent")
							if tlsErr != nil {
								t.Fatal("Product migration material signer source-bound config unavailable")
							}
							clear(migrationTLSConfig)
							migrationMaterialConfig, materialErr := slice6BuildProductMigrationMaterialAgentConfig(composed)
							if materialErr != nil {
								t.Fatal("Product migration material-agent source-bound config unavailable")
							}
							clear(migrationMaterialConfig)
							migrationPostgresConfig, postgresErr := slice6BuildProductMigrationPostgresSignerConfig(composed)
							if postgresErr != nil {
								t.Fatal("Product migration PostgreSQL signer source-bound config unavailable")
							}
							clear(migrationPostgresConfig)
							t.Logf("same-run Product migration signer/material/PostgreSQL socket allocations=3 combined=%d; migration job not launched", len(productMigrationSocketVolumes))
							if os.Getenv(slice6ProductRuntimeInputsEnv) == "1" {
								productRuntimeSocketVolumes = slice6PrepareProductRuntimeInputs(t, ctx, run, composed, productMigrationSocketVolumes)
								runtimePostgresConfig, runtimePostgresErr := slice6BuildProductPostgresSignerConfig(composed, "product-runtime")
								if runtimePostgresErr != nil {
									t.Fatal("Product runtime PostgreSQL signer config unavailable")
								}
								clear(runtimePostgresConfig)
								t.Logf("same-run Product runtime PostgreSQL signer socket allocation=1 combined=%d; Product runtime process not launched", len(productRuntimeSocketVolumes))
							}
						}
					}
				}
			}
			anchorFiles = slice6PrepareTrustAnchorVolumes(t, ctx, run, composed)
			t.Logf("same-run trust-anchor allocations=%d; one root-owned read-only file per Profile storage ID, exact digests and non-root bind reads", len(anchorFiles))
		}
		if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INSTALL_VAULT_ACCESS") == "1" {
			management := slice6VaultInstallScopedAccess(t, ctx, run, serverID, configDir, composed.Profile, general, broker)
			defer clear(management.Token)
			if os.Getenv(slice6PostgresServerLeafEnv) == "1" {
				postgresLeaf = slice6VaultPreparePostgresServerLeaf(t, ctx, run, serverID, root,
					configDir, composed.Profile, general, management.Token)
				postgresClientCRL = slice6VaultReadPostgresClientCRL(t, ctx, run, serverID, general)
				defer clear(postgresClientCRL)
				t.Cleanup(func() {
					if !postgresTerminalConfirmed {
						t.Errorf("external PostgreSQL leaf remains unconfirmed for v2 terminal revoke: run=%s issuer=%s serial=%s leaf=%s",
							run.id, postgresLeaf.IssuerID, postgresLeaf.Serial, postgresLeaf.Record.LeafDigest)
					}
				})
			}
			if os.Getenv(slice6GuestMaterialEnv) == "1" {
				guestPublicMaterial = slice6VaultInstallGuestMaterial(t, ctx, run, serverID, configDir, composed.Profile)
				if os.Getenv(slice6ProductMaterialInputsEnv) == "1" {
					productIdentityDigest = slice6VaultInstallProductIdentityMaterial(t, ctx, run,
						serverID, configDir, composed.Profile)
				}
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
					runCredentialChain := func() {
						// All role/PKI material and bootstrap leaves are now fixed. The
						// controller chain must run with the orphan management token,
						// never with the bootstrap root authority still live.
						revokeBootstrapRoot()
						var onCredentialReady func(func() error)
						if os.Getenv(slice6CertificateProcessEnv) == "1" {
							onCredentialReady = func(stopCredential func() error) {
								var onTerminated func() error
								var onManagedReady func()
								if os.Getenv(slice6GuestMaterialEnv) == "1" {
									onManagedReady = func() {
										runWork := func() {
											slice6RunBreakGlassControllerStartup(t, ctx, run, composed, breakGlassSocketVolumes, func(restartController func()) {
												var guestBindingReceipt slice6GuestBindingFixtureReceipt
												var guestReceiptPair slice6GuestReceiptPair
												var mutationReceipt slice6GuestRevokeFixtureReceipt
												var mutationVerifiedAt time.Time
												var guestRuntimeID string
												var guestRuntimeFailure error
												var productRuntimeID string
												runGuestChain := func() {
													slice6RunGuestTLSAgentStartup(t, ctx, run, composed, guestSocketVolumes, anchorFiles, func() {
														materialFailure := slice6RunGuestMaterialAgentStartup(t, ctx, run, composed, serverID,
															guestPublicMaterial.Digest, guestSocketVolumes, anchorFiles,
															func(delivery phase6security.Slice6BreakGlassSocketBinding) {
																slice6ExerciseGuestBreakGlassDelivery(t, ctx, run, composed,
																	delivery, breakGlassSocketVolumes, restartController)
																if os.Getenv(slice6GuestRuntimeProcessEnv) == "1" {
																	var onConnected func(string) error
																	if os.Getenv(slice6GuestLiveRevokeEnv) == "1" {
																		onConnected = func(guestContainerID string) error {
																			guestRuntimeID = guestContainerID
																			revoked, err := slice6RunGuestLiveRevoke(ctx, run, composed.Profile,
																				productRuntimeID, guestContainerID, postgresServerID,
																				guestBindingFixture, guestBindingReceipt, productRuntimeSocketVolumes, anchorFiles,
																				productRuntimeObserver)
																			if err == nil {
																				mutationReceipt = revoked
																				mutationVerifiedAt = time.Now().UTC()
																				t.Logf("finite same-netns Product Store mutation confirmed; Guest post-mutation 503/exit1 observed, cause unproven: generation=%d backend_pid=%d (private receipt; not production audit)",
																					revoked.BindingGeneration, revoked.PostgresBackendPID)
																			}
																			return err
																		}
																	}
																	slice6RunOrdinaryTLSAgentStartup(t, ctx, run, composed,
																		"guest-runtime", "guest-tls-agent", "guest-runtime",
																		guestRuntimeSocketVolumes, anchorFiles, func() {
																			guestRuntimeFailure = slice6RunGuestRuntimePID1(t, ctx, run, composed,
																				guestBindingReceipt, guestRuntimeSocketVolumes, anchorFiles,
																				productRuntimeID, preIssuerGuestShellDigest, &guestReceiptPair, onConnected)
																		})
																}
															})
														guestRuntimeFailure = slice6PreserveFirstFailure(guestRuntimeFailure, materialFailure)
													})
													runtimeFailure = slice6PreserveFirstFailure(runtimeFailure, guestRuntimeFailure)
												}
												if os.Getenv(slice6ProductTLSSignerEnv) == "1" {
													runProductChain := runGuestChain
													if os.Getenv(slice6ProductMaterialInputsEnv) == "1" {
														runProductChain = func() {
															slice6RunOrdinaryTLSAgentStartup(t, ctx, run, composed,
																"product-runtime-agent", "product-runtime-agent-tls-agent", "product-material",
																productMaterialSocketVolumes, anchorFiles, func() {
																	materialFailure := slice6RunRuntimeMaterialAgentStartup(t, ctx, run, composed,
																		serverID, productIdentityDigest, productRuntimeDSNDigest,
																		"product-runtime-agent", "product-runtime",
																		"product-material", 70, productMaterialSocketVolumes, anchorFiles,
																		func(phase6security.Slice6BreakGlassSocketBinding) error {
																			if os.Getenv(slice6ProductRuntimeProcessEnv) == "1" {
																				if postgresServerID == "" {
																					runtimeFailure = errors.New("Product serve has no same-run PostgreSQL PID1")
																					return runtimeFailure
																				}
																				slice6RunOrdinaryTLSAgentStartup(t, ctx, run, composed,
																					"product-runtime", "product-postgres-tls-agent", "product-runtime-postgres",
																					productRuntimeSocketVolumes, anchorFiles, func() {
																						if os.Getenv(slice6GuestBindingFixtureEnv) == "1" {
																							guestBindingReceipt, runtimeFailure = slice6RunGuestBindingFixture(ctx, run, composed.Profile,
																								postgresServerID, productRuntimeSocketVolumes, anchorFiles,
																								guestBindingFixture, guestPublicMaterial)
																							if runtimeFailure != nil {
																								return
																							}
																							t.Logf("same-run finite Guest binding fixture exited and released Product SQL endpoint before Product PID1: binding_generation=%d event_count=%d audit_count=%d; identities remain private and no live Guest claimed",
																								guestBindingReceipt.BindingGeneration, guestBindingReceipt.EventCount, guestBindingReceipt.AuditCount)
																						}
																						productFailure := slice6RunProductRuntimePID1(t, ctx, run, composed,
																							postgresServerID, productRuntimeSocketVolumes, anchorFiles, productRuntimeObserver,
																							&guestReceiptPair,
																							func(id string) error { productRuntimeID = id; runGuestChain(); return guestRuntimeFailure })
																						runtimeFailure = slice6PreserveFirstFailure(runtimeFailure, productFailure)
																						if runtimeFailure == nil && composed.PrivateGuestReceipt {
																							runtimeFailure = guestReceiptPair.verifyRevoke(guestBindingReceipt.BindingGeneration)
																							if runtimeFailure == nil {
																								runtimeFailure = slice6FinishGuestReceiptEvidence(ctx, receiptEvidence,
																									static, verifiedImages, guestBindingFixture,
																									composed.Profile.ProfileDigest, mutationReceipt, mutationVerifiedAt,
																									productRuntimeID, guestRuntimeID)
																								if runtimeFailure == nil {
																									t.Log("private Product/Guest PID1 stdout receipts durably bound to same signed attempts, source/image identities and PG revocation; component evidence only")
																								}
																							}
																						}
																					})
																				if runtimeFailure != nil {
																					return runtimeFailure
																				}
																			}
																			if os.Getenv(slice6ProductRuntimeProcessEnv) != "1" {
																				runGuestChain()
																				return guestRuntimeFailure
																			}
																			return nil
																		})
																	runtimeFailure = slice6PreserveFirstFailure(runtimeFailure, materialFailure)
																})
														}
													}
													slice6RunOrdinaryTLSAgentStartup(t, ctx, run, composed,
														"product-runtime", "product-tls-agent", "product",
														productSocketVolumes, anchorFiles, runProductChain)
												} else {
													runGuestChain()
												}
											})
										}
										if os.Getenv(slice6ProductMigrationSignersEnv) == "1" {
											if len(productMigrationSocketVolumes) != 73 {
												t.Fatal("Product migration signers require all source-bound private inputs")
											}
											dependent := runWork
											runWork = func() {
												slice6RunOrdinaryTLSAgentStartup(t, ctx, run, composed,
													"product-migration-agent", "product-migration-agent-tls-agent", "product-migration-material",
													productMigrationSocketVolumes, anchorFiles, func() {
														migrationWork := func() {
															if os.Getenv(slice6ProductMigrationJobEnv) == "1" {
																if postgresServerID == "" {
																	migrationFailure = errors.New("Product migration has no live same-run PostgreSQL server")
																	return
																}
																migrationFailure = slice6RunRuntimeMaterialAgentStartup(t, ctx, run, composed,
																	serverID, "", "", "product-migration-agent", "product-migration-job",
																	"product-migration-material", 73, productMigrationSocketVolumes, anchorFiles,
																	func(phase6security.Slice6BreakGlassSocketBinding) error {
																		return slice6RunProductMigrationJob(t, ctx, run, composed,
																			postgresServerID, productMigrationSocketVolumes, anchorFiles)
																	})
																if migrationFailure != nil {
																	return
																}
															}
														}
														slice6RunOrdinaryTLSAgentStartup(t, ctx, run, composed,
															"product-migration-job", "product-migration-postgres-tls-agent", "product-migration-postgres",
															productMigrationSocketVolumes, anchorFiles, migrationWork)
													})
												if migrationFailure != nil {
													return
												}
												if os.Getenv(slice6ProductMigrationJobEnv) == "1" {
													if err := slice6VerifyProductMigrationReadback(ctx, postgresServerID); err != nil {
														migrationFailure = err
														return
													}
													t.Log("real Product migration v2 ledger, current table ownership and post-DDL grants read back from the same PostgreSQL process")
												}
												dependent()
											}
										}
										if os.Getenv(slice6ProductPostgresDSNEnv) == "1" {
											if postgresRecord == nil || postgresStop == nil {
												t.Fatal("Product PostgreSQL bootstrap did not complete before root revocation")
											}
											runWork()
										} else if os.Getenv(slice6PostgresServerLeafEnv) == "1" {
											slice6RunPostgresServer(t, ctx, run, composed, postgresLeaf, postgresClientCRL,
												func(record phase6terminalcleanup.ExternalPostgresRecord, postgresID string, _ func() error) {
													postgresRecord = &record
													postgresServerID = postgresID
													runWork()
												})
										} else {
											runWork()
										}
									}
								}
								if terminalOperator != nil {
									onTerminated = func() error {
										if postgresStop != nil {
											if err := postgresStop(); err != nil {
												terminalFailure = errors.Join(terminalFailure,
													errors.New("Product PostgreSQL did not stop before terminal certificate cleanup"))
											}
										}
										if os.Getenv(slice6PostgresServerLeafEnv) == "1" && postgresRecord == nil {
											terminalFailure = errors.Join(terminalFailure,
												errors.New("PostgreSQL leaf was not observed on stopped server before v2 cleanup"))
										}
										if terminalFailure == nil {
											terminalFailure = slice6RunTerminalOperator(t, ctx, run, composed, serverID,
												terminalBinaryPath, terminalBinaryDigest,
												management.Accessor, general, terminalOperator, postgresRecord)
										}
										if postgresRecord != nil && terminalFailure == nil {
											postgresTerminalConfirmed = true
										}
										return terminalFailure
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
					if os.Getenv(slice6ProductPostgresDSNEnv) == "1" {
						slice6RunPostgresServer(t, ctx, run, composed, postgresLeaf, postgresClientCRL,
							func(record phase6terminalcleanup.ExternalPostgresRecord, postgresID string, stop func() error) {
								postgresRecord = &record
								postgresServerID = postgresID
								postgresStop = stop
								dsns := slice6BootstrapProductPostgres(t, ctx, run, postgresID, composed.Profile)
								defer dsns.clear()
								slice6VaultInstallProductPostgresMaterial(t, ctx, run, serverID,
									configDir, composed.Profile, dsns)
								digest := sha256.Sum256(dsns.Runtime)
								productRuntimeDSNDigest = "sha256:" + hex.EncodeToString(digest[:])
								dsns.clear()
								t.Log("live Product SQL roles and exact Vault KVv2 DSNs bootstrapped before root revocation")
								runCredentialChain()
							})
					} else {
						runCredentialChain()
					}
				}
			}
		}
		if os.Getenv(slice6BreakGlassProcessEnv) == "1" && os.Getenv(slice6GuestMaterialEnv) != "1" {
			revokeBootstrapRoot()
			slice6RunBreakGlassControllerStartup(t, ctx, run, composed, breakGlassSocketVolumes, nil)
		}
	}
	revokeBootstrapRoot()
	if closeCapacityMonitor != nil {
		closeCapacityMonitor()
	}
	_ = cleanupGuard.Run(run.cleanup)
	if os.Getenv(slice6CertificateProcessEnv) == "1" {
		t.Log("real file-backed non-dev Vault and two controller PID1 processes reached managed issuance; exact Docker cleanup is checked at test exit and final release scenarios remain unproved")
	} else if os.Getenv(slice6CredentialProcessEnv) == "1" {
		t.Log("real file-backed non-dev Vault, same-run credential controller bootstrap PID1, ledger and private socket were observed; exact Docker cleanup is checked at test exit and the full Slice 6 gate remains unproved")
	} else {
		t.Log("real file-backed non-dev Vault retained two fixed issuers and complete CRLs across final mTLS trust restart as independently observed at the controller address; both temporary trust directions were rejected, exact Docker cleanup is checked at test exit, and no managed controller process launched")
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
		"key_usage=DigitalSignature", "code_signing_flag=false", "email_protection_flag=false",
		"not_before_duration=" + strconv.FormatInt(phase6security.Slice6VaultRoleBackdateSeconds, 10) + "s",
		"basic_constraints_valid_for_non_ca=true"}, flags...)
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
	if !client {
		var mask uint16
		set := func(bit uint16, valid bool) {
			if valid {
				mask |= 1 << bit
			}
		}
		now := time.Now().UTC()
		set(0, !leaf.IsCA && leaf.BasicConstraintsValid)
		set(1, leaf.KeyUsage == x509.KeyUsageDigitalSignature)
		set(2, reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) && len(leaf.UnknownExtKeyUsage) == 0)
		set(3, leaf.Subject.String() == "")
		set(4, len(leaf.URIs) == 1 && leaf.URIs[0] != nil && leaf.URIs[0].String() == wantURI)
		set(5, reflect.DeepEqual(leaf.DNSNames, []string{"vault.sandbox-runtime.test"}))
		set(6, len(leaf.IPAddresses) == 0 && len(leaf.EmailAddresses) == 0)
		set(7, leaf.NotBefore.Before(leaf.NotAfter) && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter))
		set(8, leaf.NotAfter.Sub(leaf.NotBefore) <= time.Hour)
		roots := x509.NewCertPool()
		roots.AddCert(root.Certificate)
		chains, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		set(9, verifyErr == nil && len(chains) == 1 && len(chains[0]) == 2 && bytes.Equal(chains[0][1].Raw, root.Certificate.Raw))
		t.Logf("NON-RELEASE final Vault server strict leaf diagnostic: mask=%03x is_ca=%t basic_constraints_valid=%t duration_ms=%d",
			mask, leaf.IsCA, leaf.BasicConstraintsValid, leaf.NotAfter.Sub(leaf.NotBefore).Milliseconds())
		if mask != 0x3ff {
			t.Fatal("final Vault server leaf cannot satisfy strict live TLS peer verification")
		}
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
			IssuerRef                     string `json:"issuer_ref"`
			NotBeforeDuration             int64  `json:"not_before_duration"`
			BasicConstraintsValidForNonCA bool   `json:"basic_constraints_valid_for_non_ca"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &document) != nil || document.Data.IssuerRef != issuerID ||
		document.Data.NotBeforeDuration != phase6security.Slice6VaultRoleBackdateSeconds ||
		!document.Data.BasicConstraintsValidForNonCA {
		t.Fatal("Vault final role issuer or strict leaf parameters changed")
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

// This is the complete original issuer CRL for PostgreSQL's own client-leaf
// verifier. It is supplied by the operator, never by a SQL login or a role.
func slice6VaultReadPostgresClientCRL(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID string, root slice6VaultRoot) []byte {
	t.Helper()
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "read", "-format=json",
		"pki/issuer/"+root.ID+"/crl")...)
	defer clear(response)
	var document struct {
		Data struct {
			CRL string `json:"crl"`
		} `json:"data"`
	}
	if err != nil || len(response) > 128<<10 || json.Unmarshal(response, &document) != nil ||
		len(document.Data.CRL) > 64<<10 {
		t.Fatal("read bounded original PostgreSQL client issuer CRL")
	}
	block, remainder := pem.Decode([]byte(document.Data.CRL))
	if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatal("original PostgreSQL client issuer CRL encoding drifted")
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	now := time.Now().UTC()
	if err != nil || list.Number == nil || !bytes.Equal(list.RawIssuer, root.Certificate.RawSubject) ||
		list.CheckSignatureFrom(root.Certificate) != nil || list.ThisUpdate.After(now) ||
		!list.NextUpdate.After(now) {
		t.Fatal("original PostgreSQL client issuer CRL signature or validity drifted")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: block.Bytes})
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
