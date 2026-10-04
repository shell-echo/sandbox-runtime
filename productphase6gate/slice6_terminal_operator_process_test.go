//go:build phase6slice6gate

package productphase6gate

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
)

const slice6TerminalOperatorEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_OPERATOR"
const slice6TerminalOperatorUID = 20090
const slice6TerminalOperatorGID = 30090
const slice6TerminalOperatorV2Capability = "sandbox-runtime.phase6-terminal-cleanup-input.v2\n"
const slice6TerminalOperatorV3Capability = "sandbox-runtime.phase6-terminal-cleanup-input.v3\n"
const slice6TerminalOperatorV3DiagnosticEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_V3_DIAGNOSTIC"
const slice6TerminalExpectedDigestEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_BINARY_EXPECTED_DIGEST"

var slice6TerminalStagePattern = regexp.MustCompile(`phase6-terminal-cleanup: unavailable stage=([a-z][a-z-]{0,63})`)

func slice6ClosedTerminalOperatorStage(raw string) string {
	switch raw {
	case "input-boundary", "input-timeout", "input-read", "input-decode", "profile-decode",
		"sources-decode", "plan-rebuild", "vault-client", "evidence-replay", "evidence-encode",
		"evidence-write", "receipt-encode", "receipt-write", "execute-token-preflight-absent",
		"execute-token-preflight-bound", "execute-certificate-revoke", "execute-crl-read",
		"execute-crl-issuer", "execute-crl-signature", "execute-crl-target", "execute-token-revoke",
		"execute-token-readback", "execute-operator-self-revoke":
		return raw
	default:
		return "unknown"
	}
}

// A leaf may not be signed merely because the terminal operator built. The
// clean-source Linux binary must declare v2 before this run creates Vault.
func slice6RequireTerminalOperatorV2Capability(t *testing.T, ctx context.Context,
	run slice6DockerRun, binaryPath, binaryDigest string) {
	t.Helper()
	output := slice6ReadTerminalOperatorCapabilities(t, ctx, run, binaryPath, binaryDigest)
	if output != slice6TerminalOperatorV2Capability &&
		output != slice6TerminalOperatorV2Capability+slice6TerminalOperatorV3Capability {
		t.Fatal("source-bound terminal operator lacks exact v2 capability; refusing PostgreSQL leaf signing")
	}
}

func slice6RequireTerminalOperatorV3Capability(t *testing.T, ctx context.Context,
	run slice6DockerRun, binaryPath, binaryDigest string) {
	t.Helper()
	if output := slice6ReadTerminalOperatorCapabilities(t, ctx, run, binaryPath, binaryDigest); output != slice6TerminalOperatorV2Capability+slice6TerminalOperatorV3Capability {
		t.Fatal("source-bound terminal operator lacks exact v3 capability; refusing new signing")
	}
}

func slice6ReadTerminalOperatorCapabilities(t *testing.T, ctx context.Context,
	run slice6DockerRun, binaryPath, binaryDigest string) string {
	t.Helper()
	if binaryPath == "" || slice6HashTerminalBinary(t, binaryPath) != binaryDigest {
		t.Fatal("external PostgreSQL leaf requires a fixed terminal operator binary")
	}
	output, err := run.docker(ctx, "run", "--rm", "--pull=never",
		"--name", "sr-p6-terminal-v2-preflight-"+run.id,
		"--label", run.label(), "--network=none", "--restart=no",
		"--user", fmt.Sprintf("%d:%d", slice6TerminalOperatorUID, slice6TerminalOperatorGID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--read-only", "--memory=32m", "--cpus=0.25", "--pids-limit=16",
		"--mount", "type=bind,src="+binaryPath+",dst=/phase6-terminal-cleanup,readonly",
		"--entrypoint=/phase6-terminal-cleanup", slice6PinnedAlpineImage, "--capabilities")
	if err != nil || len(output) > 256 {
		t.Fatal("source-bound terminal operator capability output unavailable")
	}
	return string(output)
}

type slice6TerminalOperatorInput struct {
	Protocol              string                                        `json:"protocol"`
	RunID                 string                                        `json:"run_id"`
	ProfileJSON           []byte                                        `json:"profile_json"`
	PeerSourcesJSON       []byte                                        `json:"peer_sources_json"`
	CertificateLedgerJSON []byte                                        `json:"certificate_ledger_json"`
	CredentialLedgerJSON  []byte                                        `json:"credential_ledger_json"`
	ManagementAccessor    string                                        `json:"management_accessor"`
	ExternalPostgres      *phase6terminalcleanup.ExternalPostgresRecord `json:"external_postgres,omitempty"`
	PlanDigest            string                                        `json:"plan_digest"`
	VaultEndpoint         string                                        `json:"vault_endpoint"`
	VaultServerCAPEM      []byte                                        `json:"vault_server_ca_pem"`
	ClientCertificatePEM  []byte                                        `json:"client_certificate_pem"`
	ClientPrivateKeyPEM   []byte                                        `json:"client_private_key_pem"`
	OperatorToken         []byte                                        `json:"operator_token"`
	TokenExpiresAt        time.Time                                     `json:"token_expires_at"`
}

// Build before signing the short-lived operator leaf or minting its token.
// The executable is a separate clean-source artifact, not an Alpine layer.
func slice6BuildTerminalOperator(t *testing.T, ctx context.Context, privateRoot, sourceRoot, sourceRevision string) (string, string) {
	t.Helper()
	sourceRoot, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil || !filepath.IsAbs(sourceRoot) {
		t.Fatal("terminal operator requires independent clean source checkout")
	}
	revisionDocument, err := exec.CommandContext(ctx, "git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil || verifyCleanSlice6Source(ctx, sourceRoot, strings.TrimSpace(string(revisionDocument))) != nil {
		t.Fatal("terminal operator source is not an immutable clean revision")
	}
	if strings.TrimSpace(string(revisionDocument)) != sourceRevision {
		t.Fatal("terminal operator source must be the exact independently clean Profile/candidate source revision")
	}
	version, err := exec.CommandContext(ctx, "go", "env", "GOVERSION").Output()
	if err != nil || string(bytes.TrimSpace(version)) != "go1.26.8" {
		t.Fatal("terminal operator requires the reviewed Go 1.26.8 toolchain")
	}
	treeDocument, err := exec.CommandContext(ctx, "git", "-C", sourceRoot, "rev-parse", "HEAD^{tree}").Output()
	if err != nil || len(bytes.TrimSpace(treeDocument)) != 40 {
		t.Fatal("terminal operator source tree identity unavailable")
	}
	binaryPath := filepath.Join(privateRoot, "phase6-terminal-cleanup")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", binaryPath, "./cmd/phase6-terminal-cleanup")
	build.Dir = sourceRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	if _, err := build.CombinedOutput(); err != nil {
		t.Fatal("build source-bound one-shot terminal operator")
	}
	if err := os.Chmod(binaryPath, 0o555); err != nil {
		t.Fatal("set reviewed read-only executable mode")
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil || len(binary) < 1 || len(binary) > 32<<20 {
		clear(binary)
		t.Fatal("read bounded source-bound terminal operator command")
	}
	hash := sha256.Sum256(binary)
	clear(binary)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	t.Logf("terminal operator separate source revision=%s tree=%s toolchain=go1.26.8 build=CGO_ENABLED=0,linux/arm64,-mod=readonly,-trimpath,-buildvcs=false,-ldflags=-buildid= binary=%s",
		strings.TrimSpace(string(revisionDocument)), strings.TrimSpace(string(treeDocument)), digest)
	return binaryPath, digest
}

func slice6ApproveTerminalBinaryDigest(actual, expected string) error {
	if !guestRevokeFixtureDigestGate(expected) || !guestRevokeFixtureDigestGate(actual) || actual != expected {
		return errors.New("terminal operator differs from externally approved binary digest")
	}
	return nil
}

func TestSlice6TerminalBinaryExternalDigestApprovalNoIssuer(t *testing.T) {
	actual := "sha256:" + strings.Repeat("a", 64)
	if err := slice6ApproveTerminalBinaryDigest(actual, actual); err != nil {
		t.Fatalf("valid external approval rejected: %v", err)
	}
	for _, expected := range []string{"", "sha256:" + strings.Repeat("b", 64),
		"SHA256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("z", 64)} {
		if slice6ApproveTerminalBinaryDigest(actual, expected) == nil {
			t.Fatalf("invalid external terminal approval accepted: %q", expected)
		}
	}
	if slice6ApproveTerminalBinaryDigest("", actual) == nil {
		t.Fatal("missing actual terminal binary accepted")
	}
}

func slice6RunTerminalOperator(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, vaultID, binaryPath, binaryDigest, managementAccessor string,
	general slice6VaultRoot, credential *slice6TerminalOperatorCredential,
	externalPostgres *phase6terminalcleanup.ExternalPostgresRecord,
	v3 ...*slice6TerminalV3Sink) (resultErr error) {
	t.Helper()
	if len(v3) > 1 {
		return errors.New("terminal operator private evidence sink is ambiguous")
	}
	var evidenceSink *slice6TerminalV3Sink
	if len(v3) == 1 {
		evidenceSink = v3[0]
		if evidenceSink == nil || evidenceSink.Run == nil || evidenceSink.Run.id != run.id ||
			externalPostgres == nil {
			return errors.New("terminal v3 requires exact run-owned external PostgreSQL evidence")
		}
	}
	if os.Getenv(slice6TerminalOperatorEnv) != "1" || credential == nil ||
		!credential.ExpiresAt.After(time.Now().Add(90*time.Second)) ||
		phase6security.VerifySlice6DesiredFinalExternalProfile(composed.Profile) != nil ||
		len(vaultID) != 64 || !lowerHexSlice6(vaultID) ||
		!strings.HasPrefix(binaryDigest, "sha256:") {
		return errors.New("terminal operator requires prefrozen live run authority")
	}
	if parent == nil {
		return errors.New("terminal operator parent context unavailable")
	}
	// Terminal revocation is independent of canceled business work. It still
	// has the existing finite budget and short-lived credential expiry.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	certificateLedger, certificateErr := slice6ReadTerminalLedgerResult(ctx, run, composed.Profile, "certificate-controller")
	credentialLedger, credentialErr := slice6ReadTerminalLedgerResult(ctx, run, composed.Profile, "workload-credential-controller")
	defer clear(certificateLedger)
	defer clear(credentialLedger)
	if certificateErr != nil || credentialErr != nil {
		return errors.Join(certificateErr, credentialErr)
	}
	var plan phase6terminalcleanup.Plan
	var err error
	if externalPostgres != nil {
		plan, err = phase6terminalcleanup.BuildV2(run.id, composed.Profile, composed.PeerSources,
			certificateLedger, credentialLedger, managementAccessor, *externalPostgres, time.Now().UTC())
	} else {
		plan, err = phase6terminalcleanup.Build(run.id, composed.Profile, composed.PeerSources,
			certificateLedger, credentialLedger, managementAccessor, time.Now().UTC())
	}
	if err != nil || plan.Validate() != nil {
		return errors.New("independently read quiesced ledgers cannot bind the exact terminal cleanup plan")
	}
	var ledgerProjection []byte
	var ledgerProjectionErr error
	ledgerProjectionStage := ""
	if evidenceSink != nil && evidenceSink.verifiedPrecleanup {
		// Reuse the same two bounded reads consumed by BuildV2. Failure of
		// projection must not prevent the one-shot remote revocation below.
		ledgerProjection, ledgerProjectionErr = slice6ProjectTerminalLedgers(plan, certificateLedger, credentialLedger)
		if ledgerProjectionErr != nil {
			ledgerProjectionStage = "ledger_projection"
		}
		if ledgerProjectionErr == nil {
			ledgerProjectionErr = slice6VerifyTerminalEIssuedSet(ledgerProjection, composed.Profile)
			if ledgerProjectionErr != nil {
				ledgerProjectionStage = "issued_set"
			}
		}
		defer clear(ledgerProjection)
	}
	profileJSON, err := json.Marshal(composed.Profile)
	if err != nil {
		return errors.New("encode exact operator Profile input")
	}
	peerJSON, err := json.Marshal(composed.PeerSources)
	if err != nil {
		return errors.New("encode exact operator peer source input")
	}
	inputProtocol := "sandbox-runtime.phase6-terminal-cleanup-input.v1"
	if externalPostgres != nil {
		inputProtocol = slice6TerminalOperatorV2Capability[:len(slice6TerminalOperatorV2Capability)-1]
	}
	if evidenceSink != nil {
		inputProtocol = slice6TerminalOperatorV3Capability[:len(slice6TerminalOperatorV3Capability)-1]
	}
	input := slice6TerminalOperatorInput{Protocol: inputProtocol,
		RunID: run.id, ProfileJSON: profileJSON, PeerSourcesJSON: peerJSON,
		CertificateLedgerJSON: certificateLedger, CredentialLedgerJSON: credentialLedger,
		ExternalPostgres:   externalPostgres,
		ManagementAccessor: managementAccessor, PlanDigest: plan.Digest,
		VaultEndpoint: "https://vault.sandbox-runtime.test:8200", VaultServerCAPEM: general.PEM,
		ClientCertificatePEM: credential.LeafPEM, ClientPrivateKeyPEM: credential.KeyPEM,
		OperatorToken: credential.Token, TokenExpiresAt: credential.ExpiresAt}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 18<<20 {
		clear(encoded)
		return errors.New("bounded terminal operator envelope unavailable")
	}
	defer clear(encoded)
	if hash, hashErr := slice6HashTerminalBinaryResult(binaryPath); hashErr != nil || hash != binaryDigest {
		return errors.New("terminal operator binary changed after source build")
	}
	operatorNetworkName := "sr-p6-terminal-only-" + run.id
	networkDocument, err := run.docker(ctx, "network", "create", "--driver=bridge", "--internal",
		"--opt=com.docker.network.bridge.gateway_mode_ipv4=isolated", "--label", run.label(), operatorNetworkName)
	networkID := strings.TrimSpace(string(networkDocument))
	if err != nil || len(networkID) != 64 || !lowerHexSlice6(networkID) {
		return errors.New("create isolated Vault-only terminal operator network")
	}
	var containerID string
	vaultConnected := false
	receiptConfirmed := false
	defer func() {
		cleanup := &slice6CleanupSequence{stages: []slice6CleanupStage{
			{"remove-terminal-container", func(ctx context.Context) error {
				if containerID == "" {
					return nil
				}
				if _, err := run.docker(ctx, "rm", "-f", containerID); err != nil {
					return errors.New("remove exact terminal operator task")
				}
				return nil
			}},
			{"disconnect-terminal-vault", func(ctx context.Context) error {
				if !vaultConnected {
					return nil
				}
				if _, err := run.docker(ctx, "network", "disconnect", networkID, vaultID); err != nil {
					return errors.New("remove Vault from terminal-only network")
				}
				return nil
			}},
			{"remove-terminal-network", func(ctx context.Context) error {
				if _, err := run.docker(ctx, "network", "rm", networkID); err != nil {
					return errors.New("remove exact terminal-only network")
				}
				return nil
			}},
		}}
		resultErr = errors.Join(resultErr, cleanup.Run())
		if resultErr == nil && receiptConfirmed {
			t.Logf("one-shot terminal operator confirmed %d certs, two token accessors, complete CRL and self-revoke; source-bound binary %s; private receipt plan=%s", len(plan.Certificates), binaryDigest, plan.Digest)
		}
	}()
	if _, err := run.docker(ctx, "network", "connect", "--alias", "vault.sandbox-runtime.test",
		networkID, vaultID); err != nil {
		return errors.New("attach sole Vault endpoint to terminal operator network")
	}
	vaultConnected = true
	root, err := filepath.Abs("..")
	if err != nil {
		return errors.New("terminal operator source checkout unavailable")
	}
	seccompPath := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	seccompDocument, err := os.ReadFile(seccompPath)
	if err != nil {
		return errors.New("read locked terminal operator seccomp")
	}
	seccompHash := sha256.Sum256(seccompDocument)
	var controllerSeccompDigest string
	for _, principal := range composed.Profile.Principals {
		if principal.Name == "certificate-controller" {
			controllerSeccompDigest = principal.SeccompDigest
		}
	}
	if controllerSeccompDigest != "sha256:"+hex.EncodeToString(seccompHash[:]) {
		return errors.New("terminal operator seccomp differs from reviewed controller profile")
	}
	for _, principal := range composed.Profile.Principals {
		if principal.UID == slice6TerminalOperatorUID || principal.GID == slice6TerminalOperatorGID {
			return errors.New("finite operator identity aliases a resident Profile principal")
		}
	}
	carrierID, carrierErr := slice6VerifyTerminalCarrierResult(ctx, run)
	if carrierErr != nil {
		return carrierErr
	}
	identity := fmt.Sprintf("%d:%d", slice6TerminalOperatorUID, slice6TerminalOperatorGID)
	containerName := "sr-p6-terminal-cleanup-" + run.id
	created, err := run.docker(ctx, "create", "-i", "--pull=never", "--name", containerName,
		"--label", run.label(), "--log-driver=none", "--network", networkID,
		"--restart=no", "--user", identity, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--security-opt", "seccomp="+seccompPath,
		"--read-only", "--memory=128m", "--cpus=0.5", "--pids-limit=32",
		"--mount", "type=bind,src="+binaryPath+",dst=/phase6-terminal-cleanup,readonly",
		"--entrypoint=/phase6-terminal-cleanup", slice6PinnedAlpineImage, "--one-shot")
	containerID = strings.TrimSpace(string(created))
	if err != nil || len(containerID) != 64 || !lowerHexSlice6(containerID) {
		return errors.New("create restricted terminal operator task")
	}
	if err := slice6VerifyTerminalContainerResult(ctx, run, containerID, networkID, identity,
		binaryPath, seccompPath, carrierID); err != nil {
		return err
	}
	if err := slice6VerifyTerminalMountedBinaryResult(ctx, containerID, binaryPath, binaryDigest); err != nil {
		return err
	}
	attached := exec.CommandContext(ctx, "docker", "start", "-a", "-i", containerID)
	attached.Stdin = bytes.NewReader(encoded)
	var output []byte
	var stderr []byte
	var startErr error
	var stdoutOverflow, stderrOverflow bool
	operatorStarted := time.Now().UTC()
	if evidenceSink == nil {
		output, startErr = attached.CombinedOutput()
	} else {
		stdoutCapture := &slice6BoundedPrivateOutput{maximum: phase6terminalcleanup.MaxEvidenceV3Bytes}
		stderrCapture := &slice6BoundedPrivateOutput{maximum: 1024}
		attached.Stdout, attached.Stderr = stdoutCapture, stderrCapture
		startErr = attached.Run()
		output, stderr = stdoutCapture.buffer.Bytes(), stderrCapture.buffer.Bytes()
		stdoutOverflow, stderrOverflow = stdoutCapture.overflow, stderrCapture.overflow
	}
	operatorFinished := time.Now().UTC()
	defer clear(output)
	defer clear(stderr)
	networkErr := slice6VerifyTerminalNetworkResult(ctx, run, networkID, vaultID, containerID)
	if networkErr != nil {
		return networkErr
	}
	if evidenceSink != nil {
		stage := "unknown"
		if matched := slice6TerminalStagePattern.FindSubmatch(stderr); len(matched) == 2 {
			stage = slice6ClosedTerminalOperatorStage(string(matched[1]))
		}
		if startErr != nil || stdoutOverflow || stderrOverflow || len(stderr) != 0 {
			return fmt.Errorf("terminal v3 private operator incomplete: stage=%s", stage)
		}
		var evidence phase6terminalcleanup.EvidenceV3
		if err := slice6TerminalV3FirstFailure(
			slice6TerminalV3Check{"stdout_decode", func() error {
				var err error
				evidence, err = phase6terminalcleanup.DecodeEvidenceV3(output)
				return err
			}},
			slice6TerminalV3Check{"evidence_verify", func() error {
				return phase6terminalcleanup.VerifyEvidenceV3(plan, evidence)
			}},
			slice6TerminalV3Check{"identity", func() error {
				if evidence.Receipt.RunID != run.id ||
					evidence.Receipt.ProfileDigest != composed.Profile.ProfileDigest {
					return phase6terminalcleanup.ErrInvalid
				}
				return nil
			}},
			slice6TerminalV3Check{ledgerProjectionStage, func() error { return ledgerProjectionErr }},
			slice6TerminalV3Check{"persist", func() error {
				return evidenceSink.persist(plan, output, containerID, binaryDigest,
					operatorStarted, operatorFinished, ledgerProjection)
			}},
		); err != nil {
			return err
		}
		receiptConfirmed = true
		return nil
	}
	receipt, decodeErr := phase6terminalcleanup.DecodeReceipt(output)
	if startErr != nil || decodeErr != nil ||
		!receipt.Complete || !receipt.SelfRevoked || receipt.PlanDigest != plan.Digest ||
		receipt.RunID != run.id || receipt.ProfileDigest != composed.Profile.ProfileDigest ||
		phase6terminalcleanup.VerifyReceipt(plan, receipt) != nil {
		stage := "unknown"
		if matched := slice6TerminalStagePattern.FindSubmatch(output); len(matched) == 2 {
			stage = slice6ClosedTerminalOperatorStage(string(matched[1]))
		}
		var partial phase6terminalcleanup.Receipt
		firstLine := bytes.SplitN(output, []byte{'\n'}, 2)[0]
		if len(firstLine) < 16<<10 && json.Unmarshal(firstLine, &partial) == nil &&
			partial.PlanDigest == plan.Digest && partial.RunID == run.id &&
			regexp.MustCompile(`^[a-z][a-z-]{0,63}$`).MatchString(partial.FailureStage) {
			stage = slice6ClosedTerminalOperatorStage("execute-" + partial.FailureStage)
		}
		return fmt.Errorf("terminal operator did not return an exact complete private receipt: stage=%s", stage)
	}
	receiptConfirmed = true
	return nil
}

func slice6ReadTerminalLedger(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, owner string) []byte {
	t.Helper()
	document, err := slice6ReadTerminalLedgerResult(ctx, run, profile, owner)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func slice6ReadTerminalLedgerResult(ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, owner string) ([]byte, error) {
	var principal phase6security.Principal
	for _, value := range profile.Principals {
		if value.Name == owner {
			principal = value
		}
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount(owner)
	if err != nil || principal.UID == 0 || principal.GID == 0 {
		return nil, errors.New("unknown exclusive terminal ledger owner")
	}
	volume := "sr-p6-ledger-" + owner + "-" + run.id
	identity := fmt.Sprintf("%d:%d", principal.UID, principal.GID)
	document, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-terminal-read-"+owner+"-"+run.id,
		"--label", run.label(), "--network=none", "--user", identity, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--read-only", "--memory=32m", "--cpus=0.25", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/ledger,readonly", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", "test \"$(stat -c '%u:%g:%a' /ledger/ledger.json)\" = '"+identity+":600' && test -z \"$(find /ledger -mindepth 1 -maxdepth 1 ! -name ledger.json)\" && cat /ledger/ledger.json")
	if err != nil || len(document) < 1 || len(document) > 8<<20 || filepath.Base(ledgerPath) != "ledger.json" {
		clear(document)
		return nil, errors.New("independent exact quiesced ledger read failed")
	}
	return document, nil
}

func slice6VerifyTerminalCarrier(t *testing.T, ctx context.Context, run slice6DockerRun) string {
	t.Helper()
	id, err := slice6VerifyTerminalCarrierResult(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func slice6VerifyTerminalCarrierResult(ctx context.Context, run slice6DockerRun) (string, error) {
	document, err := run.docker(ctx, "image", "inspect", slice6PinnedAlpineImage)
	var images []struct {
		ID           string   `json:"Id"`
		OS           string   `json:"Os"`
		Architecture string   `json:"Architecture"`
		RepoDigests  []string `json:"RepoDigests"`
		Config       struct {
			Volumes    map[string]any `json:"Volumes"`
			Env        []string       `json:"Env"`
			Entrypoint []string       `json:"Entrypoint"`
			Cmd        []string       `json:"Cmd"`
		} `json:"Config"`
	}
	if err != nil || json.Unmarshal(document, &images) != nil || len(images) != 1 ||
		!strings.HasPrefix(images[0].ID, "sha256:") || len(images[0].ID) != 71 ||
		images[0].OS != "linux" || images[0].Architecture != "arm64" ||
		len(images[0].Config.Volumes) != 0 ||
		!slices.Equal(images[0].Config.Env, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}) ||
		len(images[0].Config.Entrypoint) != 0 || !slices.Equal(images[0].Config.Cmd, []string{"/bin/sh"}) {
		return "", errors.New("pinned Alpine carrier platform, config or no-volume boundary drift")
	}
	lockedDigest := strings.TrimPrefix(slice6PinnedAlpineImage, "docker.io/library/")
	if !slices.Contains(images[0].RepoDigests, lockedDigest) {
		return "", errors.New("terminal carrier OCI repository digest not selected")
	}
	return images[0].ID, nil
}

func slice6HashTerminalBinary(t *testing.T, path string) string {
	t.Helper()
	digest, err := slice6HashTerminalBinaryResult(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func slice6HashTerminalBinaryResult(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 ||
		info.Size() < 1 || info.Size() > 32<<20 {
		return "", errors.New("terminal operator executable is not a bounded immutable-mode file")
	}
	document, err := os.ReadFile(path)
	if err != nil || int64(len(document)) != info.Size() {
		clear(document)
		return "", errors.New("terminal operator executable changed during read")
	}
	digest := sha256.Sum256(document)
	clear(document)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// docker cp resolves the bind inside the exact created container, not merely
// the host source path. No token is delivered until these actual mounted
// bytes agree with the clean-source build digest and host file remains fixed.
func slice6VerifyTerminalMountedBinary(t *testing.T, ctx context.Context,
	containerID, binaryPath, expectedDigest string) {
	t.Helper()
	if err := slice6VerifyTerminalMountedBinaryResult(ctx, containerID, binaryPath, expectedDigest); err != nil {
		t.Fatal(err)
	}
}

func slice6VerifyTerminalMountedBinaryResult(ctx context.Context,
	containerID, binaryPath, expectedDigest string) error {
	archive, err := exec.CommandContext(ctx, "docker", "cp", containerID+":/phase6-terminal-cleanup", "-").Output()
	if err != nil || len(archive) < 1 || len(archive) > 33<<20 {
		clear(archive)
		return errors.New("read exact terminal operator bind from created container")
	}
	defer clear(archive)
	reader := tar.NewReader(bytes.NewReader(archive))
	header, err := reader.Next()
	if err != nil || header.Name != "phase6-terminal-cleanup" || header.Typeflag != tar.TypeReg ||
		header.Size < 1 || header.Size > 32<<20 || header.Mode&0o777 != 0o555 {
		return errors.New("terminal operator bind archive type, mode or size drift")
	}
	hash := sha256.New()
	if count, copyErr := io.CopyN(hash, reader, header.Size); copyErr != nil || count != header.Size {
		return errors.New("terminal operator bind archive content truncated")
	}
	hostDigest, hashErr := slice6HashTerminalBinaryResult(binaryPath)
	if _, err := reader.Next(); !errors.Is(err, io.EOF) ||
		"sha256:"+hex.EncodeToString(hash.Sum(nil)) != expectedDigest ||
		hashErr != nil || hostDigest != expectedDigest {
		return errors.New("actual terminal operator executable differs from source-bound digest")
	}
	return nil
}

func slice6VerifyTerminalContainer(t *testing.T, ctx context.Context, run slice6DockerRun,
	id, networkID, identity, binaryPath, seccompPath, carrierID string) {
	t.Helper()
	if err := slice6VerifyTerminalContainerResult(ctx, run, id, networkID, identity,
		binaryPath, seccompPath, carrierID); err != nil {
		t.Fatal(err)
	}
}

func slice6VerifyTerminalContainerResult(ctx context.Context, run slice6DockerRun,
	id, networkID, identity, binaryPath, seccompPath, carrierID string) error {
	document, err := run.docker(ctx, "inspect", id)
	var observed []struct {
		Image  string `json:"Image"`
		Config struct {
			Image      string   `json:"Image"`
			User       string   `json:"User"`
			Entrypoint []string `json:"Entrypoint"`
			Cmd        []string `json:"Cmd"`
			Env        []string `json:"Env"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode    string         `json:"NetworkMode"`
			ReadonlyRootfs bool           `json:"ReadonlyRootfs"`
			Privileged     bool           `json:"Privileged"`
			CapDrop        []string       `json:"CapDrop"`
			CapAdd         []string       `json:"CapAdd"`
			SecurityOpt    []string       `json:"SecurityOpt"`
			Memory         int64          `json:"Memory"`
			NanoCPUs       int64          `json:"NanoCpus"`
			PidsLimit      int64          `json:"PidsLimit"`
			PortBindings   map[string]any `json:"PortBindings"`
			LogConfig      struct {
				Type string `json:"Type"`
			} `json:"LogConfig"`
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if err != nil || json.Unmarshal(document, &observed) != nil || len(observed) != 1 ||
		observed[0].Image != carrierID {
		return errors.New("terminal operator image identity drift")
	}
	container := observed[0]
	seccompSource, readErr := os.ReadFile(seccompPath)
	var compactSeccomp bytes.Buffer
	if readErr != nil || json.Compact(&compactSeccomp, seccompSource) != nil {
		return errors.New("canonicalize terminal operator seccomp")
	}
	if container.Config.Image != slice6PinnedAlpineImage || container.Config.User != identity ||
		!slices.Equal(container.Config.Entrypoint, []string{"/phase6-terminal-cleanup"}) ||
		!slices.Equal(container.Config.Cmd, []string{"--one-shot"}) ||
		container.HostConfig.NetworkMode != networkID || !container.HostConfig.ReadonlyRootfs ||
		container.HostConfig.Privileged || !slices.Equal(container.HostConfig.CapDrop, []string{"ALL"}) ||
		len(container.HostConfig.CapAdd) != 0 ||
		container.HostConfig.Memory != 128<<20 || container.HostConfig.NanoCPUs != 500000000 ||
		container.HostConfig.PidsLimit != 32 || len(container.HostConfig.PortBindings) != 0 ||
		container.HostConfig.LogConfig.Type != "none" || container.HostConfig.RestartPolicy.Name != "no" ||
		len(container.Mounts) != 1 || container.Mounts[0].Type != "bind" ||
		container.Mounts[0].Source != binaryPath || container.Mounts[0].Destination != "/phase6-terminal-cleanup" ||
		container.Mounts[0].RW {
		return errors.New("terminal operator effective task bounds drift")
	}
	if !slices.Equal(container.Config.Env, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}) ||
		!slices.Contains(container.HostConfig.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(container.HostConfig.SecurityOpt, "seccomp="+compactSeccomp.String()) {
		return errors.New("terminal operator environment or security options drift")
	}
	return nil
}

func slice6VerifyTerminalNetwork(t *testing.T, ctx context.Context, run slice6DockerRun,
	networkID, vaultID, operatorID string) {
	t.Helper()
	if err := slice6VerifyTerminalNetworkResult(ctx, run, networkID, vaultID, operatorID); err != nil {
		t.Fatal(err)
	}
}

func slice6VerifyTerminalNetworkResult(ctx context.Context, run slice6DockerRun,
	networkID, vaultID, operatorID string) error {
	document, err := run.docker(ctx, "network", "inspect", networkID)
	var observed []struct {
		Internal   bool                       `json:"Internal"`
		Options    map[string]string          `json:"Options"`
		Containers map[string]json.RawMessage `json:"Containers"`
	}
	if err != nil || json.Unmarshal(document, &observed) != nil || len(observed) != 1 ||
		!observed[0].Internal ||
		observed[0].Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" ||
		(len(observed[0].Containers) != 1 && len(observed[0].Containers) != 2) ||
		observed[0].Containers[vaultID] == nil {
		return errors.New("terminal operator bridge has unexpected members or isolation")
	}
	for id := range observed[0].Containers {
		if id != vaultID && id != operatorID {
			return errors.New("terminal operator bridge contains an unknown endpoint")
		}
	}
	return nil
}
