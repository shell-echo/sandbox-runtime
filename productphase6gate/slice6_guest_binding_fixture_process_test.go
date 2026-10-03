//go:build phase6slice6gate

package productphase6gate

import (
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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6GuestBindingFixtureEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_BINDING_FIXTURE"
const slice6GuestBindingFixtureExpectedDigestEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_BINDING_FIXTURE_EXPECTED_DIGEST"
const slice6GuestBindingFixtureProtocol = "sandbox-runtime.phase6-guest-binding-fixture.v1"
const slice6GuestFixtureVolumeDockerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_FIXTURE_VOLUME_DOCKER"
const slice6GuestRevokeNamespaceDockerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_REVOKE_NAMESPACE_DOCKER"
const slice6GuestFixtureSourceRootEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_FIXTURE_SOURCE_ROOT"
const slice6GuestFixtureSourceRevisionEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_FIXTURE_SOURCE_REVISION"

type slice6GuestBindingFixtureArtifact struct {
	Path, Digest, SourceRevision, ExpectedDigest string
}

func slice6AllowedGuestFixtureSourceDifference(path string) bool {
	if strings.HasPrefix(path, "docs/") {
		return true
	}
	if strings.HasPrefix(path, "productphase6gate/") && strings.HasSuffix(path, "_test.go") {
		return true
	}
	if path == "guestagent/hub_test.go" {
		return true
	}
	switch path {
	case "cmd/phase6_guest_binding_fixture.go", "cmd/phase6_guest_binding_fixture_test.go",
		"cmd/phase6_guest_revoke_fixture.go", "cmd/phase6_guest_revoke_fixture_test.go":
		return true
	}
	return false
}

func TestSlice6GuestFixtureSourceDeltaClosedAllowlist(t *testing.T) {
	for _, path := range []string{
		"cmd/phase6_guest_revoke_fixture.go", "cmd/phase6_guest_binding_fixture_test.go",
		"productphase6gate/slice6_capacity_monitor_test.go", "guestagent/hub_test.go",
		"docs/adr/0055-phase-6-slice-6.md",
	} {
		if !slice6AllowedGuestFixtureSourceDifference(path) {
			t.Fatalf("fixture-only path rejected: %s", path)
		}
	}
	for _, path := range []string{
		"go.mod", "go.sum", "cmd/product_postgres_v3.go", "guestagent/agent.go",
		"productphase6gate/runtime.go", "internal/phase6security/profile.go", ".github/workflows/gate.yml",
	} {
		if slice6AllowedGuestFixtureSourceDifference(path) {
			t.Fatalf("ordinary runtime/build drift admitted: %s", path)
		}
	}
}

// R4 runtime images may only be paired with an E fixture when Git proves
// that no ordinary runtime or build input changed between the clean trees.
// This is deliberately a narrow R4→E proof, not a generic compatibility bit.
func slice6VerifyGuestFixtureSourceDelta(ctx context.Context, runtimeRoot, runtimeRevision,
	fixtureRoot, fixtureRevision string) error {
	if runtimeRoot == fixtureRoot || runtimeRevision == fixtureRevision ||
		verifyCleanSlice6Source(ctx, runtimeRoot, runtimeRevision) != nil ||
		verifyCleanSlice6Source(ctx, fixtureRoot, fixtureRevision) != nil {
		return errors.New("separate clean R4 runtime and E fixture source unavailable")
	}
	ancestor := exec.CommandContext(ctx, "git", "merge-base", "--is-ancestor", runtimeRevision, fixtureRevision)
	ancestor.Dir = fixtureRoot
	if ancestor.Run() != nil {
		return errors.New("fixture source does not descend from fixed runtime revision")
	}
	diff := exec.CommandContext(ctx, "git", "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z",
		runtimeRevision, fixtureRevision)
	diff.Dir = fixtureRoot
	paths, err := diff.Output()
	if err != nil || len(paths) == 0 || len(paths) > 32768 || paths[len(paths)-1] != 0 {
		return errors.New("R4 to E source difference unavailable or unbounded")
	}
	for _, raw := range bytes.Split(paths[:len(paths)-1], []byte{0}) {
		path := string(raw)
		if !slice6AllowedGuestFixtureSourceDifference(path) {
			return errors.New("ordinary runtime or dependency drift between R4 and E")
		}
	}
	for _, name := range []string{"phase6_guest_binding_fixture.go", "phase6_guest_revoke_fixture.go"} {
		path := filepath.Join(fixtureRoot, "cmd", name)
		file, err := os.Open(path)
		if err != nil {
			return errors.New("E fixture source unavailable")
		}
		var prefix [40]byte
		count, readErr := file.Read(prefix[:])
		file.Close()
		if readErr != nil && readErr != io.EOF || !bytes.HasPrefix(prefix[:count], []byte("//go:build phase6slice6fixture\n")) {
			return errors.New("E fixture escaped fixture-only build tag")
		}
	}
	return nil
}

type slice6GuestBindingFixtureInput struct {
	Protocol        string `json:"protocol"`
	RunID           string `json:"run_id"`
	ProfileDigest   string `json:"profile_digest"`
	TenantID        string `json:"tenant_id"`
	ActorID         string `json:"actor_id"`
	PublicKey       []byte `json:"public_key"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type slice6GuestBindingFixtureReceipt struct {
	Protocol          string `json:"protocol"`
	RunID             string `json:"run_id"`
	ProfileDigest     string `json:"profile_digest"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	WorkspaceID       string `json:"workspace_id"`
	GuestID           string `json:"guest_id"`
	BindingGeneration int64  `json:"binding_generation"`
	SlotGeneration    int64  `json:"slot_generation"`
	EventCount        int    `json:"event_count"`
	AuditCount        int    `json:"audit_count"`
	IdempotentReplay  bool   `json:"idempotent_replay"`
}

// Preserve the underlying cause for errors.Is without exposing Docker or
// process output through the gate's user-visible failure message.
type slice6GuestFixtureFailure struct {
	stage string
	cause error
}

func (failure slice6GuestFixtureFailure) Error() string {
	return "Guest binding fixture failed stage=" + failure.stage
}

func (failure slice6GuestFixtureFailure) Unwrap() error { return failure.cause }

// Build the fixture from a separately clean immutable E source only after the
// caller has proved the exact R4→E fixture/gate/doc-only delta. This build
// tag never enters the normal Product image or production command.
func slice6BuildGuestBindingFixture(t *testing.T, ctx context.Context, sourceRoot, revision string) (slice6GuestBindingFixtureArtifact, error) {
	t.Helper()
	root, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil || !filepath.IsAbs(root) || len(revision) != 40 || !lowerHexSlice6(revision) ||
		verifyCleanSlice6Source(ctx, root, revision) != nil || runtime.Version() != "go1.26.8" {
		return slice6GuestBindingFixtureArtifact{}, errors.New("Guest fixture immutable source or Go toolchain unavailable")
	}
	directory, err := os.MkdirTemp(".", ".sr-p6-guest-binding-fixture-")
	if err != nil {
		return slice6GuestBindingFixtureArtifact{}, errors.New("Guest fixture private build directory unavailable")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove exact Guest fixture build directory: %v", err)
		}
	})
	binary, err := filepath.Abs(filepath.Join(directory, "phase6-guest-binding-fixture"))
	if err != nil {
		return slice6GuestBindingFixtureArtifact{}, errors.New("Guest fixture binary path unavailable")
	}
	build := exec.CommandContext(ctx, "go", "build", "-tags=phase6slice6fixture", "-mod=readonly",
		"-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", binary, "./")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	output, err := build.CombinedOutput()
	clear(output)
	if err != nil {
		return slice6GuestBindingFixtureArtifact{}, errors.New("build source-bound Guest fixture failed")
	}
	if err := os.Chmod(binary, 0o555); err != nil {
		return slice6GuestBindingFixtureArtifact{}, errors.New("seal Guest fixture binary failed")
	}
	artifact := slice6GuestBindingFixtureArtifact{Path: binary, SourceRevision: revision}
	artifact.Digest, err = slice6HashGuestBindingFixture(artifact.Path)
	if err != nil {
		return slice6GuestBindingFixtureArtifact{}, err
	}
	return artifact, nil
}

func slice6HashGuestBindingFixture(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("Guest fixture binary path is not absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 ||
		info.Size() < 1 || info.Size() > 64<<20 {
		return "", errors.New("Guest fixture sealed binary unavailable")
	}
	contents, err := os.ReadFile(path)
	if err != nil || int64(len(contents)) != info.Size() {
		clear(contents)
		return "", errors.New("Guest fixture binary read unavailable")
	}
	digest := sha256.Sum256(contents)
	clear(contents)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func slice6ApproveGuestBindingFixture(artifact *slice6GuestBindingFixtureArtifact, expected string) error {
	if artifact == nil {
		return errors.New("Guest fixture approval target unavailable")
	}
	artifact.ExpectedDigest = ""
	if len(expected) != 71 || !strings.HasPrefix(expected, "sha256:") ||
		!lowerHexSlice6(strings.TrimPrefix(expected, "sha256:")) || expected != artifact.Digest {
		return errors.New("Guest fixture expected digest absent or different")
	}
	actual, err := slice6HashGuestBindingFixture(artifact.Path)
	if err != nil || actual != expected {
		return errors.New("Guest fixture binary changed after source build")
	}
	artifact.ExpectedDigest = expected
	return nil
}

func slice6VerifyApprovedGuestBindingFixture(artifact slice6GuestBindingFixtureArtifact) error {
	if artifact.ExpectedDigest == "" || artifact.ExpectedDigest != artifact.Digest ||
		len(artifact.SourceRevision) != 40 || !lowerHexSlice6(artifact.SourceRevision) {
		return errors.New("Guest fixture source or external approval unavailable")
	}
	actual, err := slice6HashGuestBindingFixture(artifact.Path)
	if err != nil || actual != artifact.ExpectedDigest {
		return errors.New("Guest fixture sealed binary digest drift")
	}
	return nil
}

func slice6ProbeGuestBindingFixtureMount(ctx context.Context, artifact slice6GuestBindingFixtureArtifact,
	uid, gid uint32) (resultErr error) {
	if slice6VerifyApprovedGuestBindingFixture(artifact) != nil || uid == 0 || gid == 0 {
		return errors.New("Guest fixture probe authority unavailable")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, run.cleanup(cleanup))
	}()
	output, runErr, overflow := slice6DockerBounded(ctx, 4096, nil,
		"run", "--rm", "--pull=never", "--name", "sr-p6-guest-fixture-probe-"+run.id,
		"--label", run.label(), "--network=none", "--restart=no",
		"--user", fmt.Sprintf("%d:%d", uid, gid), "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--read-only", "--memory=64m",
		"--cpus=0.2", "--pids-limit=16",
		"--mount", "type=bind,src="+artifact.Path+",dst=/phase6-guest-binding-fixture,readonly",
		"--entrypoint=/phase6-guest-binding-fixture", slice6PinnedAlpineImage,
		"phase6-guest-binding-fixture", "--help")
	defer clear(output)
	if runErr != nil || overflow || !bytes.Contains(output, []byte("phase6-guest-binding-fixture")) {
		return errors.New("Guest fixture non-root networkless executable probe failed")
	}
	return slice6VerifyApprovedGuestBindingFixture(artifact)
}

// The initial binding fixture borrows only the exact Product runtime SQL
// source endpoint, after migration and before Product creation. A real Guest
// public key is supplied by the same-run Vault material installation.
func slice6RunGuestBindingFixture(parent context.Context, run slice6DockerRun,
	profile phase6security.Profile, postgresID string,
	socketVolumes, anchorFiles map[string]string, artifact slice6GuestBindingFixtureArtifact,
	guestPublic slice6GuestPublicMaterial) (receipt slice6GuestBindingFixtureReceipt, resultErr error) {
	stage := "admission"
	defer func() {
		if resultErr != nil {
			resultErr = slice6GuestFixtureFailure{stage: stage, cause: resultErr}
		}
	}()
	if parent == nil {
		return receipt, errors.New("Guest fixture parent context unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 150*time.Second)
	defer cancel()
	if slice6VerifyApprovedGuestBindingFixture(artifact) != nil ||
		len(run.id) != 32 || !lowerHexSlice6(run.id) || !guestPublic.valid() ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) ||
		len(socketVolumes) != 74 || phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil {
		return receipt, errors.New("Guest fixture same-run source authority unavailable")
	}
	stage = "profile-plan"
	plan, err := slice6BuildProductRuntimeLaunchPlan(profile)
	if err != nil {
		return receipt, err
	}
	if plan.ServiceNetwork.Name != "service-product-postgres" ||
		artifact.SourceRevision == "" || plan.Principal.UID == 0 || plan.Principal.GID == 0 {
		return receipt, errors.New("Guest fixture Product source endpoint drift")
	}
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-runtime")
	signer, signerTarget, signerAgent, subject, _, signerErr := profile.PostgresClientSignerForOwner("product-runtime")
	if materialErr != nil || signerErr != nil || material.OwnerDeployment != "product-runtime" ||
		signerTarget.AgentDeployment != "product-postgres-tls-agent" ||
		signerAgent.Name != signerTarget.AgentDeployment || subject.Name != "product-runtime" ||
		material.SocketStorageID == signer.SocketStorageID ||
		socketVolumes[material.SocketStorageID] == "" || socketVolumes[signer.SocketStorageID] == "" {
		return receipt, errors.New("Guest fixture exact Product material or PostgreSQL signer unavailable")
	}
	stage = "private-volumes"
	for _, volume := range []string{"sr-p6-config-product-runtime-" + run.id,
		socketVolumes[material.SocketStorageID], socketVolumes[signer.SocketStorageID]} {
		if err := slice6VerifyGuestFixtureVolume(ctx, run, volume); err != nil {
			return receipt, err
		}
	}
	stage = "postgres-bridge"
	network, err := run.docker(ctx, "network", "inspect", plan.ServiceNetwork.Name)
	if err != nil {
		return receipt, errors.New("Guest fixture PostgreSQL bridge unavailable")
	}
	var networkMeta []struct {
		ID     string
		Labels map[string]string
	}
	if json.Unmarshal(network, &networkMeta) != nil || len(networkMeta) != 1 ||
		networkMeta[0].Labels[slice6RunLabel] != run.id || len(networkMeta[0].ID) != 64 ||
		!lowerHexSlice6(networkMeta[0].ID) {
		return receipt, errors.New("Guest fixture PostgreSQL bridge run identity mismatch")
	}
	serviceNetworkID := networkMeta[0].ID
	serviceWithoutProduct := plan.ServiceNetwork
	serviceWithoutProduct.Principals = nil
	postgresIP, addressErr := phase6security.Slice6DesiredServiceEndpointAddress(plan.ServiceNetwork.Name, "postgres")
	if addressErr != nil || slice6VerifyMigrationPostgresBridge(network, serviceWithoutProduct,
		serviceNetworkID, postgresID, postgresIP) != nil {
		return receipt, errors.New("Guest fixture source endpoint is not free before Product")
	}
	stage = "container-inputs"
	root, err := filepath.Abs("..")
	if err != nil {
		return receipt, errors.New("Guest fixture seccomp source unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompDocument, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompDocument)
	clear(seccompDocument)
	if err != nil || plan.Principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		return receipt, errors.New("Guest fixture Product seccomp drift")
	}
	anchors, err := slice6AnchorMountArguments(profile, "product-runtime", anchorFiles)
	if err != nil {
		return receipt, errors.New("Guest fixture exact Product trust anchors unavailable")
	}
	private, ok := phase6security.Slice6PrivateConfigMount("product-runtime")
	if !ok || private.Target != phase6security.Slice6PrivateConfigDirectory {
		return receipt, errors.New("Guest fixture Product private configuration unavailable")
	}
	input := slice6GuestBindingFixtureInput{
		Protocol: slice6GuestBindingFixtureProtocol, RunID: run.id,
		ProfileDigest: profile.ProfileDigest, TenantID: "tenant-phase6-" + run.id,
		ActorID: "actor-phase6-" + run.id, PublicKey: bytes.Clone(guestPublic.Key),
		PublicKeySHA256: guestPublic.Digest,
	}
	defer clear(input.PublicKey)
	payload, err := json.Marshal(input)
	if err != nil || len(payload) > 4096 {
		return receipt, errors.New("Guest fixture bounded input unavailable")
	}
	defer clear(payload)
	stage = "container-create"
	name := "sr-p6-guest-binding-fixture-" + run.id
	args := []string{"create", "-i", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network", serviceNetworkID, "--ip", plan.SourceAddress,
		"--restart=no", "--user", fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(plan.Principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(plan.Principal.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(plan.Principal.Resources.PIDs, 10),
		"--mount", "type=bind,src=" + artifact.Path + ",dst=/phase6-guest-binding-fixture,readonly",
		"--mount", "type=volume,src=sr-p6-config-product-runtime-" + run.id + ",dst=" + private.Target + ",readonly",
		"--mount", "type=volume,src=" + socketVolumes[material.SocketStorageID] + ",dst=" + material.SocketDirectory + ",readonly",
		"--mount", "type=volume,src=" + socketVolumes[signer.SocketStorageID] + ",dst=" + signer.SocketDirectory + ",readonly"}
	args = append(args, anchors...)
	args = append(args, "--entrypoint=/phase6-guest-binding-fixture", slice6PinnedAlpineImage,
		"--config", private.Target+"/"+phase6security.Slice6StartupConfigFile,
		"phase6-guest-binding-fixture")
	created, err := run.docker(ctx, args...)
	id := strings.TrimSpace(string(created))
	clear(created)
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return receipt, errors.New("Guest fixture finite container create unconfirmed")
	}
	removed := false
	defer func() {
		if removed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := run.docker(cleanup, "rm", "-f", "-v", id); err != nil {
			resultErr = errors.Join(resultErr, errors.New("Guest fixture exact container removal unconfirmed"))
		}
	}()
	// No Product public TLS signer volume is mounted: the fixture only resolves
	// the runtime DSN and performs direct v3 PostgreSQL client authentication.
	stage = "container-inspect"
	if err := slice6VerifyGuestFixtureContainer(ctx, run, id, serviceNetworkID, plan.ServiceNetwork.Name, plan.SourceAddress,
		profile, plan.Principal, artifact, socketVolumes, anchorFiles, seccomp,
		material.SocketDirectory, signer.SocketDirectory, private.Target); err != nil {
		return receipt, err
	}
	stage = "runtime-network"
	started, startErr, overflow := slice6RunGuestFixtureAfterAdmission(ctx, run, id,
		serviceNetworkID, plan.ServiceNetwork, plan.SourceAddress, postgresID, postgresIP, payload, &stage)
	defer clear(started)
	if startErr != nil || overflow || len(started) < 1 || len(started) > 2049 || started[len(started)-1] != '\n' ||
		json.Unmarshal(started[:len(started)-1], &receipt) != nil {
		return slice6GuestBindingFixtureReceipt{}, errors.New("Guest fixture finite task failed or receipt unavailable")
	}
	stage = "receipt"
	canonical, canonicalErr := json.Marshal(receipt)
	if canonicalErr != nil || !bytes.Equal(canonical, started[:len(started)-1]) ||
		receipt.Protocol != slice6GuestBindingFixtureProtocol || receipt.RunID != run.id ||
		receipt.ProfileDigest != profile.ProfileDigest || receipt.PublicKeySHA256 != input.PublicKeySHA256 ||
		receipt.WorkspaceID == "" || receipt.GuestID == "" || receipt.BindingGeneration != 1 ||
		receipt.SlotGeneration != 1 || receipt.EventCount != 1 || receipt.AuditCount != 1 ||
		!receipt.IdempotentReplay {
		return slice6GuestBindingFixtureReceipt{}, errors.New("Guest fixture receipt did not bind the exact run and public key")
	}
	stage = "exit-cleanup"
	status, statusErr := run.docker(ctx, "inspect", "--format", "{{.State.ExitCode}} {{.State.Running}}", id)
	if statusErr != nil || string(bytes.TrimSpace(status)) != "0 false" {
		return slice6GuestBindingFixtureReceipt{}, errors.New("Guest fixture process exit was not clean")
	}
	if _, err := run.docker(ctx, "rm", "-v", id); err != nil {
		return slice6GuestBindingFixtureReceipt{}, errors.New("Guest fixture exact container exit cleanup failed")
	}
	removed = true
	postRemoval, err := run.docker(ctx, "network", "inspect", plan.ServiceNetwork.Name)
	if err != nil || slice6VerifyMigrationPostgresBridge(postRemoval, serviceWithoutProduct,
		serviceNetworkID, postgresID, postgresIP) != nil {
		return slice6GuestBindingFixtureReceipt{}, errors.New("Guest fixture fixed SQL source endpoint was not released")
	}
	stage = "complete"
	return receipt, nil
}

// Keep Docker's attached stdin open while observing the actual running
// endpoint. The fixture RunE blocks in ReadAll until EOF; its pre-run only
// verifies local private files. No SQL pool or business write is possible
// before the single canonical payload is sent after this admission check.
func slice6RunGuestFixtureAfterAdmission(ctx context.Context, run slice6DockerRun, id, networkID string,
	service phase6security.Network, sourceIP, postgresID, postgresIP string,
	payload []byte, stage *string) ([]byte, error, bool) {
	if ctx == nil || stage == nil || len(payload) < 1 || len(payload) > 4096 {
		return nil, errors.New("Guest fixture stdin barrier input unavailable"), false
	}
	startCtx, cancelStart := context.WithCancel(ctx)
	command := exec.CommandContext(startCtx, "docker", "start", "-ai", id)
	stdin, err := command.StdinPipe()
	if err != nil {
		cancelStart()
		return nil, errors.New("Guest fixture attached stdin unavailable"), false
	}
	output := &slice6BoundedOutput{limit: 4096}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		stdin.Close()
		cancelStart()
		return nil, errors.New("Guest fixture attached process start unavailable"), false
	}
	completed := make(chan error, 1)
	go func() { completed <- command.Wait() }()
	finished := false
	defer func() {
		stdin.Close()
		cancelStart()
		if !finished {
			select {
			case <-completed:
			case <-time.After(5 * time.Second):
			}
		}
	}()
	if err := slice6DeliverGuestFixtureInput(ctx, func() error {
		return slice6WaitGuestFixtureRunning(ctx, run, id, networkID, service,
			sourceIP, postgresID, postgresIP, completed, &finished)
	}, stdin, payload); err != nil {
		return nil, err, false
	}
	*stage = "finite-process"
	select {
	case err = <-completed:
		finished = true
	case <-ctx.Done():
		return nil, errors.New("Guest fixture finite process deadline ended"), false
	}
	output.mu.Lock()
	document := bytes.Clone(output.buffer.Bytes())
	clear(output.buffer.Bytes())
	overflow := output.overflow
	output.mu.Unlock()
	if overflow {
		clear(document)
		return nil, errors.New("Guest fixture finite process output exceeded bound"), true
	}
	if err != nil {
		*stage = "finite-process/" + slice6GuestFixtureProcessCategory(document)
	}
	return document, err, false
}

// This can only classify an exact fixed CLI error line from the separately
// approved fixture binary. All other output, including arbitrary Docker or
// dependency diagnostics, is represented as unclassified and never logged.
func slice6GuestFixtureProcessCategory(output []byte) string {
	if len(output) < 1 || len(output) > 256 {
		return "unclassified"
	}
	switch string(output) {
	case "Guest binding fixture requires the exact Product private startup file\n",
		"Guest binding fixture Product Profile unavailable\n",
		"Guest binding fixture startup file unavailable\n",
		"Guest binding fixture startup file owner mismatch\n",
		"Guest binding fixture Product config mismatch\n":
		return "local-config"
	case "Guest binding fixture input unavailable\n", "Guest binding fixture input rejected\n":
		return "input"
	case "Guest binding fixture Product authority unavailable\n":
		return "product-authority"
	case "Guest binding fixture material registry unavailable\n":
		return "material-registry"
	case "Guest binding fixture Product PostgreSQL unavailable\n":
		return "postgres-open"
	case "Guest binding fixture Product SQL authority mismatch\n":
		return "postgres-authority"
	case "Guest binding fixture Product Store unavailable\n",
		"Guest binding fixture Product application unavailable\n":
		return "application"
	case "Guest binding fixture Workspace seed failed\n",
		"Guest binding fixture exact ready-slot seed failed\n",
		"Guest binding fixture Workspace readback failed\n":
		return "workspace-seed"
	case "Guest binding fixture Guest service unavailable\n",
		"Guest binding fixture Product provision failed\n",
		"Guest binding fixture idempotency replay mismatch\n":
		return "guest-provision"
	case "Guest binding fixture durable event or audit readback failed\n":
		return "durable-readback"
	case "Guest binding fixture receipt unavailable\n",
		"Guest binding fixture receipt delivery failed\n":
		return "receipt"
	default:
		return "unclassified"
	}
}

func slice6DeliverGuestFixtureInput(ctx context.Context, admit func() error, stdin io.WriteCloser, payload []byte) error {
	if ctx == nil || admit == nil || stdin == nil || len(payload) < 1 || len(payload) > 4096 {
		return errors.New("Guest fixture stdin barrier input unavailable")
	}
	if err := admit(); err != nil {
		return slice6GuestFixtureFailure{stage: "effective-network", cause: err}
	}
	if ctx.Err() != nil {
		return errors.New("Guest fixture stdin barrier deadline ended")
	}
	written, err := stdin.Write(payload)
	if err != nil || written != len(payload) {
		return errors.New("Guest fixture canonical payload delivery unconfirmed")
	}
	if err := stdin.Close(); err != nil {
		return errors.New("Guest fixture stdin EOF unconfirmed")
	}
	return nil
}

func slice6WaitGuestFixtureRunning(ctx context.Context, run slice6DockerRun, id, networkID string,
	service phase6security.Network, sourceIP, postgresID, postgresIP string,
	completed <-chan error, finished *bool) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		containerDocument, err := run.docker(ctx, "inspect", id)
		var observed []struct {
			ID, Name string
			Config   struct{ Labels map[string]string }
			State    struct {
				Status  string
				Running bool
				Pid     int
			}
			RestartCount    int
			HostConfig      struct{ NetworkMode string }
			NetworkSettings struct {
				Networks map[string]slice6GuestFixtureRunningEndpoint
			}
		}
		if err != nil || json.Unmarshal(containerDocument, &observed) != nil || len(observed) != 1 ||
			observed[0].ID != id || observed[0].Name != "/sr-p6-guest-binding-fixture-"+run.id ||
			observed[0].Config.Labels[slice6RunLabel] != run.id || observed[0].RestartCount != 0 ||
			observed[0].HostConfig.NetworkMode != networkID {
			return errors.New("Guest fixture running container identity drift")
		}
		if observed[0].State.Status == "created" && !observed[0].State.Running {
			select {
			case <-completed:
				*finished = true
				return errors.New("Guest fixture exited before effective endpoint admission")
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
			}
			continue
		}
		if observed[0].State.Status != "running" || !observed[0].State.Running || observed[0].State.Pid <= 0 ||
			slice6ValidateGuestFixtureRunningNetwork(observed[0].NetworkSettings.Networks,
				networkID, service.Name, sourceIP) != nil {
			return errors.New("Guest fixture effective PostgreSQL source endpoint drift")
		}
		bridge, err := run.docker(ctx, "network", "inspect", networkID)
		if err != nil {
			return errors.New("Guest fixture effective PostgreSQL bridge unavailable")
		}
		membership, err := phase6security.ObserveDockerNetworkWithExternal(bridge, service,
			map[string]string{"product-runtime": id}, map[string]string{"postgres": postgresID})
		if err != nil || membership.NetworkID != networkID || len(membership.Endpoints) != 2 {
			return errors.New("Guest fixture effective PostgreSQL bridge membership drift")
		}
		for _, endpoint := range membership.Endpoints {
			if endpoint.ContainerID == id && endpoint.IPv4Address != sourceIP ||
				endpoint.ContainerID == postgresID && endpoint.IPv4Address != postgresIP {
				return errors.New("Guest fixture effective PostgreSQL bridge address drift")
			}
		}
		if ctx.Err() != nil {
			return errors.New("Guest fixture effective PostgreSQL endpoint deadline ended")
		}
		return nil
	}
	return errors.New("Guest fixture effective PostgreSQL endpoint did not become ready")
}

func slice6VerifyGuestFixtureVolume(ctx context.Context, run slice6DockerRun, name string) error {
	if name == "" || strings.ContainsAny(name, "/\\\x00\n\r") {
		return errors.New("Guest fixture volume name invalid")
	}
	document, err := run.docker(ctx, "volume", "inspect", name)
	var volumes []struct {
		Name   string
		Labels map[string]string
	}
	if err != nil || len(document) < 1 || len(document) > 8192 ||
		json.Unmarshal(document, &volumes) != nil || len(volumes) != 1 ||
		volumes[0].Name != name || volumes[0].Labels[slice6RunLabel] != run.id {
		return errors.New("Guest fixture same-run private volume missing before container create")
	}
	return nil
}

func slice6VerifyGuestFixtureContainer(ctx context.Context, run slice6DockerRun, id, networkID, networkName, sourceIP string,
	profile phase6security.Profile, principal phase6security.Principal, artifact slice6GuestBindingFixtureArtifact,
	socketVolumes, anchorFiles map[string]string, seccomp string,
	materialDirectory, signerDirectory, configDirectory string) error {
	raw, err := run.docker(ctx, "inspect", id)
	var observed []struct {
		Name   string
		Config struct {
			User       string
			Image      string
			Entrypoint []string
			Cmd        []string
			Labels     map[string]string
		}
		HostConfig struct {
			ReadonlyRootfs bool
			Privileged     bool
			CapDrop        []string
			SecurityOpt    []string
			Memory         int64
			NanoCpus       int64
			PidsLimit      int64
			NetworkMode    string
			Binds          []string
			RestartPolicy  struct{ Name string }
			LogConfig      struct{ Type string }
			PortBindings   map[string]any
		}
		NetworkSettings struct {
			Networks map[string]slice6MigrationNetworkEndpoint
		}
		Mounts []struct {
			Type, Name, Source, Destination string
			RW                              bool
		}
		State struct {
			Running bool
			Status  string
			Pid     int
		}
		RestartCount int
	}
	seccompSource, seccompErr := os.ReadFile(seccomp)
	var canonicalSeccomp bytes.Buffer
	if seccompErr == nil {
		seccompErr = json.Compact(&canonicalSeccomp, seccompSource)
	}
	clear(seccompSource)
	if err != nil || seccompErr != nil || json.Unmarshal(raw, &observed) != nil || len(observed) != 1 ||
		observed[0].Name != "/sr-p6-guest-binding-fixture-"+run.id ||
		observed[0].Config.Labels[slice6RunLabel] != run.id ||
		observed[0].Config.User != fmt.Sprintf("%d:%d", principal.UID, principal.GID) ||
		observed[0].Config.Image != slice6PinnedAlpineImage ||
		!slices.Equal(observed[0].Config.Entrypoint, []string{"/phase6-guest-binding-fixture"}) ||
		!slices.Equal(observed[0].Config.Cmd, []string{"--config", configDirectory + "/" + phase6security.Slice6StartupConfigFile,
			"phase6-guest-binding-fixture"}) || observed[0].State.Running ||
		observed[0].State.Status != "created" || observed[0].State.Pid != 0 || observed[0].RestartCount != 0 ||
		!observed[0].HostConfig.ReadonlyRootfs || observed[0].HostConfig.Privileged ||
		!slices.Equal(observed[0].HostConfig.CapDrop, []string{"ALL"}) ||
		observed[0].HostConfig.Memory != principal.Resources.MemoryBytes ||
		observed[0].HostConfig.NanoCpus != principal.Resources.CPUMillis*1000000 ||
		observed[0].HostConfig.PidsLimit != principal.Resources.PIDs ||
		observed[0].HostConfig.NetworkMode != networkID || len(observed[0].HostConfig.Binds) != 0 ||
		observed[0].HostConfig.RestartPolicy.Name != "no" ||
		observed[0].HostConfig.LogConfig.Type != "none" ||
		len(observed[0].HostConfig.PortBindings) != 0 ||
		len(observed[0].NetworkSettings.Networks) != 1 || len(observed[0].Mounts) == 0 {
		return errors.New("Guest fixture finite container identity or resource bounds drift")
	}
	for _, option := range []string{"no-new-privileges:true", "seccomp=" + canonicalSeccomp.String()} {
		if !slices.Contains(observed[0].HostConfig.SecurityOpt, option) {
			return errors.New("Guest fixture no-new-privileges security option missing")
		}
	}
	if err := slice6ValidateGuestFixtureCreatedNetwork(observed[0].NetworkSettings.Networks,
		networkID, networkName, sourceIP); err != nil {
		return err
	}
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-runtime")
	signer, _, _, _, _, signerErr := profile.PostgresClientSignerForOwner("product-runtime")
	if materialErr != nil || signerErr != nil || material.SocketDirectory != materialDirectory ||
		signer.SocketDirectory != signerDirectory {
		return errors.New("Guest fixture socket mount authority unavailable")
	}
	required := map[string]string{
		"/phase6-guest-binding-fixture": artifact.Path,
		configDirectory:                 "sr-p6-config-product-runtime-" + run.id,
		materialDirectory:               socketVolumes[material.SocketStorageID],
		signerDirectory:                 socketVolumes[signer.SocketStorageID],
	}
	trustCount := 0
	for _, anchor := range profile.TrustAnchors {
		for _, mount := range principal.Mounts {
			if mount.Kind == "trust_anchor" && mount.StorageID == anchor.StorageID {
				trustCount++
				required[anchor.TargetPath] = anchorFiles[anchor.StorageID]
			}
		}
	}
	if trustCount == 0 || len(required) != 4+trustCount || len(observed[0].Mounts) != len(required) {
		return errors.New("Guest fixture mount count or trust-anchor inventory drift")
	}
	for _, mount := range observed[0].Mounts {
		if mount.RW {
			return errors.New("Guest fixture received a writable mount")
		}
		want, present := required[mount.Destination]
		if !present || want == "" {
			return errors.New("Guest fixture unreviewed mount present")
		}
		if mount.Destination == configDirectory || mount.Destination == materialDirectory ||
			mount.Destination == signerDirectory {
			if mount.Type != "volume" || mount.Name != want {
				return errors.New("Guest fixture private volume identity drift")
			}
		} else if mount.Type != "bind" || mount.Source != want {
			return errors.New("Guest fixture bind mount identity drift")
		}
		delete(required, mount.Destination)
	}
	if len(required) != 0 {
		return errors.New("Guest fixture private mount set incomplete")
	}
	return slice6VerifyApprovedGuestBindingFixture(artifact)
}

// Docker may leave NetworkID empty until start. The only pre-start claim is
// the unique requested network and IPAM address; effective identity requires
// the later PostgreSQL-authenticated finite task and bridge release readback.
func slice6ValidateGuestFixtureCreatedNetwork(networks map[string]slice6MigrationNetworkEndpoint,
	networkID, networkName, sourceIP string) error {
	if len(networks) != 1 || len(networkID) != 64 || !lowerHexSlice6(networkID) ||
		networkName == "" || sourceIP == "" {
		return errors.New("Guest fixture requested fixed PostgreSQL source IP drift")
	}
	byID, hasID := networks[networkID]
	byName, hasName := networks[networkName]
	if hasID == hasName {
		return errors.New("Guest fixture requested fixed PostgreSQL source IP drift")
	}
	endpoint := byID
	if hasName {
		endpoint = byName
	}
	if endpoint.IPAMConfig.IPv4Address != sourceIP ||
		(endpoint.NetworkID != "" && endpoint.NetworkID != networkID) {
		return errors.New("Guest fixture requested fixed PostgreSQL source IP drift")
	}
	return nil
}

type slice6GuestFixtureRunningEndpoint struct {
	NetworkID  string
	IPAddress  string
	IPAMConfig struct{ IPv4Address string }
}

func slice6ValidateGuestFixtureRunningNetwork(networks map[string]slice6GuestFixtureRunningEndpoint,
	networkID, networkName, sourceIP string) error {
	if len(networks) != 1 || len(networkID) != 64 || !lowerHexSlice6(networkID) ||
		networkName == "" || sourceIP == "" {
		return errors.New("Guest fixture effective PostgreSQL source endpoint drift")
	}
	byID, hasID := networks[networkID]
	byName, hasName := networks[networkName]
	if hasID == hasName {
		return errors.New("Guest fixture effective PostgreSQL source endpoint drift")
	}
	endpoint := byID
	if hasName {
		endpoint = byName
	}
	if endpoint.NetworkID != networkID || endpoint.IPAddress != sourceIP ||
		endpoint.IPAMConfig.IPv4Address != sourceIP {
		return errors.New("Guest fixture effective PostgreSQL source endpoint drift")
	}
	return nil
}

func TestSlice6GuestFixtureInputAndApprovalClosure(t *testing.T) {
	artifact := slice6GuestBindingFixtureArtifact{Digest: "sha256:" + strings.Repeat("a", 64), SourceRevision: strings.Repeat("b", 40)}
	if slice6ApproveGuestBindingFixture(&artifact, artifact.Digest) == nil {
		t.Fatal("missing sealed executable was approved")
	}
	if artifact.ExpectedDigest != "" {
		t.Fatal("failed approval retained authority")
	}
	if slice6ApproveGuestBindingFixture(&artifact, "sha256:bad") == nil {
		t.Fatal("noncanonical expected digest was approved")
	}
}

func TestSlice6GuestFixtureFailurePreservesCauseWithoutDisclosure(t *testing.T) {
	cause := errors.New("private PostgreSQL and Docker diagnostic")
	failure := slice6GuestFixtureFailure{stage: "finite-process", cause: cause}
	if !errors.Is(failure, cause) || failure.Error() != "Guest binding fixture failed stage=finite-process" ||
		strings.Contains(failure.Error(), "private") {
		t.Fatal("Guest fixture failure lost its cause or disclosed process output")
	}
}

func TestSlice6GuestFixtureCreatedNetworkChecksRequestedNotEffectiveState(t *testing.T) {
	id, name, ip := strings.Repeat("a", 64), "service-product-postgres", "172.31.70.3"
	endpoint := slice6MigrationNetworkEndpoint{}
	endpoint.IPAMConfig.IPv4Address = ip
	for _, key := range []string{id, name} {
		if err := slice6ValidateGuestFixtureCreatedNetwork(
			map[string]slice6MigrationNetworkEndpoint{key: endpoint}, id, name, ip); err != nil {
			t.Fatalf("Docker pre-start requested endpoint under %q was rejected: %v", key, err)
		}
	}
	wrongID := endpoint
	wrongID.NetworkID = strings.Repeat("b", 64)
	wrongIP := endpoint
	wrongIP.IPAMConfig.IPv4Address = "172.31.70.4"
	for label, networks := range map[string]map[string]slice6MigrationNetworkEndpoint{
		"missing":  {},
		"unknown":  {"other": endpoint},
		"two":      {id: endpoint, name: endpoint},
		"wrong-id": {name: wrongID},
		"wrong-ip": {name: wrongIP},
	} {
		if err := slice6ValidateGuestFixtureCreatedNetwork(networks, id, name, ip); err == nil {
			t.Fatalf("Guest fixture admitted %s pre-start network drift", label)
		}
	}
}

func TestSlice6GuestFixtureRunningNetworkRequiresEffectiveAddress(t *testing.T) {
	id, name, ip := strings.Repeat("a", 64), "service-product-postgres", "172.31.70.3"
	endpoint := slice6GuestFixtureRunningEndpoint{NetworkID: id, IPAddress: ip}
	endpoint.IPAMConfig.IPv4Address = ip
	for _, key := range []string{id, name} {
		if err := slice6ValidateGuestFixtureRunningNetwork(
			map[string]slice6GuestFixtureRunningEndpoint{key: endpoint}, id, name, ip); err != nil {
			t.Fatalf("Guest fixture rejected effective endpoint under %q: %v", key, err)
		}
	}
	missingID := endpoint
	missingID.NetworkID = ""
	wrongID := endpoint
	wrongID.NetworkID = strings.Repeat("b", 64)
	wrongIP := endpoint
	wrongIP.IPAddress = "172.31.70.4"
	wrongRequest := endpoint
	wrongRequest.IPAMConfig.IPv4Address = "172.31.70.4"
	for label, networks := range map[string]map[string]slice6GuestFixtureRunningEndpoint{
		"missing":       {},
		"unknown":       {"other": endpoint},
		"two":           {id: endpoint, name: endpoint},
		"missing-id":    {name: missingID},
		"wrong-id":      {name: wrongID},
		"wrong-ip":      {name: wrongIP},
		"wrong-request": {name: wrongRequest},
	} {
		if err := slice6ValidateGuestFixtureRunningNetwork(networks, id, name, ip); err == nil {
			t.Fatalf("Guest fixture admitted %s running network drift", label)
		}
	}
}

type slice6CountingInput struct {
	writes int
	closed bool
}

func (input *slice6CountingInput) Write(payload []byte) (int, error) {
	input.writes++
	return len(payload), nil
}

func (input *slice6CountingInput) Close() error {
	input.closed = true
	return nil
}

func TestSlice6GuestFixtureBarrierDoesNotReleasePayloadOnAdmissionFailure(t *testing.T) {
	first := errors.New("private endpoint detail")
	input := &slice6CountingInput{}
	err := slice6DeliverGuestFixtureInput(t.Context(), func() error { return first }, input, []byte("payload"))
	if !errors.Is(err, first) || input.writes != 0 || input.closed ||
		strings.Contains(err.Error(), "private endpoint detail") {
		t.Fatal("failed admission released payload, lost cause or exposed private detail")
	}
	if err := slice6DeliverGuestFixtureInput(t.Context(), func() error { return nil }, input, []byte("payload")); err != nil || input.writes != 1 || !input.closed {
		t.Fatal("admitted fixture did not receive exactly one payload and EOF")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := slice6DeliverGuestFixtureInput(canceled, func() error { return nil }, input, []byte("payload")); err == nil || input.writes != 1 {
		t.Fatal("canceled fixture barrier released another payload")
	}
}

func TestSlice6GuestFixtureProcessCategoryIsClosed(t *testing.T) {
	for input, want := range map[string]string{
		"Guest binding fixture Product PostgreSQL unavailable\n":        "postgres-open",
		"Guest binding fixture Product provision failed\n":              "guest-provision",
		"Guest binding fixture Product PostgreSQL unavailable\nprivate": "unclassified",
		"private PostgreSQL endpoint\n":                                 "unclassified",
		"":                                                              "unclassified",
	} {
		if got := slice6GuestFixtureProcessCategory([]byte(input)); got != want {
			t.Fatalf("finite fixture category=%q; want %q", got, want)
		}
	}
}

func TestSlice6GuestFixtureVolumeNoIssuerDocker(t *testing.T) {
	if os.Getenv(slice6GuestFixtureVolumeDockerEnv) != "1" {
		t.Skip("set " + slice6GuestFixtureVolumeDockerEnv + "=1 for a no-issuer Docker volume ownership probe")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("Guest fixture no-issuer volume exact cleanup: %v", err)
		}
	})
	name := "sr-p6-guest-fixture-volume-" + run.id
	if slice6VerifyGuestFixtureVolume(ctx, run, name) == nil {
		t.Fatal("missing fixture volume was admitted; Docker would auto-create it")
	}
	created, err := run.docker(ctx, "volume", "create", "--label", run.label(), name)
	if err != nil || string(bytes.TrimSpace(created)) != name {
		t.Fatal("no-issuer fixture volume create failed")
	}
	if err := slice6VerifyGuestFixtureVolume(ctx, run, name); err != nil {
		t.Fatal(err)
	}
	wrongRun := slice6DockerRun{id: strings.Repeat("a", 32)}
	if wrongRun.id == run.id {
		wrongRun.id = strings.Repeat("b", 32)
	}
	if slice6VerifyGuestFixtureVolume(ctx, wrongRun, name) == nil {
		t.Fatal("other-run fixture volume label was admitted")
	}
	if slice6VerifyGuestFixtureVolume(ctx, run, name+"-other") == nil ||
		slice6VerifyGuestFixtureVolume(ctx, run, "../unsafe") == nil {
		t.Fatal("wrong-name fixture volume was admitted")
	}
}

func TestSlice6GuestRevokeNamespaceNoIssuerDocker(t *testing.T) {
	if os.Getenv(slice6GuestRevokeNamespaceDockerEnv) != "1" {
		t.Skip("set " + slice6GuestRevokeNamespaceDockerEnv + "=1 for a no-issuer Docker namespace probe")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("Guest revoke namespace no-issuer exact cleanup: %v", err)
		}
	})
	identity := phase6security.Slice6DesiredUIDGID()["product-runtime"]
	owner := fmt.Sprintf("%d:%d", identity[0], identity[1])
	targetCreated, err := run.docker(ctx, "create", "--pull=never",
		"--name", "sr-p6-revoke-netns-target-"+run.id, "--label", run.label(),
		"--network=none", "--restart=no", "--user", owner, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--read-only", "--memory=64m",
		"--cpus=0.2", "--pids-limit=16", slice6PinnedAlpineImage, "/bin/sleep", "30")
	targetID := strings.TrimSpace(string(targetCreated))
	if err != nil || len(targetID) != 64 || !lowerHexSlice6(targetID) {
		t.Fatal("no-issuer namespace target create failed")
	}
	if _, err := run.docker(ctx, "start", targetID); err != nil {
		t.Fatal("no-issuer namespace target start failed")
	}
	if err := slice6AdmitGuestRevokeMemory(ctx, run, 64<<20); err != nil {
		t.Fatalf("no-issuer aggregate running memory admission failed: %v", err)
	}
	if slice6AdmitGuestRevokeMemory(ctx, run, 0) == nil {
		t.Fatal("unbounded finite-helper memory passed aggregate admission")
	}
	before, err := run.docker(ctx, "exec", targetID, "/bin/busybox", "readlink", "/proc/self/ns/net")
	if err != nil || !bytes.HasPrefix(bytes.TrimSpace(before), []byte("net:[")) {
		t.Fatal("no-issuer target namespace identity unavailable")
	}
	helperCreated, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-revoke-netns-helper-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=container:"+targetID,
		"--restart=no", "--user", owner, "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--read-only", "--memory=64m", "--cpus=0.2", "--pids-limit=16",
		slice6PinnedAlpineImage, "/bin/busybox", "readlink", "/proc/self/ns/net")
	helperID := strings.TrimSpace(string(helperCreated))
	if err != nil || len(helperID) != 64 || !lowerHexSlice6(helperID) {
		t.Fatal("no-issuer shared-namespace finite helper create failed")
	}
	inspect, err := run.docker(ctx, "inspect", helperID)
	var observed []struct {
		HostConfig struct {
			NetworkMode, PidMode, IpcMode string
			Privileged                    bool
			ReadonlyRootfs                bool
			CapDrop                       []string
			PortBindings                  map[string]any
		}
		NetworkSettings struct{ Networks map[string]any }
	}
	if err != nil || json.Unmarshal(inspect, &observed) != nil || len(observed) != 1 ||
		observed[0].HostConfig.NetworkMode != "container:"+targetID ||
		observed[0].HostConfig.PidMode != "" || observed[0].HostConfig.IpcMode != "private" ||
		observed[0].HostConfig.Privileged || !observed[0].HostConfig.ReadonlyRootfs ||
		!slices.Equal(observed[0].HostConfig.CapDrop, []string{"ALL"}) ||
		len(observed[0].HostConfig.PortBindings) != 0 ||
		len(observed[0].NetworkSettings.Networks) != 0 {
		t.Fatal("no-issuer shared-namespace helper gained another namespace, endpoint or port")
	}
	help, err := run.docker(ctx, "start", "-a", helperID)
	if err != nil || !bytes.Equal(bytes.TrimSpace(help), bytes.TrimSpace(before)) {
		t.Fatal("finite helper did not share only the target's observed network namespace")
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.ExitCode}} {{.State.Running}}", helperID)
	if err != nil || string(bytes.TrimSpace(state)) != "0 false" {
		t.Fatal("finite helper did not exit cleanly")
	}
	if _, err := run.docker(ctx, "rm", "-v", helperID); err != nil {
		t.Fatal("remove exact finite helper without disconnecting target")
	}
	after, err := run.docker(ctx, "exec", targetID, "/bin/busybox", "readlink", "/proc/self/ns/net")
	if err != nil || !bytes.Equal(bytes.TrimSpace(after), bytes.TrimSpace(before)) {
		t.Fatal("target namespace changed after finite helper cleanup")
	}
	if _, err := run.docker(ctx, "rm", "-f", "-v", targetID); err != nil {
		t.Fatal("remove exact no-issuer target")
	}
	for _, class := range []string{"container", "network", "volume"} {
		if ids, err := run.labeledIDs(ctx, class); err != nil || len(ids) != 0 {
			t.Fatal("no-issuer namespace probe did not return exact run resources to zero")
		}
	}
}
