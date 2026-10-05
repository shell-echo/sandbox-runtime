//go:build integration

package dockercontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

// One operator-approved, one-effect component batch. The opt-in harness is
// deliberately separate from production Control: it fixes one Unix endpoint,
// persists Unknown before the first mutating Docker call, never retries an
// ambiguous mutation, and leaves Unknown if any effect or cleanup is unsure.
func TestCodingCompleteObservationOneRealDaemonBatch(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CODING_COMPLETE_OBSERVATION") != "1" {
		t.Skip("one approved Coding completion batch not enabled")
	}
	if runtime.GOARCH != "arm64" {
		t.Fatal("approved native arm64 batch cannot run on another host")
	}
	host := os.Getenv("SANDBOX_RUNTIME_CODING_COMPLETE_UNIX_ENDPOINT")
	if !strings.HasPrefix(host, "unix:///") {
		t.Fatal("explicit fixed Unix endpoint required")
	}
	socket := strings.TrimPrefix(host, "unix://")
	if filepath.Clean(socket) != socket || len(socket) > 100 {
		t.Fatal("invalid fixed test Unix endpoint")
	}
	socketInfo, err := os.Lstat(socket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("fixed test endpoint is not a Unix socket")
	}
	archivePath := os.Getenv("SANDBOX_RUNTIME_CODING_COMPLETE_OCI_ARCHIVE")
	archiveInfo, err := os.Lstat(archivePath)
	if err != nil || !archiveInfo.Mode().IsRegular() || archiveInfo.Mode().Perm() != 0o600 ||
		archiveInfo.Size() < 1 || archiveInfo.Size() > 8<<30 {
		t.Fatal("approved private cached OCI archive missing or unsafe")
	}
	publication := codingimage.LockedPublication()
	documents := testCodingRawDocuments(t)
	archiveDocuments, archiveProof, err := phase6security.ReadOCIArchiveDescriptorChain(archivePath,
		"registry", phase6security.ImageIdentityOCIIndex, publication.Image(), publication.Digest,
		"linux/arm64/v8", codingimage.PublishedARM64V8Digest)
	if err != nil || !bytes.Equal(archiveDocuments.Index, documents.Index) ||
		!bytes.Equal(archiveDocuments.Manifest, documents.Manifest) ||
		!bytes.Equal(archiveDocuments.Config, documents.Config) ||
		archiveProof.ConfigDigest != codingimage.PublishedARM64ConfigDigest ||
		phase6security.VerifyOCIArchiveLayers(archivePath, documents.Manifest, documents.Config) != nil {
		t.Fatal("cached OCI archive differs from retained raw descriptor/layer chain")
	}
	policy, err := os.ReadFile(filepath.Join("..", "..", "profiles", "phase6", "security", "originals",
		"moby-default-seccomp-836ae4d3.json"))
	policySum := sha256.Sum256(policy)
	if err != nil || "sha256:"+hex.EncodeToString(policySum[:]) !=
		"sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" {
		t.Fatal("pinned seccomp source drift")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		current, err := os.Lstat(socket)
		if err != nil || !os.SameFile(socketInfo, current) || current.Mode()&os.ModeSocket == 0 {
			return nil, ErrInvalidCodingObservationTransport
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	mutatingTransport := newCodingObservationHTTPTransport(dial)
	defer mutatingTransport.CloseIdleConnections()
	mutator, err := client.New(client.WithHost(host), client.WithHTTPClient(&http.Client{
		Transport: mutatingTransport, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport },
	}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer mutator.Close()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	runID := hex.EncodeToString(nonce[:])
	now := time.Now().UTC().Truncate(time.Millisecond)
	request := lifecycle.CreateRequest{OperationID: "coding-observe-operation-" + runID,
		AttemptID: "coding-observe-attempt-" + runID, FencingToken: 7,
		IdempotencyKey: "coding-observe-" + runID, RequestDigest: testControlDigest("a"),
		Deadline: now.Add(time.Minute), Spec: lifecycle.SandboxSpec{
			SandboxID:          "coding-observe-sandbox-" + runID,
			TenantID:           "coding-observe-tenant-" + runID,
			WorkOrderID:        "coding-observe-work-" + runID,
			WorkspaceID:        "coding-observe-workspace-" + runID,
			ProviderRevisionID: "coding-observe-revision-" + runID,
			RuntimeProfile:     codingimage.ProfileID, Network: lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone},
			SandboxSlotKey: "coding/observe-" + runID, LeaseExpiresAt: now.Add(time.Hour)}}
	sandbox, operation, err := lifecycle.StartCreate(request, now)
	if err != nil {
		t.Fatal(err)
	}
	operation.State = lifecycle.OperationRunning
	allocationID, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID,
		sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	slots := []codingidentity.Slot{
		{ID: "coding-" + runID + "-a", WorkloadUID: 57000, WorkloadGID: 58000,
			InputsVolume: "coding-" + runID + "-a-inputs", WorkspaceVolume: "coding-" + runID + "-a-workspace",
			OutputsVolume: "coding-" + runID + "-a-outputs"},
		{ID: "coding-" + runID + "-b", WorkloadUID: 57001, WorkloadGID: 58001,
			InputsVolume: "coding-" + runID + "-b-inputs", WorkspaceVolume: "coding-" + runID + "-b-workspace",
			OutputsVolume: "coding-" + runID + "-b-outputs"},
	}
	limits := codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64}
	template, err := phase6security.NewCodingRuntimeTemplateV2("linux/arm64/v8",
		codingimage.PublishedARM64ConfigDigest, codingimage.PublishedDescriptorSize,
		testControlDigest("f"), "sha256:"+hex.EncodeToString(policySum[:]), slots, limits)
	if err != nil {
		t.Fatal(err)
	}
	templateDigest, err := template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: testControlDigest("d"), OwnerDeployment: template.OwnerDeployment,
		OwnerPrincipalDigest: template.OwnerPrincipalDigest, Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: templateDigest, ImageDigest: template.Image.Descriptor.Digest,
		ImageConfigDigest: template.Image.ConfigDigest, NetworkMode: "none", Limits: limits,
		Capacity: codingidentity.LocalCandidateCapacity, Slots: slots}
	planDigest, err := plan.Digest()
	if err != nil || template.BindPlan(plan) != nil {
		t.Fatal("frozen template does not bind unique physical plan")
	}
	ticket := codingidentity.Reservation{PlanDigest: planDigest, Slot: slots[0],
		Claim: codingidentity.Claim{TenantDigest: tenantDigest, SandboxID: sandbox.ID,
			AllocationID: allocationID, OperationID: operation.ID, AttemptID: operation.AttemptID,
			RequestDigest: request.RequestDigest, Generation: sandbox.Generation,
			Fence: operation.FencingToken}, SpecDigest: testControlDigest("c"), Status: codingidentity.Creating}
	authority, err := NewCodingCreateAuthority(ctx, ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	endpointScope := testControlDigest("7") // explicit test fixture; not production Profile scope
	daemon, err := ObserveCodingDaemon(ctx, mutator, endpointScope)
	if err != nil || daemon.Platform != "linux/arm64/v8" {
		t.Fatal("original daemon differs from approved native platform")
	}
	binding := CodingReceiptBinding{Plan: plan, SpecBySlot: map[string]string{
		slots[0].ID: ticket.SpecDigest, slots[1].ID: testControlDigest("d")},
		ProfileDigest: plan.ProfileDigest, PlanDigest: planDigest,
		DaemonDigest: daemon.IdentityDigest, DaemonEnvironmentDigest: daemon.EnvironmentDigest,
		EndpointScopeDigest: endpointScope, RuntimePlatform: daemon.Platform,
		ControlPolicyDigest: testControlDigest("e"), PeerPrincipalDigest: testControlDigest("f"),
		Capacity: 2}
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		t.Fatal(err)
	}
	readTransport := newCodingObservationHTTPTransport(dial)
	defer readTransport.CloseIdleConnections()
	bounded := &codingObservationTransport{base: readTransport, set: set,
		endpointHost: socket, requestHost: client.DummyHost,
		imageRef: template.Image.Reference, platform: template.Image.Platform,
		archiveUID: int(slots[0].WorkloadUID), archiveGID: int(slots[0].WorkloadGID),
		archiveMode: int64(template.VolumePrepMode)}
	readAPI, err := client.New(client.WithHost(host), client.WithHTTPClient(&http.Client{
		Transport: bounded, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport },
	}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer readAPI.Close()
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	observer := &codingUnixObserver{gate: gate, api: readAPI, transport: readTransport,
		bounded: bounded, binding: binding, authority: authority, template: template,
		documents: documents, policy: policy}
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	ledgerDir, err := os.MkdirTemp(filepath.Join(userHome, ".codex"), "phase6-coding-control-")
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(ledgerDir, "receipts.json")
	ledger, err := InitializeCodingReceiptLedger(ctx, ledgerPath, binding, func(ctx context.Context) error {
		inventory, err := observer.ReadInventory(ctx)
		if err != nil {
			return err
		}
		for _, item := range inventory.Containers {
			if item.Present {
				return ErrInvalidCodingInventory
			}
		}
		for _, item := range inventory.Volumes {
			if item.Present {
				return ErrInvalidCodingInventory
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("clean namespace/ledger initialization failed; private dir=%s: %v", ledgerDir, err)
	}
	defer ledger.Close()
	var effectsConfirmed bool
	receipt, err := ledger.DispatchCodingCreate(ctx, authority, func(effectCtx context.Context, got CodingCreateAuthority) error {
		if got != authority {
			return ErrInvalidAuthority
		}
		persisted, err := readReceiptState(ledgerPath, binding)
		if err != nil || persisted.Revision != 2 || len(persisted.Records) != 1 ||
			persisted.Records[0].Status != ReceiptUnknown {
			return ErrInvalidReceiptState
		}
		for _, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
			name, _ := set.VolumeName(role)
			labels, _ := set.Labels(role)
			if _, err := mutator.VolumeCreate(effectCtx, client.VolumeCreateOptions{
				Name: name, Driver: "local", Labels: labels}); err != nil {
				return err
			}
		}
		prepName, _ := set.ContainerName(CodingPreparationRole)
		prepLabels, _ := set.ContainerLabels(CodingPreparationRole, template, documents)
		prep, mounts, err := codingProbeCreateOptions(template, plan, ticket.Claim,
			slots[0].ID, codingProbePreparation, prepName, prepLabels, policy)
		if err != nil || !slices.Equal(mounts, set.Mounts()) {
			return ErrInvalidVolumePrep
		}
		delete(prep.Config.Labels, "io.github.shell-echo.sandbox-runtime.phase")
		createdPrep, err := mutator.ContainerCreate(effectCtx, prep)
		if err != nil || createdPrep.ID == "" {
			return ErrInvalidVolumePrep
		}
		inspectedPrep, err := mutator.ContainerInspect(effectCtx, prepName, client.ContainerInspectOptions{})
		if err != nil || inspectedPrep.Container.ID != createdPrep.ID || inspectedPrep.Container.State == nil ||
			inspectedPrep.Container.State.Running || inspectedPrep.Container.State.Pid != 0 ||
			matchEffectiveCodingContainerLabels(prepLabels, inspectedPrep.Container.Config.Labels) != nil ||
			codingProbeContainerMismatch(inspectedPrep.Container, template, slots[0], mounts,
				fmt.Sprintf("%d:%d", slots[0].WorkloadUID, slots[0].WorkloadGID),
				string(policy), codingProbePreparation) != "" {
			return ErrInvalidVolumePrep
		}
		prepArchive, err := CodingVolumePrepArchive(template, slots[0].ID)
		if err != nil {
			return err
		}
		if _, err := mutator.CopyToContainer(effectCtx, createdPrep.ID, client.CopyToContainerOptions{
			DestinationPath: "/", Content: bytes.NewReader(prepArchive),
			CopyUIDGID: false, AllowOverwriteDirWithFile: false}); err != nil {
			return err
		}
		if _, err := mutator.ContainerRemove(effectCtx, createdPrep.ID,
			client.ContainerRemoveOptions{Force: false}); err != nil {
			return err
		}
		if _, err := mutator.ContainerInspect(effectCtx, prepName, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			return ErrInvalidVolumePrep
		}
		runtimeName, _ := set.ContainerName(CodingRuntimeRole)
		runtimeLabels, _ := set.ContainerLabels(CodingRuntimeRole, template, documents)
		runtimeOptions, runtimeMounts, err := codingProbeCreateOptions(template, plan,
			ticket.Claim, slots[0].ID, codingProbeRuntime, runtimeName, runtimeLabels, policy)
		if err != nil || !slices.Equal(runtimeMounts, set.Mounts()) {
			return ErrInvalidVolumePrep
		}
		delete(runtimeOptions.Config.Labels, "io.github.shell-echo.sandbox-runtime.phase")
		createdRuntime, err := mutator.ContainerCreate(effectCtx, runtimeOptions)
		if err != nil || !codingArchiveRuntimeID.MatchString(createdRuntime.ID) {
			return ErrInvalidVolumePrep
		}
		stoppedRuntime, err := mutator.ContainerInspect(effectCtx, runtimeName, client.ContainerInspectOptions{})
		if err != nil || stoppedRuntime.Container.ID != createdRuntime.ID ||
			stoppedRuntime.Container.State == nil || stoppedRuntime.Container.State.Running ||
			stoppedRuntime.Container.State.Pid != 0 ||
			matchEffectiveCodingContainerLabels(runtimeLabels, stoppedRuntime.Container.Config.Labels) != nil ||
			codingProbeContainerMismatch(stoppedRuntime.Container, template, slots[0], runtimeMounts,
				fmt.Sprintf("%d:%d", slots[0].WorkloadUID, slots[0].WorkloadGID),
				string(policy), codingProbeRuntime) != "" {
			return ErrInvalidVolumePrep
		}
		if _, err := mutator.ContainerStart(effectCtx, createdRuntime.ID,
			client.ContainerStartOptions{}); err != nil {
			return err
		}
		effectsConfirmed = true
		return nil
	})
	if err != nil || !effectsConfirmed || receipt.Status != ReceiptUnknown {
		t.Fatalf("physical effect uncertain; retain Unknown and resources, private ledger=%s: %v", ledgerDir, err)
	}
	state, err := readReceiptState(ledgerPath, binding)
	if err != nil || state.Revision != 2 {
		t.Fatalf("Unknown receipt changed before observation; retain resources, ledger=%s: %v", ledgerDir, err)
	}
	proof, err := observer.observeCompleted(ctx, receipt, state.Revision)
	if err != nil || proof.recheck(binding, authority, template, documents, policy) != nil {
		t.Fatalf("physical observation is not independently complete; retain Unknown/resources, ledger=%s: %v", ledgerDir, err)
	}
	proofDocument, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	proofFile, err := os.OpenFile(filepath.Join(ledgerDir, "private-completion-observation.json"),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	written, writeErr := proofFile.Write(proofDocument)
	syncErr := proofFile.Sync()
	closeErr := proofFile.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(proofDocument) {
		t.Fatalf("private physical proof persistence failed; retain resources, ledger=%s: write=%v sync=%v close=%v bytes=%d",
			ledgerDir, writeErr, syncErr, closeErr, written)
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cleanupCancel()
	if _, err := cleanupCodingObservedEffect(cleanupCtx, mutator, observer, set, proof,
		template, documents, policy); err != nil {
		t.Fatalf("exact cleanup uncertain; retain Unknown, ledger=%s: %v", ledgerDir, err)
	}
	t.Logf("one physical completion-observation batch: run=%s proof=%s runtime=%s; exact two-container/three-volume zero after cleanup; durable receipt remains Unknown; private evidence=%s",
		runID, proof.CompletionDigest, proof.RuntimeID, ledgerDir)
}

func cleanupCodingObservedEffect(ctx context.Context, api *client.Client,
	observer *codingUnixObserver, set CodingResourceSet, proof codingCompletionObservation,
	template phase6security.CodingRuntimeTemplateV2, documents phase6security.ImageDescriptorDocuments,
	policy []byte) ([2]CodingResourceInventory, error) {
	var absent [2]CodingResourceInventory
	if ctx.Err() != nil || proof.recheck(observer.binding, observer.authority, template, documents, policy) != nil {
		return absent, ErrInvalidCodingCompletionObservation
	}
	prepName, _ := set.ContainerName(CodingPreparationRole)
	if _, err := api.ContainerInspect(ctx, prepName, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		return absent, ErrInvalidCodingCompletionObservation
	}
	runtimeName, _ := set.ContainerName(CodingRuntimeRole)
	inspected, err := api.ContainerInspect(ctx, runtimeName, client.ContainerInspectOptions{})
	if err != nil || inspected.Container.ID != proof.RuntimeID || inspected.Container.Config == nil {
		return absent, ErrInvalidCodingCompletionObservation
	}
	runtimeLabels, _ := set.ContainerLabels(CodingRuntimeRole, template, documents)
	var slot codingidentity.Slot
	for _, candidate := range template.Slots {
		if candidate.ID == observer.authority.SlotID {
			slot = candidate
		}
	}
	if slot.ID == "" || validateCodingRuntimeInspect(inspected.Container, proof.RuntimeID,
		runtimeName, runtimeLabels, template, slot, set.Mounts(), string(policy)) != nil {
		return absent, ErrInvalidCodingCompletionObservation
	}
	if _, err := api.ContainerRemove(ctx, proof.RuntimeID, client.ContainerRemoveOptions{Force: true}); err != nil {
		return absent, err
	}
	for _, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := set.VolumeName(role)
		labels, _ := set.Labels(role)
		volume, err := api.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
		if err != nil || volume.Volume.Name != name || volume.Volume.Driver != "local" ||
			volume.Volume.Scope != "local" ||
			len(volume.Volume.Options) != 0 || !mapsEqualStringString(volume.Volume.Labels, labels) {
			return absent, ErrInvalidCodingCompletionObservation
		}
		if _, err := api.VolumeRemove(ctx, name, client.VolumeRemoveOptions{}); err != nil {
			return absent, err
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		inventory, err := observer.ReadInventory(ctx)
		if err != nil || inventory.Daemon != proof.Daemon {
			return absent, ErrInvalidCodingInventory
		}
		for _, item := range inventory.Containers {
			if item.Present {
				return absent, ErrInvalidCodingInventory
			}
		}
		for _, item := range inventory.Volumes {
			if item.Present {
				return absent, ErrInvalidCodingInventory
			}
		}
		absent[attempt] = inventory
	}
	return absent, nil
}

func mapsEqualStringString(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}
