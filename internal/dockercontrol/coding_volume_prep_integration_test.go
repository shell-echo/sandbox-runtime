//go:build integration

package dockercontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

const codingPrepProbeEnv = "SANDBOX_RUNTIME_CODING_VOLUME_PREP_PROBE"

// This one-shot mechanism probe is not a production Control service or a
// release gate. It creates one never-started preparation carrier, removes it,
// then creates one separate read-only runtime over the same three uniquely
// labelled volumes. Only the runtime may start for fixed high-UID checks.
func TestCodingVolumePrepArchiveRealDaemon(t *testing.T) {
	if os.Getenv(codingPrepProbeEnv) != "1" {
		t.Skip("set " + codingPrepProbeEnv + "=1 to run the bounded local Docker probe")
	}
	if runtime.GOARCH != "arm64" {
		t.Skip("the approved one-shot probe is bound to the current arm64 host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	api, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal("construct local Docker API client:", err)
	}
	t.Cleanup(func() { _ = api.Close() })
	version, err := api.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil || version.Os != "linux" || version.Arch != "arm64" {
		t.Fatalf("unsupported local daemon version/OS/arch: %#v, %v", version, err)
	}
	t.Logf("Docker client API %s; daemon %s API %s linux/arm64; CopyUIDGID=false; AllowOverwriteDirWithFile=false",
		api.ClientVersion(), version.Version, version.APIVersion)
	publication := codingimage.LockedPublication()
	var rawImage bytes.Buffer
	imageResult, err := api.ImageInspect(ctx, publication.Image(), client.ImageInspectWithRawResponse(&rawImage))
	if err != nil || imageResult.Descriptor == nil ||
		imageResult.Descriptor.Digest.String() != publication.Digest ||
		imageResult.Descriptor.MediaType != "application/vnd.oci.image.index.v1+json" ||
		imageResult.Descriptor.Size != codingimage.PublishedDescriptorSize {
		t.Fatalf("local image index descriptor mismatch: %v", err)
	}
	platform := &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	selectedImage, err := api.ImageInspect(ctx, publication.Image(), client.ImageInspectWithPlatform(platform))
	manifest, manifestErr := codingimage.LockedManifest()
	if err != nil || selectedImage.Descriptor == nil ||
		selectedImage.Descriptor.Digest.String() != codingimage.PublishedARM64V8Digest ||
		selectedImage.Descriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
		selectedImage.Descriptor.Size != codingimage.PublishedManifestSize ||
		selectedImage.Descriptor.Platform == nil ||
		selectedImage.Descriptor.Platform.OS != platform.OS ||
		selectedImage.Descriptor.Platform.Architecture != platform.Architecture ||
		selectedImage.Descriptor.Platform.Variant != platform.Variant ||
		selectedImage.Config == nil || manifestErr != nil ||
		!slices.Equal(selectedImage.Config.Env, codingimage.LockedRuntimeEnvironment()) ||
		len(selectedImage.Config.Entrypoint) != 0 ||
		!slices.Equal(selectedImage.Config.Cmd, manifest.Runtime.Command) ||
		len(selectedImage.Config.Volumes) != 0 || selectedImage.Config.Healthcheck != nil ||
		selectedImage.Config.WorkingDir != "/workspace" || selectedImage.Config.User != "65532:65532" {
		t.Fatalf("local selected image descriptor or frozen config mismatch: %v", err)
	}
	policyPath := filepath.Join("..", "..", "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal("read pinned seccomp source:", err)
	}
	policySum := sha256.Sum256(policy)
	policyDigest := "sha256:" + hex.EncodeToString(policySum[:])
	if policyDigest != "sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" {
		t.Fatal("seccomp source digest drift")
	}
	runID := fmt.Sprintf("%x%x", time.Now().UnixNano(), os.Getpid())
	t.Logf("one-shot Coding volume probe run=%s image=%s selected_manifest=%s config=%s",
		runID, publication.Image(), codingimage.PublishedARM64V8Digest,
		codingimage.PublishedARM64ConfigDigest)
	firstSlotID, secondSlotID := "coding-"+runID+"-a", "coding-"+runID+"-b"
	slots := []codingidentity.Slot{
		{ID: firstSlotID, WorkloadUID: 57000, WorkloadGID: 58000,
			InputsVolume: firstSlotID + "-inputs", WorkspaceVolume: firstSlotID + "-workspace", OutputsVolume: firstSlotID + "-outputs"},
		{ID: secondSlotID, WorkloadUID: 57001, WorkloadGID: 58001,
			InputsVolume: secondSlotID + "-inputs", WorkspaceVolume: secondSlotID + "-workspace", OutputsVolume: secondSlotID + "-outputs"},
	}
	limits := codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64}
	template, err := phase6security.NewCodingRuntimeTemplateV2("linux/arm64/v8",
		codingimage.PublishedARM64ConfigDigest,
		imageResult.Descriptor.Size, testControlDigest("f"), policyDigest, slots, limits)
	if err != nil {
		t.Fatal("source-derived v2 template:", err)
	}
	// Verify the actual cached OCI index -> selected manifest -> config ->
	// layers before creating any probe resources. Docker's containerd store
	// image ID is the index descriptor, not the OCI config digest.
	archivePath := filepath.Join(t.TempDir(), "coding-published.oci.tar")
	archiveCommand := exec.CommandContext(ctx, "docker", "image", "save", "-o", archivePath, publication.Image())
	if output, saveErr := archiveCommand.CombinedOutput(); saveErr != nil {
		t.Fatalf("save only the cached pinned Coding image: %v, output=%.256s", saveErr, output)
	}
	if err := os.Chmod(archivePath, 0o600); err != nil {
		t.Fatal("restrict private Coding image archive:", err)
	}
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(archivePath,
		"registry", phase6security.ImageIdentityOCIIndex, publication.Image(), publication.Digest,
		"linux/arm64/v8", codingimage.PublishedARM64V8Digest)
	if err != nil || proof.ConfigDigest != template.Image.ConfigDigest ||
		phase6security.VerifyOCIArchiveLayers(archivePath, documents.Manifest, documents.Config) != nil {
		t.Fatalf("cached Coding OCI descriptor/config/layer chain differs from template: %v", err)
	}
	templateDigest, err := template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: testControlDigest("d"), OwnerDeployment: template.OwnerDeployment,
		OwnerPrincipalDigest: template.OwnerPrincipalDigest, Namespace: "coding-volume-prep-probe",
		ControllerID: "coding-volume-prep-probe", Template: "coding-sandbox-runtime",
		TemplateDigest: templateDigest, ImageDigest: template.Image.Descriptor.Digest,
		ImageConfigDigest: template.Image.ConfigDigest, NetworkMode: template.NetworkMode,
		Limits: template.Limits, Capacity: codingidentity.LocalCandidateCapacity, Slots: slots}
	if template.BindPlan(plan) != nil {
		t.Fatal("v2 template did not bind probe plan")
	}
	sandboxID, operationID := "probe-sandbox-"+runID, "probe-operation-"+runID
	allocationID, err := codingidentity.DeriveAllocationID("probe-revision", "probe-tenant", sandboxID, operationID)
	if err != nil {
		t.Fatal(err)
	}
	claim := codingidentity.Claim{TenantDigest: testControlDigest("a"), SandboxID: sandboxID,
		AllocationID: allocationID, OperationID: operationID, AttemptID: "probe-attempt-" + runID,
		RequestDigest: testControlDigest("b"), Generation: 1, Fence: 1}
	mounts, err := plan.EffectiveMounts(slots[0].ID, claim)
	if err != nil || len(mounts) != 3 {
		t.Fatalf("closed volume mapping: %v", err)
	}
	prepName := "sandbox-runtime-coding-prep-probe-" + runID
	runtimeName := "sandbox-runtime-coding-runtime-probe-" + runID
	probeLabel := "io.github.shell-echo.sandbox-runtime.coding-prep-probe"
	labels := map[string]string{probeLabel: runID,
		"io.github.shell-echo.sandbox-runtime.managed":   "true",
		"io.github.shell-echo.sandbox-runtime.namespace": "coding-volume-prep-probe"}
	for _, name := range []string{prepName, runtimeName} {
		if _, err := api.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatalf("probe container name was not absent before allocation: %s, %v", name, err)
		}
	}
	for _, item := range mounts {
		if _, err := api.VolumeInspect(ctx, item.Name, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatalf("probe volume name was not absent before allocation: %s, %v", item.Target, err)
		}
	}
	// Register cleanup before the first creation. If a response is lost, the
	// unique names are still checked for exact ownership before deletion.
	t.Cleanup(func() {
		cleanupCodingVolumeProbe(t, api, []string{runtimeName, prepName}, mounts, probeLabel, runID)
	})
	for _, item := range mounts {
		if _, err := api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: item.Name, Driver: "local",
			Labels: map[string]string{probeLabel: runID, "io.github.shell-echo.sandbox-runtime.target": item.Target}}); err != nil {
			t.Fatalf("create exact probe volume %s: %v", item.Target, err)
		}
	}
	for _, item := range mounts {
		observed, err := api.VolumeInspect(ctx, item.Name, client.VolumeInspectOptions{})
		if err != nil || observed.Volume.Name != item.Name || observed.Volume.Driver != "local" ||
			observed.Volume.Labels[probeLabel] != runID || observed.Volume.Labels["io.github.shell-echo.sandbox-runtime.target"] != item.Target {
			t.Fatalf("probe volume identity mismatch for %s: %v", item.Target, err)
		}
	}
	user := fmt.Sprintf("%d:%d", slots[0].WorkloadUID, slots[0].WorkloadGID)
	prepOptions, prepMounts, err := codingProbeCreateOptions(template, plan, claim, slots[0].ID,
		codingProbePreparation, prepName, labels, policy)
	if err != nil || !slices.Equal(prepMounts, mounts) || codingProbeStartAllowed(codingProbePreparation) {
		t.Fatalf("closed stopped preparation projection: %v", err)
	}
	createdAt := time.Now()
	prep, err := api.ContainerCreate(ctx, prepOptions)
	if err != nil || prep.ID == "" {
		t.Fatalf("create one stopped preparation carrier: %v", err)
	}
	t.Logf("stopped preparation create elapsed=%s", time.Since(createdAt))
	rootBefore, err := codingProbePathOwnership(ctx, api, prep.ID, "/")
	if err != nil {
		t.Fatalf("initial preparation root inode: %v", err)
	}
	inputsBefore, err := codingProbePathOwnership(ctx, api, prep.ID, "/inputs")
	if err != nil {
		t.Fatalf("initial read-only inputs inode: %v", err)
	}
	for _, target := range []string{"/workspace", "/outputs"} {
		before, err := codingProbePathOwnership(ctx, api, prep.ID, target)
		if err != nil || before.UID != 65532 || before.GID != 65532 || before.Mode != 0o770 {
			t.Fatalf("initial %s inode owner/mode = %#v, %v", target, before, err)
		}
		if err := codingProbeEmptyDirectory(ctx, api, prep.ID, target); err != nil {
			t.Fatalf("new %s volume is not empty: %v", target, err)
		}
	}
	if err := codingProbeEmptyDirectory(ctx, api, prep.ID, "/inputs"); err != nil {
		t.Fatalf("new read-only inputs volume is not empty: %v", err)
	}
	if err := codingProbeInspectStopped(ctx, api, prep.ID, prepName, runID, probeLabel,
		template, slots[0], mounts, user, policy, codingProbePreparation,
		rawImage.Bytes(), documents, proof.ProofDigest); err != nil {
		t.Fatalf("preparation carrier admission before archive: %v", err)
	}
	archive, err := CodingVolumePrepArchive(template, slots[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	archiveStarted := time.Now()
	_, err = api.CopyToContainer(ctx, prep.ID, client.CopyToContainerOptions{
		DestinationPath: "/", Content: bytes.NewReader(archive),
		CopyUIDGID: false, AllowOverwriteDirWithFile: false})
	if err != nil {
		t.Fatalf("closed two-directory stopped-carrier archive-put: %v", err)
	}
	if err := codingProbeInspectStopped(ctx, api, prep.ID, prepName, runID, probeLabel,
		template, slots[0], mounts, user, policy, codingProbePreparation,
		rawImage.Bytes(), documents, proof.ProofDigest); err != nil {
		t.Fatalf("preparation carrier drift after archive: %v", err)
	}
	for _, target := range []string{"/workspace", "/outputs"} {
		observed, err := codingProbePathOwnership(ctx, api, prep.ID, target)
		if err != nil || observed.UID != int(slots[0].WorkloadUID) ||
			observed.GID != int(slots[0].WorkloadGID) ||
			observed.Mode != int64(template.VolumePrepMode) {
			t.Fatalf("prepared %s ownership = %#v, %v", target, observed, err)
		}
		t.Logf("prepared %s owner=%d:%d mode=%o", target, observed.UID, observed.GID, observed.Mode)
	}
	rootAfter, rootErr := codingProbePathOwnership(ctx, api, prep.ID, "/")
	inputsAfter, inputsErr := codingProbePathOwnership(ctx, api, prep.ID, "/inputs")
	if rootErr != nil || inputsErr != nil || rootAfter != rootBefore || inputsAfter != inputsBefore {
		t.Fatalf("preparation changed root or read-only inputs metadata: root=%#v inputs=%#v errors=%v %v",
			rootAfter, inputsAfter, rootErr, inputsErr)
	}
	t.Logf("stopped-carrier archive-put and inode verification elapsed=%s", time.Since(archiveStarted))
	if _, err := api.ContainerRemove(ctx, prep.ID, client.ContainerRemoveOptions{Force: false}); err != nil {
		t.Fatalf("remove never-started preparation carrier before runtime creation: %v", err)
	}
	if _, err := api.ContainerInspect(ctx, prepName, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatalf("preparation carrier not absent before runtime creation: %v", err)
	}
	runtimeOptions, runtimeMounts, err := codingProbeCreateOptions(template, plan, claim, slots[0].ID,
		codingProbeRuntime, runtimeName, labels, policy)
	if err != nil || !slices.Equal(runtimeMounts, mounts) || !codingProbeStartAllowed(codingProbeRuntime) {
		t.Fatalf("closed read-only runtime projection: %v", err)
	}
	runtimeCreated, err := api.ContainerCreate(ctx, runtimeOptions)
	if err != nil || runtimeCreated.ID == "" {
		t.Fatalf("create one closed read-only runtime: %v", err)
	}
	if err := codingProbeInspectStopped(ctx, api, runtimeCreated.ID, runtimeName, runID, probeLabel,
		template, slots[0], mounts, user, policy, codingProbeRuntime,
		rawImage.Bytes(), documents, proof.ProofDigest); err != nil {
		t.Fatalf("read-only runtime admission before start: %v", err)
	}
	for _, target := range []string{"/workspace", "/outputs"} {
		observed, err := codingProbePathOwnership(ctx, api, runtimeCreated.ID, target)
		if err != nil || observed.UID != int(slots[0].WorkloadUID) ||
			observed.GID != int(slots[0].WorkloadGID) ||
			observed.Mode != int64(template.VolumePrepMode) {
			t.Fatalf("runtime NoCopy %s ownership = %#v, %v", target, observed, err)
		}
	}
	if !codingProbeStartAllowed(codingProbeRuntime) {
		t.Fatal("runtime phase no longer permits start")
	}
	if _, err := api.ContainerStart(ctx, runtimeCreated.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start only the read-only high-UID runtime: %v", err)
	}
	running, err := api.ContainerInspect(ctx, runtimeCreated.ID, client.ContainerInspectOptions{})
	if err != nil || running.Container.State == nil || !running.Container.State.Running ||
		running.Container.State.Pid <= 0 ||
		codingProbeContainerMismatch(running.Container, template, slots[0], mounts,
			user, string(policy), codingProbeRuntime) != "" {
		t.Fatalf("started workload is not the closed read-only runtime: %v", err)
	}
	for _, item := range []struct {
		path    string
		succeed bool
	}{{"/workspace/probe", true}, {"/outputs/probe", true}, {"/tmp/probe", true},
		{"/inputs/probe", false}, {"/root-probe", false}} {
		command := exec.CommandContext(ctx, "docker", "exec", "--user", user, runtimeCreated.ID, "touch", item.path)
		output, err := command.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("high-UID fixed write check %s exceeded probe deadline: %v", item.path, ctx.Err())
		}
		if item.succeed {
			if err != nil {
				t.Fatalf("high-UID fixed write check %s did not succeed: %v, output=%q", item.path, err, output)
			}
		} else {
			var exitErr *exec.ExitError
			denial := strings.Contains(string(output), "Permission denied") ||
				strings.Contains(string(output), "Read-only file system")
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 ||
				!strings.HasPrefix(strings.TrimSpace(string(output)), "touch: "+item.path+": ") || !denial {
				t.Fatalf("high-UID fixed write check %s lacked an actual permission denial: %v, output=%q", item.path, err, output)
			}
		}
		t.Logf("high-UID fixed write %s permitted=%t", item.path, err == nil)
	}
}

func codingProbeInspectStopped(ctx context.Context, api *client.Client, id, name, runID, probeLabel string,
	template phase6security.CodingRuntimeTemplateV2, slot codingidentity.Slot,
	mounts []codingidentity.VolumeMount, user string, policy []byte,
	phase codingProbePhase, rawImage []byte, documents phase6security.ImageDescriptorDocuments,
	expectedProofDigest string) error {
	inspected, err := api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect exact %s: %w", phase, err)
	}
	state := inspected.Container.State
	if state == nil || state.Status != "created" || state.Running || state.Pid != 0 ||
		state.ExitCode != 0 || state.Error != "" || !codingProbeZeroStartedAt(state.StartedAt) ||
		inspected.Container.RestartCount != 0 || len(inspected.Container.ExecIDs) != 0 ||
		inspected.Container.Name != "/"+name || inspected.Container.Config == nil ||
		inspected.Container.Config.Labels[probeLabel] != runID ||
		inspected.Container.Config.Labels["io.github.shell-echo.sandbox-runtime.phase"] != string(phase) {
		return fmt.Errorf("%s object is not exclusive, never-started and stopped", phase)
	}
	if mismatch := codingProbeContainerMismatch(inspected.Container, template, slot, mounts,
		user, string(policy), phase); mismatch != "" {
		return fmt.Errorf("%s inspect fields: %s", phase, mismatch)
	}
	observedImage, err := phase6security.ObserveDockerRuntimeImage(
		codingProbeInspectArray(inspected.Raw), codingProbeInspectArray(rawImage),
		"registry", phase6security.ImageIdentityOCIIndex, template.Image.Reference,
		template.Image.Descriptor.Digest, template.Image.Platform,
		template.Image.SelectedManifestDigest, template.Image.ConfigDigest, documents)
	if err != nil || observedImage.DescriptorProofDigest != expectedProofDigest {
		return fmt.Errorf("%s image/index/selected/config observation: %v", phase, err)
	}
	return nil
}

func codingProbeZeroStartedAt(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.IsZero()
}

// The stopped preparation carrier and running workload are two distinct,
// closed projections of the same v2 template. Only the preparation carrier
// has a writable rootfs, an inert command, and no permission to start/exec.
// The runtime always has a read-only rootfs and NoCopy on all three volumes.
func codingProbeCreateOptions(template phase6security.CodingRuntimeTemplateV2,
	plan codingidentity.Plan, claim codingidentity.Claim, slotID string,
	phase codingProbePhase, name string, labels map[string]string, policy []byte,
) (client.ContainerCreateOptions, []codingidentity.VolumeMount, error) {
	if template.BindPlan(plan) != nil || claim.Validate() != nil ||
		template.Image.Platform != "linux/arm64/v8" ||
		(phase != codingProbePreparation && phase != codingProbeRuntime) || name == "" {
		return client.ContainerCreateOptions{}, nil, ErrInvalidVolumePrep
	}
	policySum := sha256.Sum256(policy)
	if "sha256:"+hex.EncodeToString(policySum[:]) != template.SeccompPolicyDigest {
		return client.ContainerCreateOptions{}, nil, ErrInvalidVolumePrep
	}
	var slot codingidentity.Slot
	for _, candidate := range template.Slots {
		if candidate.ID == slotID {
			slot = candidate
		}
	}
	if slot.ID == "" {
		return client.ContainerCreateOptions{}, nil, ErrInvalidVolumePrep
	}
	mounts, err := plan.EffectiveMounts(slotID, claim)
	if err != nil || len(mounts) != 3 {
		return client.ContainerCreateOptions{}, nil, ErrInvalidVolumePrep
	}
	var dockerMounts []mount.Mount
	for _, item := range mounts {
		dockerMounts = append(dockerMounts, mount.Mount{Type: mount.TypeVolume,
			Source: item.Name, Target: item.Target, ReadOnly: item.ReadOnly,
			VolumeOptions: &mount.VolumeOptions{NoCopy: phase == codingProbeRuntime}})
	}
	command := slices.Clone(template.Command)
	if phase == codingProbePreparation {
		command = []string{"/bin/false"}
	}
	phaseLabels := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		phaseLabels[key] = value
	}
	phaseLabels["io.github.shell-echo.sandbox-runtime.phase"] = string(phase)
	pids := template.Limits.PIDs
	options := client.ContainerCreateOptions{
		Name: name, Platform: &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"},
		Config: &container.Config{Image: template.Image.Reference, Cmd: command,
			Env: slices.Clone(template.Environment), WorkingDir: template.WorkingDirectory,
			User: fmt.Sprintf("%d:%d", slot.WorkloadUID, slot.WorkloadGID), Labels: phaseLabels},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode("none"),
			ReadonlyRootfs: phase == codingProbeRuntime, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + string(policy)},
			Mounts:      dockerMounts, Tmpfs: map[string]string{"/tmp": fmt.Sprintf(
				"rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=%d,gid=%d",
				template.TmpfsBytes, slot.WorkloadUID, slot.WorkloadGID)},
			RestartPolicy: container.RestartPolicy{Name: "no"},
			Resources: container.Resources{Memory: template.Limits.MemoryBytes,
				MemorySwap: template.Limits.MemoryBytes,
				NanoCPUs:   int64(template.Limits.CPUMillis) * 1_000_000, PidsLimit: &pids}},
	}
	return options, mounts, nil
}

func codingProbeStartAllowed(phase codingProbePhase) bool { return phase == codingProbeRuntime }

func codingProbeInspectArray(raw []byte) []byte {
	result := make([]byte, 0, len(raw)+2)
	result = append(result, '[')
	result = append(result, raw...)
	return append(result, ']')
}

func TestCodingProbeMismatchAggregatesClosedFields(t *testing.T) {
	template := testVolumeTemplate(t)
	slot := template.Slots[0]
	mounts := []codingidentity.VolumeMount{
		{Name: slot.InputsVolume, Target: "/inputs", ReadOnly: true},
		{Name: slot.WorkspaceVolume, Target: "/workspace"},
		{Name: slot.OutputsVolume, Target: "/outputs"},
	}
	observed := container.InspectResponse{Config: &container.Config{Env: []string{"UNTRUSTED=1"}},
		HostConfig: &container.HostConfig{}}
	diagnostic := codingProbeContainerMismatch(observed, template, slot, mounts,
		"57000:58000", "private-seccomp-body", codingProbeRuntime)
	for _, field := range []string{"Image store index ID", "Config.Env", "HostConfig.SecurityOpt", "Mounts count"} {
		if !strings.Contains(diagnostic, field) {
			t.Fatalf("missing aggregated mismatch %q: %q", field, diagnostic)
		}
	}
	for _, secret := range []string{"UNTRUSTED=1", "private-seccomp-body", slot.InputsVolume} {
		if strings.Contains(diagnostic, secret) {
			t.Fatalf("mismatch diagnostic leaked a raw value: %q", diagnostic)
		}
	}
}

func TestCodingProbePhaseProjectionIsClosed(t *testing.T) {
	ticket, _, _, plan, _ := testCodingCreate(t)
	template := testVolumeTemplate(t)
	policy := []byte("fixed-test-policy")
	policySum := sha256.Sum256(policy)
	template.SeccompPolicyDigest = "sha256:" + hex.EncodeToString(policySum[:])
	digest, err := template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.TemplateDigest = digest
	plan.ImageDigest = template.Image.Descriptor.Digest
	plan.ImageConfigDigest = template.Image.ConfigDigest
	for _, phase := range []codingProbePhase{codingProbePreparation, codingProbeRuntime} {
		options, mounts, err := codingProbeCreateOptions(template, plan, ticket.Claim,
			template.Slots[0].ID, phase, "closed-test", map[string]string{"owner": "test"}, policy)
		if err != nil || options.Config == nil || options.HostConfig == nil || len(mounts) != 3 ||
			len(options.HostConfig.Mounts) != 3 || options.Config.User != "57000:58000" ||
			options.Config.Labels["io.github.shell-echo.sandbox-runtime.phase"] != string(phase) ||
			options.HostConfig.NetworkMode != container.NetworkMode("none") ||
			options.HostConfig.Privileged || !slices.Equal(options.HostConfig.CapDrop, []string{"ALL"}) {
			t.Fatalf("unsafe %s phase projection: %v", phase, err)
		}
		if phase == codingProbePreparation {
			if codingProbeStartAllowed(phase) || options.HostConfig.ReadonlyRootfs ||
				!slices.Equal(options.Config.Cmd, []string{"/bin/false"}) {
				t.Fatal("preparation carrier could run or lacks inert command")
			}
		} else if !codingProbeStartAllowed(phase) || !options.HostConfig.ReadonlyRootfs ||
			!slices.Equal(options.Config.Cmd, template.Command) {
			t.Fatal("runtime lost its read-only fixed-command policy")
		}
		for _, item := range options.HostConfig.Mounts {
			if item.Type != mount.TypeVolume || item.VolumeOptions == nil ||
				item.VolumeOptions.NoCopy != (phase == codingProbeRuntime) {
				t.Fatal("phase volume copy policy drift")
			}
		}
	}
	for name, mutate := range map[string]func(*codingidentity.Plan, *codingidentity.Claim, *string, *codingProbePhase, *[]byte){
		"wrong slot": func(_ *codingidentity.Plan, _ *codingidentity.Claim, slot *string, _ *codingProbePhase, _ *[]byte) {
			*slot = "coding-unknown"
		},
		"wrong plan": func(plan *codingidentity.Plan, _ *codingidentity.Claim, _ *string, _ *codingProbePhase, _ *[]byte) {
			plan.TemplateDigest = testControlDigest("0")
		},
		"wrong policy": func(_ *codingidentity.Plan, _ *codingidentity.Claim, _ *string, _ *codingProbePhase, policy *[]byte) {
			*policy = []byte("wrong")
		},
		"unknown phase": func(_ *codingidentity.Plan, _ *codingidentity.Claim, _ *string, phase *codingProbePhase, _ *[]byte) {
			*phase = "unknown"
		},
	} {
		t.Run(name, func(t *testing.T) {
			badPlan, badClaim, slotID, phase, badPolicy := plan, ticket.Claim,
				template.Slots[0].ID, codingProbeRuntime, slices.Clone(policy)
			mutate(&badPlan, &badClaim, &slotID, &phase, &badPolicy)
			if _, _, err := codingProbeCreateOptions(template, badPlan, badClaim, slotID,
				phase, "closed-test", nil, badPolicy); !errors.Is(err, ErrInvalidVolumePrep) {
				t.Fatalf("unsafe phase input accepted: %v", err)
			}
		})
	}
}

type codingProbeOwnership struct {
	UID, GID int
	Mode     int64
}

func codingProbeEmptyDirectory(ctx context.Context, api *client.Client, containerID, path string) error {
	result, err := api.CopyFromContainer(ctx, containerID, client.CopyFromContainerOptions{SourcePath: path})
	if err != nil {
		return err
	}
	defer result.Content.Close()
	const maximum = 32 << 10
	document, err := io.ReadAll(io.LimitReader(result.Content, maximum+1))
	if err != nil || len(document) > maximum {
		return ErrInvalidVolumePrep
	}
	reader := tar.NewReader(bytes.NewReader(document))
	header, err := reader.Next()
	if err != nil || header.Typeflag != tar.TypeDir || header.Size != 0 {
		return ErrInvalidVolumePrep
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		return ErrInvalidVolumePrep
	}
	return nil
}

func codingProbePathOwnership(ctx context.Context, api *client.Client, containerID, path string) (codingProbeOwnership, error) {
	result, err := api.CopyFromContainer(ctx, containerID, client.CopyFromContainerOptions{SourcePath: path})
	if err != nil {
		return codingProbeOwnership{}, err
	}
	defer result.Content.Close()
	reader := tar.NewReader(io.LimitReader(result.Content, 32<<10))
	header, err := reader.Next()
	if err != nil || header.Typeflag != tar.TypeDir || header.Size != 0 {
		return codingProbeOwnership{}, ErrInvalidVolumePrep
	}
	return codingProbeOwnership{UID: header.Uid, GID: header.Gid, Mode: header.Mode}, nil
}

func cleanupCodingVolumeProbe(t *testing.T, api *client.Client, containerNames []string,
	mounts []codingidentity.VolumeMount, probeLabel, runID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, containerName := range containerNames {
		inspected, err := api.ContainerInspect(ctx, containerName, client.ContainerInspectOptions{})
		if err == nil {
			if inspected.Container.Config == nil || inspected.Container.Config.Labels[probeLabel] != runID ||
				inspected.Container.Name != "/"+containerName {
				t.Errorf("refusing to remove container without exact probe ownership: %s", containerName)
			} else if _, err := api.ContainerRemove(ctx, inspected.Container.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
				t.Errorf("remove exact probe container %s: %v", containerName, err)
			}
		} else if !cerrdefs.IsNotFound(err) {
			t.Errorf("inspect exact probe container for cleanup %s: %v", containerName, err)
		}
	}
	for _, item := range mounts {
		observed, err := api.VolumeInspect(ctx, item.Name, client.VolumeInspectOptions{})
		if err == nil {
			if observed.Volume.Name != item.Name || observed.Volume.Labels[probeLabel] != runID ||
				observed.Volume.Labels["io.github.shell-echo.sandbox-runtime.target"] != item.Target {
				t.Errorf("refusing to remove volume without exact probe ownership: %s", item.Target)
			} else if _, err := api.VolumeRemove(ctx, item.Name, client.VolumeRemoveOptions{Force: false}); err != nil {
				t.Errorf("remove exact probe volume %s: %v", item.Target, err)
			}
		} else if !cerrdefs.IsNotFound(err) {
			t.Errorf("inspect exact probe volume for cleanup %s: %v", item.Target, err)
		}
	}
	for _, containerName := range containerNames {
		if _, err := api.ContainerInspect(ctx, containerName, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Errorf("probe container %s remains after cleanup: %v", containerName, err)
		}
	}
	for _, item := range mounts {
		if _, err := api.VolumeInspect(ctx, item.Name, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Errorf("probe volume remains after cleanup %s: %v", item.Target, err)
		}
	}
}
