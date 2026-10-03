//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6FiniteCarrierAdmissionEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_FINITE_CARRIER_ADMISSION"

// No Vault, issuer, controller or operator process starts here. A real
// stopped Docker container proves the finite task's exact index reference,
// selected arm64 manifest/config, two read-only mounts and cleanup.
func TestPhase6Slice6FiniteCarrierAdmission(t *testing.T) {
	if os.Getenv(slice6FiniteCarrierAdmissionEnv) != "1" {
		t.Skip("set " + slice6FiniteCarrierAdmissionEnv + "=1 for the no-secret finite-task carrier")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	sourceRoot := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT")
	revision := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION")
	if !absoluteCleanSlice6Path(sourceRoot) || runtime.Version() != "go1.26.8" ||
		len(revision) != 40 || !lowerHexSlice6(revision) ||
		verifyCleanSlice6Source(ctx, sourceRoot, revision) != nil {
		t.Fatal("clean locked source unavailable for finite carrier admission")
	}
	items := slice6RequiredAuxiliaryImages()
	if len(items) != 3 || items[2].name != "break-glass-operator-task" ||
		items[2].digest != phase6security.Slice6BreakGlassCarrierIndexDigest {
		t.Fatal("finite task carrier missing from preissuer inventory")
	}
	if err := slice6PreflightAuxiliaryImages(ctx); err != nil {
		t.Fatal(err)
	}
	carrier := items[2]
	archive := filepath.Join(t.TempDir(), "finite-carrier.oci.tar")
	if _, err := exec.CommandContext(ctx, "docker", "image", "save", "-o", archive, carrier.reference).CombinedOutput(); err != nil {
		t.Fatal("export exact pinned finite-task index")
	}
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal("restrict finite-task OCI archive")
	}
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(archive, "registry",
		phase6security.ImageIdentityOCIIndex, carrier.reference, carrier.digest, "linux/arm64/v8",
		phase6security.Slice6BreakGlassCarrierManifestDigest)
	if err != nil || proof.ConfigDigest != phase6security.Slice6BreakGlassCarrierConfigDigest ||
		phase6security.VerifyOCIArchiveLayers(archive, documents.Manifest, documents.Config) != nil {
		t.Fatal("finite-task index, selected arm64 manifest, config or layers differ from locked authority")
	}
	operatorDirectory, err := os.MkdirTemp(filepath.Dir(sourceRoot), ".sr-p6-finite-carrier-")
	if err != nil {
		t.Fatal("create private finite-task executable directory")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(operatorDirectory); err != nil {
			t.Errorf("remove exact finite-task executable directory: %v", err)
		}
	})
	binary := filepath.Join(operatorDirectory, "phase6-break-glass-operator")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", binary, "./cmd/phase6-break-glass-operator")
	build.Dir = sourceRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local",
		"GOFLAGS=", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
	if _, err := build.CombinedOutput(); err != nil || os.Chmod(binary, 0o555) != nil {
		t.Fatal("build exact clean-source finite-task executable")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("finite-task carrier exact cleanup: %v", err)
		}
	})
	volume := "sr-p6-finite-socket-" + run.id
	if _, err := run.docker(ctx, "volume", "create", "--name", volume, "--label", run.label()); err != nil {
		t.Fatal("create exact finite-task socket volume")
	}
	name := "sr-p6-break-glass-admission-" + run.id
	created, createErr := run.docker(ctx, "create", "-i", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network=none", "--restart=no", "--user=20091:30091",
		"--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--read-only",
		"--memory", strconv.FormatInt(64<<20, 10), "--cpus=0.100", "--pids-limit=16",
		"--mount", "type=bind,src="+binary+",dst=/phase6-break-glass-operator,readonly",
		"--mount", "type=volume,src="+volume+",dst=/run/phase6/break-glass/controller/operator,readonly",
		"--entrypoint=/phase6-break-glass-operator", carrier.reference)
	id := slice6CanonicalCreatedID(created, createErr)
	if id == "" {
		t.Fatalf("no-secret finite-task create: %s", slice6DockerCreateFailure(ctx, created, createErr))
	}
	containerDocument, containerErr := run.docker(ctx, "inspect", id)
	imageDocument, imageErr := run.docker(ctx, "image", "inspect", carrier.reference)
	if containerErr != nil || imageErr != nil {
		t.Fatal("inspect exact finite-task container and pinned image")
	}
	observed, err := phase6security.ObserveDockerRuntimeImage(containerDocument, imageDocument,
		"registry", phase6security.ImageIdentityOCIIndex, carrier.reference, carrier.digest, "linux/arm64/v8",
		phase6security.Slice6BreakGlassCarrierManifestDigest,
		phase6security.Slice6BreakGlassCarrierConfigDigest, documents)
	if err != nil || observed.ContainerID != id || observed.RuntimeStoreImageID != carrier.digest ||
		observed.SelectedManifestDescriptor.Digest != phase6security.Slice6BreakGlassCarrierManifestDigest ||
		observed.OCIConfigDigest != phase6security.Slice6BreakGlassCarrierConfigDigest {
		t.Fatal("finite-task Docker index/selected manifest/config differs from complete OCI archive")
	}
	var containers []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image      string            `json:"Image"`
			User       string            `json:"User"`
			Entrypoint []string          `json:"Entrypoint"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode    string `json:"NetworkMode"`
			ReadonlyRootfs bool   `json:"ReadonlyRootfs"`
			Privileged     bool   `json:"Privileged"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type, Source, Name, Destination string
			RW                              bool
		} `json:"Mounts"`
	}
	if json.Unmarshal(containerDocument, &containers) != nil || len(containers) != 1 ||
		containers[0].ID != id || containers[0].Name != "/"+name ||
		containers[0].Config.Labels[slice6RunLabel] != run.id ||
		containers[0].Config.Image != carrier.reference || containers[0].Config.User != "20091:30091" ||
		!slices.Equal(containers[0].Config.Entrypoint, []string{"/phase6-break-glass-operator"}) ||
		containers[0].HostConfig.NetworkMode != "none" || !containers[0].HostConfig.ReadonlyRootfs ||
		containers[0].HostConfig.Privileged || len(containers[0].Mounts) != 2 {
		t.Fatal("finite-task created-container identity or confinement drift")
	}
	seenBinary, seenSocket := false, false
	for _, mount := range containers[0].Mounts {
		if mount.RW {
			t.Fatal("finite-task admission gained writable mount")
		}
		if mount.Type == "bind" && mount.Source == binary && mount.Destination == "/phase6-break-glass-operator" {
			seenBinary = true
		}
		if mount.Type == "volume" && mount.Name == volume &&
			mount.Destination == "/run/phase6/break-glass/controller/operator" {
			seenSocket = true
		}
	}
	if !seenBinary || !seenSocket {
		t.Fatal("finite-task executable or sole socket mount differs from reviewed shape")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if remaining, err := run.labeledIDs(ctx, "container"); err != nil || len(remaining) != 0 {
		t.Fatal("finite-task created container remained after exact cleanup")
	}
	if remaining, err := run.labeledIDs(ctx, "volume"); err != nil || len(remaining) != 0 {
		t.Fatal("finite-task socket volume remained after exact cleanup")
	}
	t.Log("pinned finite-task index, selected arm64 manifest/config/layers, two read-only mounts and exact cleanup observed; no operator process or issuer")
}
