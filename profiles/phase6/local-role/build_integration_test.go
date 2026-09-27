//go:build integration

package localrole

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This is a source-bound local-image/real-command smoke, not a complete
// Slice 6 role inventory or a release-artifact qualification.
func TestLocalCoreCandidateRunsAsHighUID(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_LOCAL_ROLE_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_LOCAL_ROLE_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	architecture, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Arch}}").Output()
	platform := "linux/arm64/v8"
	wantArchitecture := "arm64"
	if strings.TrimSpace(string(architecture)) == "amd64" {
		platform, wantArchitecture = "linux/amd64", "amd64"
	} else if err != nil || strings.TrimSpace(string(architecture)) != "arm64" {
		t.Fatalf("unsupported Docker architecture: %q, %v", architecture, err)
	}
	output, err := exec.CommandContext(ctx, "./build.sh", platform, "core").CombinedOutput()
	if err != nil {
		t.Fatalf("build source-bound local role candidate: %v: %.2048s", err, output)
	}
	image, source := "", ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "image=sha256:") {
			image = strings.TrimPrefix(line, "image=")
		}
		if strings.HasPrefix(line, "source=") {
			source = strings.TrimPrefix(line, "source=")
		}
	}
	if len(image) != 71 || len(source) != 40 {
		t.Fatalf("candidate builder omitted immutable image digest: %.512s", output)
	}
	sourceRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := phase6rolecandidate.CollectSourceInputs(ctx, sourceRoot, "product-runtime", platform)
	if err != nil || inputs.SourceRevision != source || inputs.BuildTarget != "core" ||
		!strings.HasPrefix(inputs.SourceTreeDigest, "sha256:") ||
		!strings.HasPrefix(inputs.ToolchainDigest, "sha256:") ||
		!strings.HasPrefix(inputs.DependencyLockDigest, "sha256:") {
		t.Fatalf("source-bound role build inputs: %#v, %v", inputs, err)
	}
	inspect, err := exec.CommandContext(ctx, "docker", "image", "inspect", image).Output()
	var images []struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Descriptor   *struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"Descriptor"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err != nil || json.Unmarshal(inspect, &images) != nil || len(images) != 1 ||
		images[0].ID != image || images[0].OS != "linux" || images[0].Architecture != wantArchitecture ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.phase6-candidate"] != "local-only-non-release" ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.source-revision"] != source ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.role-target"] != "core" ||
		images[0].Descriptor == nil || images[0].Descriptor.Digest != image {
		t.Fatal("local role candidate image identity or labels drifted")
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	container := "sr-p6-role-core-" + hex.EncodeToString(random)
	identityProbe := container + "-identity"
	descriptorProbe := container + "-descriptor"
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		for _, name := range []string{container, identityProbe, descriptorProbe} {
			_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
			if err := exec.CommandContext(cleanup, "docker", "inspect", name).Run(); err == nil {
				t.Errorf("test-owned local role container %s remains", name)
			}
		}
	})
	confined := []string{"run", "--rm", "--pull=never", "--network", "none", "--read-only", "--user", "21001:31001",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "32", "--memory", "128m"}
	probeArgs := append(append([]string(nil), confined...), "--name", identityProbe, "--entrypoint", "/bin/sh", image,
		"-c", "id -u; id -g")
	output, err = exec.CommandContext(ctx, "docker", probeArgs...).CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "21001\n31001" {
		t.Fatalf("effective high-UID container identity: %v: %.512s", err, output)
	}
	observeLocalRoleDescriptor(t, ctx, image, platform, sourceRoot, inputs, descriptorProbe, inspect)
	args := append(append([]string(nil), confined...), "--name", container, image, "--help")
	output, err = exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "sandbox-runtime") {
		t.Fatalf("real high-UID role command failed: %v: %.1024s", err, output)
	}
}

func observeLocalRoleDescriptor(t *testing.T, ctx context.Context, image, platform, sourceRoot string,
	inputs phase6rolecandidate.SourceInputs, name string, imageInspect []byte) {
	t.Helper()
	created, err := exec.CommandContext(ctx, "docker", "create", "--pull=never", "--network", "none", "--name", name, image).Output()
	containerID := strings.TrimSpace(string(created))
	if err != nil || len(containerID) != 64 {
		t.Fatalf("create exact stopped image observation: %v", err)
	}
	containerInspect, err := exec.CommandContext(ctx, "docker", "inspect", containerID).Output()
	var containers []struct {
		Selected *struct {
			Digest string `json:"digest"`
		} `json:"ImageManifestDescriptor"`
	}
	if err != nil || json.Unmarshal(containerInspect, &containers) != nil || len(containers) != 1 || containers[0].Selected == nil {
		t.Fatal("Docker did not report a selected candidate manifest")
	}
	var images []struct {
		Descriptor *struct {
			MediaType string `json:"mediaType"`
		} `json:"Descriptor"`
	}
	if json.Unmarshal(imageInspect, &images) != nil || len(images) != 1 || images[0].Descriptor == nil {
		t.Fatal("Docker did not report a candidate store descriptor")
	}
	kind := phase6security.ImageIdentityOCIManifest
	if images[0].Descriptor.MediaType == "application/vnd.oci.image.index.v1+json" ||
		images[0].Descriptor.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		kind = phase6security.ImageIdentityOCIIndex
	}
	archive := filepath.Join(t.TempDir(), "candidate.oci.tar")
	if output, err := exec.CommandContext(ctx, "docker", "image", "save", "-o", archive, image).CombinedOutput(); err != nil {
		t.Fatalf("save exact role candidate archive: %v: %.512s", err, output)
	}
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatalf("secure role candidate archive: %v", err)
	}
	selected := containers[0].Selected.Digest
	documents, err := phase6security.ReadOCIArchiveDocuments(archive, kind, image, selected, "")
	if err != nil {
		t.Fatalf("read raw role candidate descriptor chain: %v", err)
	}
	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if json.Unmarshal(documents.Manifest, &manifest) != nil {
		t.Fatal("selected role candidate manifest is invalid")
	}
	principal := phase6security.Principal{Name: "product-runtime", ImageLocation: "local",
		ImageReference: image, ImageDigest: image, ImageIdentityKind: kind,
		ImagePlatform: platform, ImageConfigDigest: manifest.Config.Digest}
	if kind == phase6security.ImageIdentityOCIIndex {
		principal.ImageSelectedManifestDigest = selected
	}
	probe, err := phase6security.VerifySlice6LocalRoleCandidateProbe(principal, inputs.SourceRevision,
		containerInspect, imageInspect, archive)
	if err != nil || probe.Image.OCIConfigDigest != manifest.Config.Digest ||
		probe.Image.SelectedManifestDescriptor.Digest != selected ||
		probe.ArchiveSize < 1 || !strings.HasPrefix(probe.ArchiveDigest, "sha256:") ||
		!strings.HasPrefix(probe.RootFSChainDigest, "sha256:") {
		t.Fatalf("source-bound role archive probe: %#v, %v", probe, err)
	}
	documents, err = phase6security.ReadOCIArchiveDocuments(archive, kind, image, selected, manifest.Config.Digest)
	if err != nil {
		t.Fatalf("retain exact candidate manifest and config: %v", err)
	}
	buildProof, err := phase6rolecandidate.VerifyBuildContext(ctx, sourceRoot, inputs,
		archive, documents.Manifest, documents.Config)
	if err != nil || !strings.HasPrefix(buildProof.BinaryDigest, "sha256:") ||
		!strings.HasPrefix(buildProof.BuildContextDigest, "sha256:") {
		t.Fatalf("rebuilt executable differs from verified OCI layer: %#v, %v", buildProof, err)
	}
	if output, err := exec.CommandContext(ctx, "docker", "rm", "-f", containerID).CombinedOutput(); err != nil {
		t.Fatalf("remove exact stopped role image observation: %v: %.512s", err, output)
	}
	if err := exec.CommandContext(ctx, "docker", "inspect", containerID).Run(); err == nil {
		t.Fatal("stopped role image observation container remained")
	}
}
