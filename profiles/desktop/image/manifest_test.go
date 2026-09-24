package image

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestManifestIsStrictAndComplete(t *testing.T) {
	manifest, err := Load(LocalCandidateManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if manifest.Source.Manifests["linux/amd64"].PackageArchiveSetDigest == manifest.Source.Manifests["linux/arm64/v8"].PackageArchiveSetDigest {
		t.Fatal("architecture-specific package archive locks collapsed")
	}
	if manifest.Outputs.VCSReference != "pending-phase6-locked" || len(manifest.Outputs.Platforms) != 0 {
		t.Fatal("new candidate claimed old reproducible outputs")
	}
}

func TestManifestRejectsUnsafeChanges(t *testing.T) {
	base, err := Load(LocalCandidateManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Manifest){
		"mutable source": func(m *Manifest) { m.Source.IndexDigest = "" },
		"package drift":  func(m *Manifest) { m.Packages.Required[0].Version = "latest" },
		"package bytes": func(m *Manifest) {
			platform := m.Source.Manifests["linux/amd64"]
			platform.PackageArchiveSetDigest = "sha256:" + strings.Repeat("0", 64)
			m.Source.Manifests["linux/amd64"] = platform
		},
		"root user":             func(m *Manifest) { m.Security.UID = 0 },
		"writable root":         func(m *Manifest) { m.Security.RootFilesystem = "writable" },
		"privileged":            func(m *Manifest) { m.Security.Privileged = true },
		"host device":           func(m *Manifest) { m.Security.Devices = []string{"/dev/dri"} },
		"device request":        func(m *Manifest) { m.Security.DeviceRequests = "gpu" },
		"public tcp":            func(m *Manifest) { m.Display.TCPListen = true },
		"raw display reference": func(m *Manifest) { m.Display.Reference = "/tmp/.X11-unix/X99" },
		"arbitrary method":      func(m *Manifest) { m.Broker.Methods = append(m.Broker.Methods, "exec") },
		"unbounded request":     func(m *Manifest) { m.Broker.MaxRequest = 0 },
		"forged output": func(m *Manifest) {
			m.Outputs.Platforms["linux/amd64"] = Output{ImageDigest: "sha256:" + strings.Repeat("0", 64), Evidence: "native"}
		},
		"missing attestation": func(m *Manifest) { m.Provenance.SignedAttestationRequiredForAdapter = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Source.Manifests = copyPlatforms(base.Source.Manifests)
			candidate.Packages.Repositories = append([]string(nil), base.Packages.Repositories...)
			candidate.Packages.Required = append([]Package(nil), base.Packages.Required...)
			candidate.Broker.Methods = append([]string(nil), base.Broker.Methods...)
			candidate.Security.Devices = append([]string(nil), base.Security.Devices...)
			candidate.Mounts = append([]Mount(nil), base.Mounts...)
			candidate.Outputs.Platforms = copyOutputs(base.Outputs.Platforms)
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestBuildDefinitionKeepsDesktopBoundary(t *testing.T) {
	manifest, err := Load(LocalCandidateManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile(DockerfilePath)
	if err != nil {
		t.Fatal(err)
	}
	dockerText := string(dockerfile)
	for _, required := range []string{
		"FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST}",
		"apk fetch --recursive",
		"PACKAGE_ARCHIVE_SET_SHA256",
		"apk add --no-network /tmp/apks/*.apk",
		"INSTALLED_SET_SHA256",
		"addgroup -g 1000 -S desktop",
		"adduser -u 1000",
		"FROM scratch",
		"USER 1000:1000",
		"ENTRYPOINT [\"/usr/local/bin/desktop-runtime\"]",
	} {
		if !strings.Contains(dockerText, required) {
			t.Fatalf("Dockerfile missing %q", required)
		}
	}
	for _, forbidden := range []string{"EXPOSE ", "--privileged", "/dev/dri", "/dev/input", "/dev/snd", ":latest"} {
		if strings.Contains(dockerText, forbidden) {
			t.Fatalf("Dockerfile contains forbidden value %q", forbidden)
		}
	}

	entrypoint, err := os.ReadFile(EntrypointPath)
	if err != nil {
		t.Fatal(err)
	}
	entryText := string(entrypoint)
	if !strings.Contains(entryText, `if [ "$#" -ne 0 ]`) || !strings.Contains(entryText, "desktop-broker serve") {
		t.Fatalf("entrypoint boundary is incomplete: %s", entryText)
	}

	buildScript, err := os.ReadFile(BuildScriptPath)
	if err != nil {
		t.Fatal(err)
	}
	buildText := string(buildScript)
	for _, required := range []string{
		"CGO_ENABLED=0 GOOS=linux GOARCH=\"$goarch\"",
		"go1.26.5",
		"-trimpath -buildvcs=false -ldflags=-buildid=",
		"--provenance=false",
		"SOURCE_DATE_EPOCH=0",
	} {
		if !strings.Contains(buildText, required) {
			t.Fatalf("build script missing %q", required)
		}
	}
	candidateDockerfile, err := os.ReadFile("Dockerfile.phase6-candidate")
	if err != nil {
		t.Fatal(err)
	}
	candidateText := string(candidateDockerfile)
	for _, required := range []string{"COPY --chmod=0644 apks/", "sha256sum -c /tmp/SHA256SUMS", "apk add --no-network", "candidate-classification=\"local-candidate-non-release\"", "candidate-apk-lock-digest=\"sha256:${APK_LOCK_SHA256}\""} {
		if !strings.Contains(candidateText, required) {
			t.Fatalf("Phase 6 candidate Dockerfile missing %q", required)
		}
	}
	if strings.Contains(candidateText, "apk fetch --recursive") || strings.Contains(candidateText, "apk update") {
		t.Fatal("Phase 6 candidate Dockerfile re-resolves live package dependencies")
	}
	candidateBuild, err := os.ReadFile("build-phase6-locked.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"go1.26.8", "stage-desktop-phase6-apks", "--network none", "--no-cache", "APK_LOCK_SHA256"} {
		if !strings.Contains(string(candidateBuild), required) {
			t.Fatalf("Phase 6 candidate build missing %q", required)
		}
	}
	candidateRecord, err := os.ReadFile("build-phase6-candidate.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(candidateRecord), "status --porcelain --untracked-files=all") {
		t.Fatal("candidate recording does not reject a dirty source tree")
	}
	for platform, source := range manifest.Source.Manifests {
		path, err := APKLockPath(platform)
		if err != nil {
			t.Fatal(err)
		}
		lock, err := LoadAPKLock(path)
		if err != nil || lock.ArchiveDigest != source.PackageArchiveSetDigest || lock.InstalledDigest != source.InstalledSetDigest || lock.BaseImageDigest != source.Digest {
			t.Fatalf("candidate manifest and %s lock drift: %v", platform, err)
		}
	}
}

func TestPublicationWorkflowIsManualNativeAndIndependentlyVerified(t *testing.T) {
	manifest, err := LoadPhase5ProductionRelease(Phase5ProductionReleaseManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := os.ReadFile(PublicationWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		"  workflow_dispatch:",
		"if: github.ref == 'refs/heads/main'",
		"runner: ubuntu-24.04",
		"runner: ubuntu-24.04-arm",
		"go-version: 1.26.5",
		manifest.Source.Manifests["linux/amd64"].Digest,
		manifest.Source.Manifests["linux/arm64/v8"].Digest,
		"./profiles/desktop/image/build.sh",
		"SANDBOX_RUNTIME_DESKTOP_IMAGE_INTEGRATION",
		"actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
		"independent-verify:",
		"needs: publish-index",
		"gh attestation verify",
		"--signer-workflow",
		"--source-digest",
		"--deny-self-hosted-runners",
		"sha-${{ github.sha }}",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("publication workflow missing %q", required)
		}
	}
	for _, forbidden := range []string{"\n  push:\n", "\n  pull_request:\n", "sandbox-runtime-desktop:latest", "qemu"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("publication workflow contains forbidden trigger or build mode %q", forbidden)
		}
	}
}

func TestParseRejectsUnknownTrailingAndOversizedInput(t *testing.T) {
	data, err := os.ReadFile(LocalCandidateManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"unknown":   append(data[:len(data)-2], []byte(`,"unknown":true}`)...),
		"trailing":  append(data, []byte("{}")...),
		"oversized": []byte(strings.Repeat("x", MaxManifestBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(candidate); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Parse() error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func copyPlatforms(input map[string]Platform) map[string]Platform {
	output := make(map[string]Platform, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func copyOutputs(input map[string]Output) map[string]Output {
	output := make(map[string]Output, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
