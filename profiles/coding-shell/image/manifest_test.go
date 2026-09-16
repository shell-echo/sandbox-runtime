package image

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestManifestIsStrictAndComplete(t *testing.T) {
	manifest, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if manifest.Source.Manifests["linux/arm64/v8"].Digest != "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c" {
		t.Fatal("arm64 source manifest is not locked")
	}
}

func TestManifestRejectsUnsafeChanges(t *testing.T) {
	base, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Manifest){
		"mutable source": func(m *Manifest) { m.Source.IndexDigest = "" },
		"extra platform": func(m *Manifest) {
			m.Source.Manifests["linux/386"] = Platform{Digest: "sha256:" + strings.Repeat("0", 64), Architecture: "386"}
		},
		"root user":           func(m *Manifest) { m.Security.UID = 0 },
		"writable root":       func(m *Manifest) { m.Security.RootFilesystem = "writable" },
		"writable inputs":     func(m *Manifest) { m.Mounts[0].Mode = "rw" },
		"network enabled":     func(m *Manifest) { m.Network.Mode = "bridge" },
		"shell changed":       func(m *Manifest) { m.Runtime.ShellPath = "/bin/bash" },
		"broker moved":        func(m *Manifest) { m.Runtime.TerminalBrokerPath = "/workspace/broker" },
		"attestation omitted": func(m *Manifest) { m.Provenance.AttestationRequiredBeforeQualification = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Source.Manifests = copyPlatforms(base.Source.Manifests)
			candidate.Mounts = append([]Mount(nil), base.Mounts...)
			candidate.Runtime.Command = append([]string(nil), base.Runtime.Command...)
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestBuildDefinitionKeepsRuntimeBoundary(t *testing.T) {
	manifest, err := Load(ManifestPath)
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
		"FROM scratch",
		"COPY --chmod=0555 terminal-broker " + TerminalBrokerPath,
		"find / -xdev -type d",
		"USER 65532:65532",
		"WORKDIR /workspace",
		"CMD [\"/bin/sh\"",
	} {
		if !strings.Contains(dockerText, required) {
			t.Fatalf("Dockerfile missing %q", required)
		}
	}
	for _, forbidden := range []string{"apk add", "EXPOSE ", "0.0.0.0", "latest"} {
		if strings.Contains(dockerText, forbidden) {
			t.Fatalf("Dockerfile contains forbidden value %q", forbidden)
		}
	}
	script, err := os.ReadFile(BuildScriptPath)
	if err != nil {
		t.Fatal(err)
	}
	scriptText := string(script)
	for _, required := range []string{
		"CGO_ENABLED=0 GOOS=linux GOARCH=\"$goarch\"",
		"go_version=$(go env GOVERSION)",
		"go1.26.5",
		"-trimpath -buildvcs=false -ldflags=-buildid=",
		"--provenance=false",
		"SOURCE_DATE_EPOCH=0",
		manifest.Source.Manifests["linux/amd64"].Digest,
		manifest.Source.Manifests["linux/arm64/v8"].Digest,
	} {
		if !strings.Contains(scriptText, required) {
			t.Fatalf("build script missing %q", required)
		}
	}
}

func TestPublicationWorkflowIsManualPinnedNativeAndAttested(t *testing.T) {
	manifest, err := Load(ManifestPath)
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
		"SANDBOX_RUNTIME_CODING_SHELL_IMAGE_INTEGRATION",
		"push-by-digest=true",
		`{"architecture":"arm64","os":"linux","variant":"v8"}`,
		"sha-${{ github.sha }}",
		"actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
		"--signer-workflow",
		"--source-digest",
		"--deny-self-hosted-runners",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("publication workflow missing %q", required)
		}
	}
	for _, forbidden := range []string{"\n  push:\n", "\n  pull_request:\n", "sandbox-runtime-coding-shell:latest", "qemu"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("publication workflow contains forbidden trigger or build mode %q", forbidden)
		}
	}
}

func TestParseRejectsUnknownAndTrailingInput(t *testing.T) {
	data, err := os.ReadFile(ManifestPath)
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
