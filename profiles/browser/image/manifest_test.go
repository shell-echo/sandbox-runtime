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
	if got := manifest.Source.Manifests["linux/arm64/v8"].Digest; got != "sha256:2fc473f3f926ccae8dbfedf60897937dece94ff7bbdfab20457ebfc732c2b162" {
		t.Fatalf("arm64 source digest = %q", got)
	}
}

func TestManifestRejectsUnsafeChanges(t *testing.T) {
	base, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Manifest){
		"mutable source":           func(m *Manifest) { m.Source.Repository = "docker.io/chromedp/headless-shell:latest" },
		"public endpoint":          func(m *Manifest) { m.Browser.Endpoint.Public = true },
		"non-loopback endpoint":    func(m *Manifest) { m.Browser.Endpoint.Address = "0.0.0.0" },
		"user override":            func(m *Manifest) { m.Launch.UserArguments = "accepted" },
		"root user":                func(m *Manifest) { m.Security.UID = 0 },
		"writable root":            func(m *Manifest) { m.Security.RootFilesystem = "writable" },
		"sandbox disabled":         func(m *Manifest) { m.Security.BrowserSandbox = "disabled" },
		"seccomp digest changed":   func(m *Manifest) { m.Security.SeccompProfile.Digest = "sha256:" + strings.Repeat("0", 64) },
		"unrestricted network":     func(m *Manifest) { m.Network.Mode = "none" },
		"missing attestation gate": func(m *Manifest) { m.Provenance.AttestationRequiredBeforeAdvertisement = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Source.Manifests = copyPlatforms(base.Source.Manifests)
			candidate.Mounts = append([]Mount(nil), base.Mounts...)
			candidate.Launch.Arguments = append([]string(nil), base.Launch.Arguments...)
			candidate.Security.SeccompProfile.AllowedSandboxSyscalls = append([]string(nil), base.Security.SeccompProfile.AllowedSandboxSyscalls...)
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestDockerfileAndEntrypointKeepBoundary(t *testing.T) {
	dockerfile, err := os.ReadFile(DockerfilePath)
	if err != nil {
		t.Fatal(err)
	}
	dockerText := string(dockerfile)
	for _, required := range []string{
		"FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST}",
		"FROM scratch",
		"RUN find / -xdev -type d",
		"! -path '/proc*'",
		"ARG SOURCE_DATE_EPOCH=0",
		"USER 1000:1000",
		"ENTRYPOINT [\"/usr/local/bin/browser-runtime\"]",
	} {
		if !strings.Contains(dockerText, required) {
			t.Fatalf("Dockerfile missing %q", required)
		}
	}
	if strings.Contains(dockerText, "EXPOSE ") {
		t.Fatal("Dockerfile contains a public endpoint declaration")
	}
	entrypoint, err := os.ReadFile(EntrypointPath)
	if err != nil {
		t.Fatal(err)
	}
	entrypointText := string(entrypoint)
	for _, required := range []string{"--remote-debugging-address=127.0.0.1", "--remote-debugging-port=9222", "if [ \"$#\" -ne 0 ]"} {
		if !strings.Contains(entrypointText, required) {
			t.Fatalf("entrypoint missing %q", required)
		}
	}
	if strings.Contains(entrypointText, "0.0.0.0") || strings.Contains(entrypointText, "socat") || strings.Contains(entrypointText, "--no-sandbox") || strings.Contains(entrypointText, "ALLOW_UNSANDBOXED") {
		t.Fatal("entrypoint contains an unsafe endpoint forwarder")
	}
}

func TestSeccompProfileIsPinnedAndFailClosed(t *testing.T) {
	manifest, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySeccompProfile("chromium-seccomp.json", manifest.Security.SeccompProfile.Digest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("chromium-seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	unsafe := strings.Replace(string(data), `"defaultAction": "SCMP_ACT_ERRNO"`, `"defaultAction": "SCMP_ACT_ALLOW"`, 1)
	path := t.TempDir() + "/unsafe-seccomp.json"
	if err := os.WriteFile(path, []byte(unsafe), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySeccompProfile(path, manifest.Security.SeccompProfile.Digest); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("VerifySeccompProfile() error = %v, want ErrInvalidManifest", err)
	}
}

func TestPublicationWorkflowIsManualPinnedAndManifestBound(t *testing.T) {
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
		manifest.Source.Manifests["linux/amd64"].Digest,
		manifest.Source.Manifests["linux/arm64/v8"].Digest,
		"runner: ubuntu-24.04",
		"runner: ubuntu-24.04-arm",
		"SANDBOX_RUNTIME_BROWSER_IMAGE_INTEGRATION",
		"push-by-digest=true",
		`touch "${RUNNER_TEMP}/digests/${PLATFORM_ID}-${digest}"`,
		`{"architecture":"arm64","os":"linux","variant":"v8"}`,
		"descriptor_args+=(--file",
		".manifests | map(.platform)",
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
	for _, forbidden := range []string{"\n  push:\n", "\n  pull_request:\n", "sandbox-runtime-browser:latest"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("publication workflow contains forbidden trigger or tag %q", forbidden)
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
