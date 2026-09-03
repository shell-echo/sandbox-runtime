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
		"unrestricted network":     func(m *Manifest) { m.Network.Mode = "none" },
		"missing attestation gate": func(m *Manifest) { m.Provenance.AttestationRequiredBeforeAdvertisement = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Source.Manifests = copyPlatforms(base.Source.Manifests)
			candidate.Mounts = append([]Mount(nil), base.Mounts...)
			candidate.Launch.Arguments = append([]string(nil), base.Launch.Arguments...)
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
	for _, required := range []string{"BROWSER_RUNTIME_ALLOW_UNSANDBOXED", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=9222", "if [ \"$#\" -ne 0 ]"} {
		if !strings.Contains(entrypointText, required) {
			t.Fatalf("entrypoint missing %q", required)
		}
	}
	if strings.Contains(entrypointText, "0.0.0.0") || strings.Contains(entrypointText, "socat") {
		t.Fatal("entrypoint contains an unsafe endpoint forwarder")
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
