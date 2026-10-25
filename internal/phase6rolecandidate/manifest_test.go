package phase6rolecandidate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
)

func TestDecodeCanonicalManifestRejectsNoncanonicalAndDrift(t *testing.T) {
	m := Manifest{Schema: ManifestSchema, Classification: ManifestClassification,
		Source: SourceInputs{Deployment: "product-runtime", BuildTarget: "core"}}
	m.ManifestDigest = m.digest()
	document, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeCanonicalManifest(document); err != nil || decoded.ManifestDigest != m.ManifestDigest {
		t.Fatalf("canonical manifest rejected: %v", err)
	}
	for name, candidate := range map[string][]byte{
		"whitespace":     append(append([]byte(nil), document...), '\n'),
		"unknown":        bytes.Replace(document, []byte(`"schema":`), []byte(`"extra":1,"schema":`), 1),
		"duplicate":      bytes.Replace(document, []byte(`"schema":`), []byte(`"schema":"shadow","schema":`), 1),
		"digest drift":   bytes.Replace(document, []byte(`"build_target":"core"`), []byte(`"build_target":"other"`), 1),
		"classification": bytes.Replace(document, []byte(ManifestClassification), []byte("production-release"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCanonicalManifest(candidate); err == nil {
				t.Fatal("invalid manifest admitted")
			}
		})
	}
}

func TestRoleConfigRejectsUnreviewedBuildRecipes(t *testing.T) {
	for _, target := range []string{"unknown", "../core", "provider-artifact-scanner",
		"provider-docker-control-bootstrap-v1", phase6fdloader.ControlDeliveryTarget,
		phase6fdloader.ControlSourceTarget, phase6fdloader.ControlTrustTarget} {
		t.Run(target, func(t *testing.T) {
			source := SourceInputs{BuildTarget: target, SourceRevision: strings.Repeat("a", 40)}
			entrypoint := []string{phase6fdloader.RolePath}
			if _, ok := phase6fdloader.SpecificationFor(target); ok {
				entrypoint = []string{"/bin/sh", "-ec", phase6fdloader.FixedEntrypointCommand}
			}
			document, err := json.Marshal(map[string]any{"config": map[string]any{
				"User": "65532:65532", "Entrypoint": entrypoint,
				"Labels": map[string]string{
					"io.github.shell-echo.sandbox-runtime.phase6-candidate": "local-only-non-release",
					"io.github.shell-echo.sandbox-runtime.source-revision":  source.SourceRevision,
					"io.github.shell-echo.sandbox-runtime.role-target":      target,
					"io.github.shell-echo.sandbox-runtime.go-version":       "go1.26.8",
				},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if validRoleConfig(document, source) {
				t.Fatal("matching labels admitted an unsupported build recipe")
			}
		})
	}
}

func TestPrivateManifestRequiresPrivateDirectoryAndExclusiveCreate(t *testing.T) {
	private := t.TempDir()
	path := filepath.Join(private, "candidate.json")
	if info, err := os.Lstat(private); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(private, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	m := Manifest{Schema: ManifestSchema, Classification: ManifestClassification}
	m.ManifestDigest = m.digest()
	if err := m.WritePrivate(path); err != nil {
		t.Fatal(err)
	}
	if err := m.WritePrivate(path); err == nil {
		t.Fatal("existing candidate overwritten")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %v, %v", info, err)
	}
	if _, err := LoadCurrent(context.Background(), private, path); err == nil {
		t.Fatal("missing archive/source was admitted")
	}
	if err := os.Chmod(private, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.WritePrivate(filepath.Join(private, "public.json")); err == nil {
		t.Fatal("public parent admitted")
	}
	if !strings.HasPrefix(m.ManifestDigest, "sha256:") {
		t.Fatal("manifest digest missing")
	}
}

func TestRoleConfigBindsSourceTargetAndDefaultIdentity(t *testing.T) {
	source := SourceInputs{SourceRevision: strings.Repeat("a", 40), BuildTarget: "core"}
	config := []byte(`{"config":{"User":"65532:65532","Entrypoint":["/usr/local/bin/phase6-role"],"Labels":{"io.github.shell-echo.sandbox-runtime.phase6-candidate":"local-only-non-release","io.github.shell-echo.sandbox-runtime.source-revision":"` + source.SourceRevision + `","io.github.shell-echo.sandbox-runtime.role-target":"core","io.github.shell-echo.sandbox-runtime.go-version":"go1.26.8"}}}`)
	if !validRoleConfig(config, source) {
		t.Fatal("valid role config rejected")
	}
	for _, changed := range []SourceInputs{
		{SourceRevision: strings.Repeat("b", 40), BuildTarget: "core"},
		{SourceRevision: source.SourceRevision, BuildTarget: "gateway"},
	} {
		if validRoleConfig(config, changed) {
			t.Fatal("source or target drift admitted")
		}
	}
	if validRoleConfig(bytes.Replace(config, []byte("65532:65532"), []byte("0:0"), 1), source) {
		t.Fatal("root default user admitted")
	}
	fdSource := SourceInputs{SourceRevision: source.SourceRevision, BuildTarget: "certificate-controller"}
	fdConfig := bytes.Replace(config, []byte(`role-target":"core"`), []byte(`role-target":"certificate-controller"`), 1)
	fdConfig = bytes.Replace(fdConfig, []byte(`"Entrypoint":["/usr/local/bin/phase6-role"]`),
		[]byte(`"Entrypoint":["/bin/sh","-ec","exec 3</dev/null 4</dev/null 5</dev/null 6</dev/null; exec /usr/local/bin/phase6-fd-loader"]`), 1)
	if !validRoleConfig(fdConfig, fdSource) || validRoleConfig(config, fdSource) || validRoleConfig(fdConfig, source) {
		t.Fatal("FD-loader entrypoint did not bind exactly to its source target")
	}
}
