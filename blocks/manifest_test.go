package blocks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseAcceptsEquivalentYAMLAndJSON(t *testing.T) {
	yamlDocument := []byte(`apiVersion: sandbox.runtime/v1alpha1
kind: Block
metadata:
  name: browser-chrome
  version: 1.0.0
  description: Chromium block
runtime:
  runtime_profile: sandbox-runtime-browser-v1
  image: registry.example.invalid/runtime/browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  command: ["/usr/bin/chromium", "--headless"]
  working_directory: /workspace
capabilities:
  - id: sandbox.browser
    version: 1.0.0
    profile: browser-v1
`)
	jsonDocument := []byte(`{"apiVersion":"sandbox.runtime/v1alpha1","kind":"Block","metadata":{"name":"browser-chrome","version":"1.0.0","description":"Chromium block"},"runtime":{"runtime_profile":"sandbox-runtime-browser-v1","image":"registry.example.invalid/runtime/browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":["/usr/bin/chromium","--headless"],"working_directory":"/workspace"},"capabilities":[{"id":"sandbox.browser","version":"1.0.0","profile":"browser-v1"}]}`)

	fromYAML, err := Parse(yamlDocument)
	if err != nil {
		t.Fatalf("Parse YAML: %v", err)
	}
	fromJSON, err := Parse(jsonDocument)
	if err != nil {
		t.Fatalf("Parse JSON: %v", err)
	}
	if !reflect.DeepEqual(fromYAML, fromJSON) {
		t.Fatalf("YAML manifest = %#v, JSON manifest = %#v", fromYAML, fromJSON)
	}
}

func TestParseRejectsMalformedOrUnsafeManifest(t *testing.T) {
	tests := map[string]func(*Manifest){
		"wrong api version":  func(m *Manifest) { m.APIVersion = "sandbox.runtime/v1" },
		"wrong kind":         func(m *Manifest) { m.Kind = "Runtime" },
		"invalid block name": func(m *Manifest) { m.Metadata.Name = "Browser_Chrome" },
		"invalid version":    func(m *Manifest) { m.Metadata.Version = "v1" },
		"unpinned image":     func(m *Manifest) { m.Runtime.Image = "registry.example.invalid/runtime/browser:latest" },
		"unsafe workdir":     func(m *Manifest) { m.Runtime.WorkingDirectory = "/workspace/../tmp" },
		"outside workdir":    func(m *Manifest) { m.Runtime.WorkingDirectory = "/etc" },
		"duplicate capability": func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, m.Capabilities[0])
		},
		"empty argument": func(m *Manifest) { m.Runtime.Command = []string{""} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest()
			mutate(&manifest)
			if err := manifest.Validate(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
			}
		})
	}

	for name, document := range map[string][]byte{
		"unknown field": []byte(`apiVersion: sandbox.runtime/v1alpha1
kind: Block
metadata:
  name: shell
  version: 1.0.0
runtime:
  runtime_profile: sandbox-runtime-shell-v1
  image: registry.example.invalid/runtime/shell@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
capabilities:
  - id: sandbox.exec
    version: 1.0.0
unexpected: true
`),
		"multiple documents": append(validManifestYAML(), []byte("---\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := func() error { _, err := Parse(document); return err }(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Parse() error = %v, want ErrInvalidManifest", err)
			}
		})
	}

	if _, err := Parse([]byte(strings.Repeat("x", MaxManifestBytes+1))); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("oversized Parse() error = %v, want ErrInvalidManifest", err)
	}
}

func TestNewRegistryReturnsSortedDefensiveCopies(t *testing.T) {
	input := []Manifest{validManifestNamed("zulu"), validManifestNamed("alpha")}
	registry, err := NewRegistry(input)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	input[0].Runtime.Command[0] = "mutated"
	input[0].Capabilities[0].ID = "mutated"

	list := registry.List()
	if got := []string{list[0].Metadata.Name, list[1].Metadata.Name}; !reflect.DeepEqual(got, []string{"alpha", "zulu"}) {
		t.Fatalf("List names = %v", got)
	}
	list[0].Runtime.Command[0] = "mutated"
	list[0].Capabilities[0].ID = "mutated"
	got, ok := registry.Get("alpha")
	if !ok || got.Runtime.Command[0] == "mutated" || got.Capabilities[0].ID == "mutated" {
		t.Fatalf("Get returned mutable or missing manifest: ok=%t manifest=%#v", ok, got)
	}
	if _, ok := registry.Get("missing"); ok {
		t.Fatal("Get found missing manifest")
	}
}

func TestRegistryRejectsDuplicatesAndBounds(t *testing.T) {
	manifest := validManifest()
	if _, err := NewRegistry([]Manifest{manifest, manifest}); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("duplicate registry error = %v, want ErrInvalidRegistry", err)
	}
	tooMany := make([]Manifest, MaxManifestCount+1)
	for index := range tooMany {
		tooMany[index] = validManifestNamed("block-" + strings.Repeat("a", index%3) + string(rune('a'+index%26)))
	}
	if _, err := NewRegistry(tooMany); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("oversized registry error = %v, want ErrInvalidRegistry", err)
	}
}

func TestLoadFileAndDirRejectUnsafeEntries(t *testing.T) {
	directory := t.TempDir()
	writeManifestFile(t, directory, "zulu.yaml", validManifestYAML())
	writeManifestFile(t, directory, "alpha.json", validManifestJSON("alpha"))
	if err := os.WriteFile(filepath.Join(directory, "README.md"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadDir(context.Background(), directory)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if got := len(registry.List()); got != 2 {
		t.Fatalf("LoadDir manifest count = %d, want 2", got)
	}

	nested := filepath.Join(directory, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(context.Background(), directory); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("nested LoadDir error = %v, want ErrInvalidRegistry", err)
	}

	if err := os.RemoveAll(nested); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "zulu.yaml"), filepath.Join(directory, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(context.Background(), directory); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("symlink LoadDir error = %v, want ErrInvalidRegistry", err)
	}
	if _, err := LoadFile(context.Background(), filepath.Join(directory, "link.yaml")); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("symlink LoadFile error = %v, want ErrInvalidManifest", err)
	}
}

func TestLoadHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadFile(ctx, filepath.Join(t.TempDir(), "missing.yaml")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled LoadFile error = %v, want context.Canceled", err)
	}
	if _, err := LoadDir(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled LoadDir error = %v, want context.Canceled", err)
	}
	if _, err := LoadFile(nil, "manifest.yaml"); err == nil {
		t.Fatal("nil LoadFile context accepted")
	}
}

func validManifest() Manifest { return validManifestNamed("shell") }

func validManifestNamed(name string) Manifest {
	return Manifest{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata:   Metadata{Name: name, Version: "1.0.0"},
		Runtime: RuntimeSpec{
			RuntimeProfile:   "sandbox-runtime-shell-v1",
			Image:            "registry.example.invalid/runtime/shell@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Command:          []string{"/bin/sh"},
			WorkingDirectory: "/workspace",
		},
		Capabilities: []Capability{{ID: "sandbox.exec", Version: "1.0.0", Profile: "exec-v1"}},
	}
}

func validManifestYAML() []byte {
	return validManifestYAMLNamed("shell")
}

func validManifestYAMLNamed(name string) []byte {
	return []byte("apiVersion: sandbox.runtime/v1alpha1\nkind: Block\nmetadata:\n  name: " + name + "\n  version: 1.0.0\nruntime:\n  runtime_profile: sandbox-runtime-shell-v1\n  image: registry.example.invalid/runtime/shell@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  command: [\"/bin/sh\"]\n  working_directory: /workspace\ncapabilities:\n  - id: sandbox.exec\n    version: 1.0.0\n    profile: exec-v1\n")
}

func validManifestJSON(name string) []byte {
	return []byte(`{"apiVersion":"sandbox.runtime/v1alpha1","kind":"Block","metadata":{"name":"` + name + `","version":"1.0.0"},"runtime":{"runtime_profile":"sandbox-runtime-shell-v1","image":"registry.example.invalid/runtime/shell@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":["/bin/sh"],"working_directory":"/workspace"},"capabilities":[{"id":"sandbox.exec","version":"1.0.0","profile":"exec-v1"}]}`)
}

func writeManifestFile(t *testing.T, directory, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
}
