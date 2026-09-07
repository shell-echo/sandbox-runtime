package contractlock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testContractManifest = `{"license":"MIT","namespace":"urn:shell-echo:sandbox-runtime:provider-v1","version":"1.0.0","resources":[{"path":"openapi/sandbox-provider-v1.yaml","kind":"openapi","id":"urn:test:openapi"},{"path":"semantic-rules/provider-v1.json","kind":"semantic-rules","id":"urn:test:semantic-rules"},{"path":"fixtures/capabilities.json","kind":"fixture","id":"urn:test:fixture"},{"path":"conformance/sandbox/v1/suite.json","kind":"conformance-suite","id":"urn:test:suite"}]}`

func TestVerifyAcceptsEquivalentCleanContractTree(t *testing.T) {
	source := t.TempDir()
	writeContractFixture(t, source)
	writeTestFile(t, source, "contract/openapi/sandbox-provider-v1.yaml", "openapi: 3.1.1\n")
	runGit(t, source, "init")
	runGit(t, source, "config", "user.name", "Contract Lock Test")
	runGit(t, source, "config", "user.email", "contract-lock@example.invalid")
	runGit(t, source, "remote", "add", "origin", "https://example.invalid/agent")
	runGit(t, source, "add", "contract")
	runGit(t, source, "commit", "-m", "add contract")
	revision := runGit(t, source, "rev-parse", "HEAD")
	tree := runGit(t, source, "rev-parse", "HEAD:contract")

	lock := testLock(revision, tree, digestString([]byte("openapi: 3.1.1\n")))
	report, err := Verify(context.Background(), lock, source)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.ContractTree != tree || report.CheckoutHead != revision {
		t.Fatalf("report = %+v", report)
	}

	writeTestFile(t, source, "README.md", "later unrelated commit\n")
	runGit(t, source, "add", "README.md")
	runGit(t, source, "commit", "-m", "unrelated change")
	if _, err := Verify(context.Background(), lock, source); err != nil {
		t.Fatalf("Verify equivalent later tree: %v", err)
	}
}

func TestVerifyRejectsDirtyContract(t *testing.T) {
	source := t.TempDir()
	writeContractFixture(t, source)
	writeTestFile(t, source, "contract/openapi/sandbox-provider-v1.yaml", "openapi: 3.1.1\n")
	runGit(t, source, "init")
	runGit(t, source, "config", "user.name", "Contract Lock Test")
	runGit(t, source, "config", "user.email", "contract-lock@example.invalid")
	runGit(t, source, "remote", "add", "origin", "https://example.invalid/agent.git")
	runGit(t, source, "add", "contract")
	runGit(t, source, "commit", "-m", "add contract")
	revision := runGit(t, source, "rev-parse", "HEAD")
	tree := runGit(t, source, "rev-parse", "HEAD:contract")
	lock := testLock(revision, tree, digestString([]byte("openapi: 3.1.1\n")))

	writeTestFile(t, source, "contract/openapi/sandbox-provider-v1.yaml", "openapi: 3.0.0\n")
	if _, err := Verify(context.Background(), lock, source); err == nil || !strings.Contains(err.Error(), "uncommitted changes") {
		t.Fatalf("Verify dirty Contract = %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	if err := os.WriteFile(path, []byte(`{"format_version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Load = %v", err)
	}
}

func TestLockRejectsResourceOutsideContractRoot(t *testing.T) {
	lock := testLock(strings.Repeat("c", 40), strings.Repeat("d", 40), "sha256:"+strings.Repeat("e", 64))
	lock.Contract.OpenAPIPath = "blueprint/openapi/sandbox-provider-v1.yaml"
	if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), "inside the Contract root") {
		t.Fatalf("Validate = %v", err)
	}
}

func TestReadContractManifestRejectsUnknownFields(t *testing.T) {
	for _, test := range []struct {
		name     string
		contents string
	}{
		{name: "top level", contents: `{"namespace":"n","version":"1","license":"MIT","resources":[],"unknown":true}`},
		{name: "resource", contents: `{"namespace":"n","version":"1","license":"MIT","resources":[{"path":"a","kind":"fixture","id":"i","unknown":true}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readContractManifest(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("readContractManifest = %v", err)
			}
		})
	}
}

func TestValidateContractManifestResources(t *testing.T) {
	root := t.TempDir()
	valid := make([]contractManifestResource, 0, len(manifestKinds))
	for _, kind := range []string{"specification", "openapi", "json-schema", "semantic-rules", "fixture", "conformance-suite"} {
		path := kind + ".json"
		writeTestFile(t, root, path, `{}`)
		valid = append(valid, contractManifestResource{Path: path, Kind: kind, ID: "urn:test:" + kind})
	}
	if err := validateContractManifestResources(root, valid); err != nil {
		t.Fatalf("validate valid resources: %v", err)
	}

	directory := "directory"
	if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		resources []contractManifestResource
		want      string
	}{
		{name: "empty resources", want: "must not be empty"},
		{name: "empty path", resources: []contractManifestResource{{Kind: "fixture", ID: "urn:test:a"}}, want: "must not be empty"},
		{name: "empty kind", resources: []contractManifestResource{{Path: "fixture.json", ID: "urn:test:a"}}, want: "must not be empty"},
		{name: "empty id", resources: []contractManifestResource{{Path: "fixture.json", Kind: "fixture"}}, want: "must not be empty"},
		{name: "blank id", resources: []contractManifestResource{{Path: "fixture.json", Kind: "fixture", ID: " \t"}}, want: "must not be empty"},
		{name: "unclean path", resources: []contractManifestResource{{Path: "dir/../fixture.json", Kind: "fixture", ID: "urn:test:a"}}, want: "clean relative slash path"},
		{name: "absolute path", resources: []contractManifestResource{{Path: "/fixture.json", Kind: "fixture", ID: "urn:test:a"}}, want: "clean relative slash path"},
		{name: "unsupported kind", resources: []contractManifestResource{{Path: "fixture.json", Kind: "document", ID: "urn:test:a"}}, want: "unsupported kind"},
		{name: "duplicate path", resources: []contractManifestResource{{Path: "fixture.json", Kind: "fixture", ID: "urn:test:a"}, {Path: "fixture.json", Kind: "fixture", ID: "urn:test:b"}}, want: "duplicates path"},
		{name: "duplicate id", resources: []contractManifestResource{{Path: "fixture.json", Kind: "fixture", ID: "urn:test:a"}, {Path: "openapi.json", Kind: "openapi", ID: "urn:test:a"}}, want: "duplicates id"},
		{name: "missing file", resources: []contractManifestResource{{Path: "missing.json", Kind: "fixture", ID: "urn:test:a"}}, want: "resolve Contract manifest resource"},
		{name: "not regular", resources: []contractManifestResource{{Path: directory, Kind: "fixture", ID: "urn:test:a"}}, want: "not a regular file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateContractManifestResources(root, test.resources); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateContractManifestResources = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateContractManifestResourcesRejectsSymlinkOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "contract")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, parent, "outside.json", `{}`)
	if err := os.Symlink(filepath.Join(parent, "outside.json"), filepath.Join(root, "resource.json")); err != nil {
		t.Fatal(err)
	}
	resources := []contractManifestResource{{Path: "resource.json", Kind: "fixture", ID: "urn:test:resource"}}
	if err := validateContractManifestResources(root, resources); err == nil || !strings.Contains(err.Error(), "escapes the source root") {
		t.Fatalf("validateContractManifestResources = %v", err)
	}
}

func TestValidateContractManifestResourcesRejectsSymlinkFile(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "target.json", `{}`)
	if err := os.Symlink("target.json", filepath.Join(root, "resource.json")); err != nil {
		t.Fatal(err)
	}
	resources := []contractManifestResource{{Path: "resource.json", Kind: "fixture", ID: "urn:test:resource"}}
	if err := validateContractManifestResources(root, resources); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("validateContractManifestResources = %v", err)
	}
}

func testLock(revision, tree, openAPIDigest string) Lock {
	return Lock{
		FormatVersion: 1,
		Source: Source{
			Repository:   "https://example.invalid/agent.git",
			Revision:     revision,
			ContractTree: tree,
		},
		Contract: Contract{
			Root:                "contract",
			Namespace:           "urn:shell-echo:sandbox-runtime:provider-v1",
			Version:             "1.0.0",
			License:             "MIT",
			ManifestPath:        "contract/compatibility/contract-manifest.json",
			ManifestDigest:      digestString([]byte(testContractManifest)),
			OpenAPIPath:         "contract/openapi/sandbox-provider-v1.yaml",
			OpenAPISHA256:       openAPIDigest,
			SemanticRulesPath:   "contract/semantic-rules/provider-v1.json",
			SemanticRulesSHA256: digestString([]byte(`{"namespace":"urn:shell-echo:sandbox-runtime:provider-v1","version":"1.0.0","rules":[{}]}`)),
			FixturesRoot:        "contract/fixtures",
		},
		SandboxSuite: SandboxSuite{
			Path:            "contract/conformance/sandbox/v1/suite.json",
			SuiteID:         "sandbox-provider",
			SuiteVersion:    "1.0.0",
			SuiteDigest:     "sha256:" + strings.Repeat("b", 64),
			RequiredProfile: "sandbox-runtime-provider-v1",
		},
	}
}

func writeContractFixture(t *testing.T, source string) {
	t.Helper()
	writeTestFile(t, source, "contract/compatibility/contract-manifest.json", testContractManifest)
	writeTestFile(t, source, "contract/semantic-rules/provider-v1.json", `{"namespace":"urn:shell-echo:sandbox-runtime:provider-v1","version":"1.0.0","rules":[{}]}`)
	writeTestFile(t, source, "contract/fixtures/capabilities.json", `{}`)
	writeTestFile(t, source, "contract/conformance/sandbox/v1/suite.json", `{"suite_id":"sandbox-provider","suite_version":"1.0.0","suite_digest":"sha256:`+strings.Repeat("b", 64)+`","profiles":[{"profile_id":"sandbox-runtime-provider-v1"}]}`)
}

func writeTestFile(t *testing.T, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func digestString(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}
