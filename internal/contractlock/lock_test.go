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

func TestVerifyAcceptsEquivalentCleanContractTree(t *testing.T) {
	source := t.TempDir()
	writeTestFile(t, source, "contract/compatibility/contract-manifest.json", `{"manifest_digest":"sha256:`+strings.Repeat("a", 64)+`"}`)
	writeTestFile(t, source, "contract/openapi/sandbox-provider-v1.yaml", "openapi: 3.1.1\n")
	writeTestFile(t, source, "contract/conformance/sandbox/v1/suite.json", `{"suite_id":"sandbox-provider","suite_version":"1.0.0","suite_digest":"sha256:`+strings.Repeat("b", 64)+`","profiles":[{"profile_id":"sandbox-core-v1"}]}`)
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
	writeTestFile(t, source, "contract/compatibility/contract-manifest.json", `{"manifest_digest":"sha256:`+strings.Repeat("a", 64)+`"}`)
	writeTestFile(t, source, "contract/openapi/sandbox-provider-v1.yaml", "openapi: 3.1.1\n")
	writeTestFile(t, source, "contract/conformance/sandbox/v1/suite.json", `{"suite_id":"sandbox-provider","suite_version":"1.0.0","suite_digest":"sha256:`+strings.Repeat("b", 64)+`","profiles":[{"profile_id":"sandbox-core-v1"}]}`)
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

func testLock(revision, tree, openAPIDigest string) Lock {
	return Lock{
		FormatVersion: 1,
		Source: Source{
			Repository:   "https://example.invalid/agent.git",
			Revision:     revision,
			ContractTree: tree,
		},
		Contract: Contract{
			Root:           "contract",
			License:        "LicenseRef-Proprietary",
			Consumption:    "read-only-checkout",
			ManifestPath:   "contract/compatibility/contract-manifest.json",
			ManifestDigest: "sha256:" + strings.Repeat("a", 64),
			OpenAPIPath:    "contract/openapi/sandbox-provider-v1.yaml",
			OpenAPISHA256:  openAPIDigest,
		},
		SandboxSuite: SandboxSuite{
			Path:            "contract/conformance/sandbox/v1/suite.json",
			SuiteID:         "sandbox-provider",
			SuiteVersion:    "1.0.0",
			SuiteDigest:     "sha256:" + strings.Repeat("b", 64),
			RequiredProfile: "sandbox-core-v1",
		},
	}
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
