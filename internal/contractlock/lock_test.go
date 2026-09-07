package contractlock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/suitedigest"
)

const (
	testOpenAPI           = "openapi: 3.1.1\n"
	testSemanticRules     = `{"namespace":"urn:shell-echo:sandbox-runtime:provider-v1","version":"1.0.0","rules":[{}]}`
	testPlaceholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	testSandboxSuitePath = "contract/conformance/provider-v1/suite.json"
	testRemoteSuitePath  = "contract/conformance/provider-remote-v1/suite.json"
)

func TestVerifyAcceptsEquivalentCleanContractTree(t *testing.T) {
	source, lock, revision := prepareContractRepository(t, testContractManifest("conformance-suite", true, "conformance-suite"))

	report, err := Verify(context.Background(), lock, source)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	wantSandbox := VerifiedSuite{
		ID:            "sandbox-provider",
		Version:       "1.0.0",
		Digest:        lock.SandboxSuite.SuiteDigest,
		DigestProfile: suitedigest.DigestProfile,
		ProfileID:     "sandbox-runtime-provider-v1",
		Cases:         []string{"contract-metadata", "provider-discovery"},
	}
	wantRemote := VerifiedSuite{
		ID:            "sandbox-provider-remote",
		Version:       "1.0.0",
		Digest:        lock.ProviderRemoteSuite.SuiteDigest,
		DigestProfile: suitedigest.DigestProfile,
		ProfileID:     "sandbox-runtime-provider-remote-discovery-v1",
		Cases:         []string{"authenticated-discovery", "get-only-routing"},
	}
	if report.ContractTree != lock.Source.ContractTree || report.CheckoutHead != revision ||
		report.ContractNamespace != lock.Contract.Namespace || report.ContractVersion != lock.Contract.Version ||
		report.SuiteDigest != lock.SandboxSuite.SuiteDigest ||
		!reflect.DeepEqual(report.SandboxSuite, wantSandbox) || !reflect.DeepEqual(report.RemoteSuite, wantRemote) {
		t.Fatalf("report = %+v", report)
	}

	report.SandboxSuite.Cases[0] = "mutated"
	report.RemoteSuite.Cases[0] = "mutated"
	again, err := Verify(context.Background(), lock, source)
	if err != nil {
		t.Fatalf("Verify after mutating report snapshots: %v", err)
	}
	if !reflect.DeepEqual(again.SandboxSuite.Cases, wantSandbox.Cases) || !reflect.DeepEqual(again.RemoteSuite.Cases, wantRemote.Cases) {
		t.Fatalf("case snapshots were not defensive: sandbox=%v remote=%v", again.SandboxSuite.Cases, again.RemoteSuite.Cases)
	}

	writeTestFile(t, source, "README.md", "later unrelated commit\n")
	runGit(t, source, "add", "README.md")
	runGit(t, source, "commit", "-m", "unrelated change")
	if _, err := Verify(context.Background(), lock, source); err != nil {
		t.Fatalf("Verify equivalent later tree: %v", err)
	}
}

func TestVerifyWithGitExecutableRequiresAbsoluteRegularExecutable(t *testing.T) {
	for name, executable := range map[string]string{
		"relative":  "git",
		"directory": t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyWithGitExecutable(context.Background(), Lock{}, t.TempDir(), executable)
			if err == nil || !strings.Contains(err.Error(), "Git executable") {
				t.Fatalf("VerifyWithGitExecutable(%q) = %v", executable, err)
			}
		})
	}
}

func TestVerifyRejectsDirtyContract(t *testing.T) {
	source, lock, _ := prepareContractRepository(t, testContractManifest("conformance-suite", true, "conformance-suite"))

	writeTestFile(t, source, "contract/openapi/sandbox-provider-v1.yaml", "openapi: 3.0.0\n")
	if _, err := Verify(context.Background(), lock, source); err == nil || !strings.Contains(err.Error(), "uncommitted changes") {
		t.Fatalf("Verify dirty Contract = %v", err)
	}
}

func TestVerifyRejectsResourceDriftHiddenByAssumeUnchanged(t *testing.T) {
	source, lock, _ := prepareContractRepository(t, testContractManifest("conformance-suite", true, "conformance-suite"))
	const resource = "contract/fixtures/capabilities.json"
	writeTestFile(t, source, resource, `{"tampered":true}`)
	runGit(t, source, "update-index", "--assume-unchanged", resource)
	if dirty := runGit(t, source, "status", "--porcelain", "--", "contract"); dirty != "" {
		t.Fatalf("assume-unchanged fixture unexpectedly visible to status: %q", dirty)
	}
	if _, err := Verify(context.Background(), lock, source); err == nil || !strings.Contains(err.Error(), "differs from the locked Git blob") {
		t.Fatalf("Verify hidden resource drift = %v", err)
	}
}

func TestVerifiedResourceSnapshotIsDefensiveAndLockBound(t *testing.T) {
	source, lock, _ := prepareContractRepository(t, testContractManifest("conformance-suite", true, "conformance-suite"))
	report, err := Verify(context.Background(), lock, source)
	if err != nil {
		t.Fatal(err)
	}
	document, err := report.Resource(lock, lock.Contract.OpenAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(document) != testOpenAPI {
		t.Fatalf("OpenAPI snapshot = %q", document)
	}
	document[0] = 'X'
	again, err := report.Resource(lock, lock.Contract.OpenAPIPath)
	if err != nil || string(again) != testOpenAPI {
		t.Fatalf("defensive OpenAPI snapshot = %q, %v", again, err)
	}
	mismatched := lock
	mismatched.Source.Revision = strings.Repeat("f", 40)
	if _, err := report.Resource(mismatched, lock.Contract.OpenAPIPath); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched lock snapshot = %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	if err := os.WriteFile(path, []byte(`{"format_version":2,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Load = %v", err)
	}
}

func TestContractMetadataRejectsDuplicateJSONMembers(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "lock.json")
	if err := os.WriteFile(lockPath, []byte(`{"format_version":2,"format_version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(lockPath); err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
		t.Fatalf("Load duplicate member = %v", err)
	}

	manifest := []byte(`{"namespace":"n","namespace":"other","version":"1.0.0","license":"MIT","resources":[]}`)
	if _, err := decodeContractManifest(manifest); err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
		t.Fatalf("decodeContractManifest duplicate member = %v", err)
	}

	semantic := []byte(`{"rules":[{"id":"a","id":"b"}]}`)
	var destination map[string]any
	if err := decodeMetadata(semantic, &destination); err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
		t.Fatalf("decodeMetadata duplicate member = %v", err)
	}
}

func TestContractMetadataRejectsInvalidJSONUnicode(t *testing.T) {
	tests := []struct {
		name     string
		document []byte
		want     string
	}{
		{
			name:     "invalid UTF-8 in value",
			document: append([]byte(`{"duplicate":1,"duplicate":2,"value":"`), 0xff, '"', '}'),
			want:     "valid UTF-8",
		},
		{
			name:     "invalid UTF-8 in key",
			document: append([]byte(`{"duplicate":1,"duplicate":2,"`), 0xff, '"', ':', '1', '}'),
			want:     "valid UTF-8",
		},
		{
			name:     "lone high surrogate",
			document: []byte(`{"duplicate":1,"duplicate":2,"value":"\uD800"}`),
			want:     "invalid Unicode surrogate",
		},
		{
			name:     "lone low surrogate",
			document: []byte(`{"duplicate":1,"duplicate":2,"\uDC00":true}`),
			want:     "invalid Unicode surrogate",
		},
		{
			name:     "high surrogate followed by non-surrogate",
			document: []byte(`{"duplicate":1,"duplicate":2,"value":"\uD800\u0041"}`),
			want:     "invalid Unicode surrogate",
		},
		{
			name:     "high surrogate followed by high surrogate",
			document: []byte(`{"duplicate":1,"duplicate":2,"value":"\uD800\uD801"}`),
			want:     "invalid Unicode surrogate",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateUniqueJSONMembers(test.document); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateUniqueJSONMembers = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestContractMetadataUnicodeValidationAppliesToAllDecoders(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "lock.json")
	invalidLock := append([]byte(`{"format_version":2,"value":"`), 0xff, '"', '}')
	if err := os.WriteFile(lockPath, invalidLock, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(lockPath); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("Load invalid UTF-8 = %v", err)
	}

	manifest := []byte(`{"namespace":"\uD800","version":"1.0.0","license":"MIT","resources":[]}`)
	if _, err := decodeContractManifest(manifest); err == nil || !strings.Contains(err.Error(), "invalid Unicode surrogate") {
		t.Fatalf("decodeContractManifest invalid surrogate = %v", err)
	}

	semantic := []byte(`{"rules":[{"id":"\uDC00"}]}`)
	var destination map[string]any
	if err := decodeMetadata(semantic, &destination); err == nil || !strings.Contains(err.Error(), "invalid Unicode surrogate") {
		t.Fatalf("decodeMetadata invalid surrogate = %v", err)
	}
}

func TestContractMetadataAcceptsValidJSONUnicode(t *testing.T) {
	for _, document := range [][]byte{
		[]byte("{\"rocket\":\"\xf0\x9f\x9a\x80\"}"),
		[]byte(`{"rocket":"\uD83D\uDE80"}`),
		[]byte(`{"literal":"\\uD800"}`),
	} {
		var destination map[string]any
		if err := decodeMetadata(document, &destination); err != nil {
			t.Fatalf("decodeMetadata(%q): %v", document, err)
		}
	}
}

func TestLockRejectsFormatOne(t *testing.T) {
	lock := testLock(strings.Repeat("c", 40), strings.Repeat("d", 40), "sha256:"+strings.Repeat("e", 64))
	lock.FormatVersion = 1
	if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported contract lock format 1") {
		t.Fatalf("Validate format 1 = %v", err)
	}
}

func TestLockRequiresBothSuiteEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Lock)
		want   string
	}{
		{name: "sandbox path", mutate: func(lock *Lock) { lock.SandboxSuite.Path = "" }, want: "Sandbox Suite path"},
		{name: "sandbox ID", mutate: func(lock *Lock) { lock.SandboxSuite.SuiteID = "" }, want: "Sandbox Suite identity and required profile"},
		{name: "sandbox version", mutate: func(lock *Lock) { lock.SandboxSuite.SuiteVersion = "" }, want: "Sandbox Suite identity and required profile"},
		{name: "sandbox digest", mutate: func(lock *Lock) { lock.SandboxSuite.SuiteDigest = "" }, want: "Sandbox Suite digest"},
		{name: "sandbox digest profile missing", mutate: func(lock *Lock) { lock.SandboxSuite.SuiteDigestProfile = "" }, want: "Sandbox Suite digest profile"},
		{name: "sandbox digest profile unsupported", mutate: func(lock *Lock) { lock.SandboxSuite.SuiteDigestProfile = "sha256-file-v1" }, want: "Sandbox Suite digest profile"},
		{name: "sandbox required profile", mutate: func(lock *Lock) { lock.SandboxSuite.RequiredProfile = "" }, want: "Sandbox Suite identity and required profile"},
		{name: "remote path", mutate: func(lock *Lock) { lock.ProviderRemoteSuite.Path = "" }, want: "Provider Remote Suite path"},
		{name: "remote ID", mutate: func(lock *Lock) { lock.ProviderRemoteSuite.SuiteID = "" }, want: "Provider Remote Suite identity and required profile"},
		{name: "remote version", mutate: func(lock *Lock) { lock.ProviderRemoteSuite.SuiteVersion = "" }, want: "Provider Remote Suite identity and required profile"},
		{name: "remote digest", mutate: func(lock *Lock) { lock.ProviderRemoteSuite.SuiteDigest = "" }, want: "Provider Remote Suite digest"},
		{name: "remote digest profile missing", mutate: func(lock *Lock) { lock.ProviderRemoteSuite.SuiteDigestProfile = "" }, want: "Provider Remote Suite digest profile"},
		{name: "remote digest profile unsupported", mutate: func(lock *Lock) { lock.ProviderRemoteSuite.SuiteDigestProfile = "sha256-file-v1" }, want: "Provider Remote Suite digest profile"},
		{name: "remote required profile", mutate: func(lock *Lock) { lock.ProviderRemoteSuite.RequiredProfile = "" }, want: "Provider Remote Suite identity and required profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lock := testLock(strings.Repeat("c", 40), strings.Repeat("d", 40), "sha256:"+strings.Repeat("e", 64))
			test.mutate(&lock)
			if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestLockRejectsResourceOutsideContractRoot(t *testing.T) {
	lock := testLock(strings.Repeat("c", 40), strings.Repeat("d", 40), "sha256:"+strings.Repeat("e", 64))
	lock.Contract.OpenAPIPath = "blueprint/openapi/sandbox-provider-v1.yaml"
	if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), "inside the Contract root") {
		t.Fatalf("Validate = %v", err)
	}
}

func TestVerifyLockedSuiteRejectsDocumentDigestProfileMismatch(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(testRemoteSuiteDocument(), suitedigest.DigestProfile, "sha256-file-v1", 1)
	writeTestFile(t, root, "suite.json", document)
	lock := SuiteLock{
		Path:               "suite.json",
		SuiteID:            "sandbox-provider-remote",
		SuiteVersion:       "1.0.0",
		SuiteDigest:        testPlaceholderDigest,
		SuiteDigestProfile: suitedigest.DigestProfile,
		RequiredProfile:    "sandbox-runtime-provider-remote-discovery-v1",
	}
	if _, err := verifyLockedSuite(root, "Provider Remote Suite", lock, suitedigest.ExecutionModeRemoteHTTPBlackBox); err == nil || !strings.Contains(err.Error(), "digest profile") {
		t.Fatalf("verifyLockedSuite = %v", err)
	}
}

func TestVerifyLockedSuiteRejectsUnexpectedExecutionMode(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Replace(testRemoteSuiteDocument(), `"execution_mode":"remote-http-black-box","mutations_performed":false`, `"execution_mode":"repository-go-test"`, 1)
	document = signSuite(t, document)
	writeTestFile(t, root, "suite.json", document)
	lock := SuiteLock{
		Path:               "suite.json",
		SuiteID:            "sandbox-provider-remote",
		SuiteVersion:       "1.0.0",
		SuiteDigest:        suiteDigest(t, document),
		SuiteDigestProfile: suitedigest.DigestProfile,
		RequiredProfile:    "sandbox-runtime-provider-remote-discovery-v1",
	}
	if _, err := verifyLockedSuite(root, "Provider Remote Suite", lock, suitedigest.ExecutionModeRemoteHTTPBlackBox); err == nil || !strings.Contains(err.Error(), "execution mode") {
		t.Fatalf("verifyLockedSuite = %v", err)
	}
}

func TestVerifyRejectsRemoteSuiteLockMismatch(t *testing.T) {
	source, valid, _ := prepareContractRepository(t, testContractManifest("conformance-suite", true, "conformance-suite"))
	tests := []struct {
		name   string
		mutate func(*SuiteLock)
		want   string
	}{
		{name: "ID", mutate: func(lock *SuiteLock) { lock.SuiteID = "other-remote-suite" }, want: "identity does not match"},
		{name: "version", mutate: func(lock *SuiteLock) { lock.SuiteVersion = "2.0.0" }, want: "identity does not match"},
		{name: "digest", mutate: func(lock *SuiteLock) { lock.SuiteDigest = "sha256:" + strings.Repeat("f", 64) }, want: "identity does not match"},
		{name: "required profile", mutate: func(lock *SuiteLock) { lock.RequiredProfile = "missing-profile" }, want: "missing required profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lock := valid
			test.mutate(&lock.ProviderRemoteSuite)
			if _, err := Verify(context.Background(), lock, source); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestVerifyRequiresSelectedSuitesInManifest(t *testing.T) {
	tests := []struct {
		name          string
		sandboxKind   string
		includeRemote bool
		remoteKind    string
		want          string
	}{
		{name: "sandbox kind", sandboxKind: "fixture", includeRemote: true, remoteKind: "conformance-suite", want: "Sandbox Suite manifest resource"},
		{name: "remote missing", sandboxKind: "conformance-suite", includeRemote: false, want: "Provider Remote Suite path"},
		{name: "remote kind", sandboxKind: "conformance-suite", includeRemote: true, remoteKind: "fixture", want: "Provider Remote Suite manifest resource"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, lock, _ := prepareContractRepository(t, testContractManifest(test.sandboxKind, test.includeRemote, test.remoteKind))
			if _, err := Verify(context.Background(), lock, source); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify = %v, want error containing %q", err, test.want)
			}
		})
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

type suiteDigests struct {
	sandbox string
	remote  string
}

func prepareContractRepository(t *testing.T, manifest string) (string, Lock, string) {
	t.Helper()
	source := t.TempDir()
	digests := writeContractFixture(t, source, manifest)
	writeTestFile(t, source, "contract/openapi/sandbox-provider-v1.yaml", testOpenAPI)
	runGit(t, source, "init")
	runGit(t, source, "config", "user.name", "Contract Lock Test")
	runGit(t, source, "config", "user.email", "contract-lock@example.invalid")
	runGit(t, source, "remote", "add", "origin", "https://example.invalid/agent")
	runGit(t, source, "add", "contract")
	runGit(t, source, "commit", "-m", "add contract")
	revision := runGit(t, source, "rev-parse", "HEAD")
	tree := runGit(t, source, "rev-parse", "HEAD:contract")
	lock := testLock(revision, tree, digestString([]byte(testOpenAPI)))
	lock.Contract.ManifestDigest = digestString([]byte(manifest))
	lock.SandboxSuite.SuiteDigest = digests.sandbox
	lock.ProviderRemoteSuite.SuiteDigest = digests.remote
	return source, lock, revision
}

func testLock(revision, tree, openAPIDigest string) Lock {
	return Lock{
		FormatVersion: LockFormatVersion,
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
			ManifestDigest:      "sha256:" + strings.Repeat("a", 64),
			OpenAPIPath:         "contract/openapi/sandbox-provider-v1.yaml",
			OpenAPISHA256:       openAPIDigest,
			SemanticRulesPath:   "contract/semantic-rules/provider-v1.json",
			SemanticRulesSHA256: digestString([]byte(testSemanticRules)),
			FixturesRoot:        "contract/fixtures",
		},
		SandboxSuite: SuiteLock{
			Path:               testSandboxSuitePath,
			SuiteID:            "sandbox-provider",
			SuiteVersion:       "1.0.0",
			SuiteDigest:        "sha256:" + strings.Repeat("b", 64),
			SuiteDigestProfile: suitedigest.DigestProfile,
			RequiredProfile:    "sandbox-runtime-provider-v1",
		},
		ProviderRemoteSuite: SuiteLock{
			Path:               testRemoteSuitePath,
			SuiteID:            "sandbox-provider-remote",
			SuiteVersion:       "1.0.0",
			SuiteDigest:        "sha256:" + strings.Repeat("c", 64),
			SuiteDigestProfile: suitedigest.DigestProfile,
			RequiredProfile:    "sandbox-runtime-provider-remote-discovery-v1",
		},
	}
}

func writeContractFixture(t *testing.T, source, manifest string) suiteDigests {
	t.Helper()
	sandbox := signSuite(t, testSandboxSuiteDocument())
	remote := signSuite(t, testRemoteSuiteDocument())
	writeTestFile(t, source, "contract/compatibility/contract-manifest.json", manifest)
	writeTestFile(t, source, "contract/semantic-rules/provider-v1.json", testSemanticRules)
	writeTestFile(t, source, "contract/fixtures/capabilities.json", `{}`)
	writeTestFile(t, source, testSandboxSuitePath, sandbox)
	writeTestFile(t, source, testRemoteSuitePath, remote)
	return suiteDigests{
		sandbox: suiteDigest(t, sandbox),
		remote:  suiteDigest(t, remote),
	}
}

func testContractManifest(sandboxKind string, includeRemote bool, remoteKind string) string {
	resources := `{"path":"openapi/sandbox-provider-v1.yaml","kind":"openapi","id":"urn:test:openapi"},` +
		`{"path":"semantic-rules/provider-v1.json","kind":"semantic-rules","id":"urn:test:semantic-rules"},` +
		`{"path":"fixtures/capabilities.json","kind":"fixture","id":"urn:test:fixture"},` +
		`{"path":"conformance/provider-v1/suite.json","kind":"` + sandboxKind + `","id":"urn:test:sandbox-suite"}`
	if includeRemote {
		resources += `,{"path":"conformance/provider-remote-v1/suite.json","kind":"` + remoteKind + `","id":"urn:test:remote-suite"}`
	}
	return `{"license":"MIT","namespace":"urn:shell-echo:sandbox-runtime:provider-v1","version":"1.0.0","resources":[` + resources + `]}`
}

func testSandboxSuiteDocument() string {
	return `{"suite_id":"sandbox-provider","suite_version":"1.0.0","suite_digest_profile":"` + suitedigest.DigestProfile + `","profiles":[{"profile_id":"sandbox-runtime-provider-v1","execution_mode":"repository-go-test","tests":["contract-metadata","provider-discovery"]}],"suite_digest":"` + testPlaceholderDigest + `"}`
}

func testRemoteSuiteDocument() string {
	return `{"suite_id":"sandbox-provider-remote","suite_version":"1.0.0","suite_digest_profile":"` + suitedigest.DigestProfile + `","profiles":[{"profile_id":"sandbox-runtime-provider-remote-discovery-v1","execution_mode":"remote-http-black-box","mutations_performed":false,"tests":["authenticated-discovery","get-only-routing"]}],"suite_digest":"` + testPlaceholderDigest + `"}`
}

func signSuite(t *testing.T, document string) string {
	t.Helper()
	digest, err := suitedigest.Compute([]byte(document), suitedigest.DigestProfile)
	if err != nil {
		t.Fatalf("compute Suite digest: %v", err)
	}
	return strings.Replace(document, testPlaceholderDigest, digest, 1)
}

func suiteDigest(t *testing.T, document string) string {
	t.Helper()
	digest, err := suitedigest.Compute([]byte(document), suitedigest.DigestProfile)
	if err != nil {
		t.Fatalf("compute signed Suite digest: %v", err)
	}
	return digest
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
