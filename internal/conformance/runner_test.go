package conformance

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/suitedigest"
)

const conformanceHelperModeEnv = "SANDBOX_RUNTIME_CONFORMANCE_TEST_HELPER_MODE"

func TestResolveGoToolchainIgnoresPATHAndRejectsVersionMismatch(t *testing.T) {
	fakeDirectory := t.TempDir()
	fakeName := "go"
	if runtime.GOOS == "windows" {
		fakeName += ".exe"
	}
	fakeGo := filepath.Join(fakeDirectory, fakeName)
	if err := os.WriteFile(fakeGo, []byte("not the Go toolchain"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeDirectory)
	environment := withSourceRootEnv(t.TempDir())
	resolved, err := resolveGoToolchain(context.Background(), runtime.Version(), environment)
	if err != nil {
		t.Fatalf("resolveGoToolchain: %v", err)
	}
	if resolved == fakeGo || !filepath.IsAbs(resolved) {
		t.Fatalf("resolved Go toolchain = %q, fake PATH entry = %q", resolved, fakeGo)
	}
	if _, err := resolveGoToolchain(context.Background(), runtime.Version()+"-mismatch", environment); err == nil || !strings.Contains(err.Error(), "does not match build version") {
		t.Fatalf("resolveGoToolchain(mismatch) = %v", err)
	}
	t.Setenv("GOROOT", runtime.GOROOT())
	if _, err := resolveGoToolchain(context.Background(), runtime.Version(), environment); err == nil || !strings.Contains(err.Error(), "GOROOT to be unset") {
		t.Fatalf("resolveGoToolchain(explicit GOROOT) = %v", err)
	}
}

func TestResolveGitToolchainReturnsAbsoluteRegularExecutable(t *testing.T) {
	executable, version, err := resolveGitToolchain(context.Background(), withSourceRootEnv(t.TempDir()))
	if err != nil {
		t.Fatalf("resolveGitToolchain: %v", err)
	}
	info, err := os.Lstat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(executable) || !info.Mode().IsRegular() {
		t.Fatalf("resolved Git executable = %q, mode = %v", executable, info.Mode())
	}
	if version == "" || strings.HasPrefix(version, "git version ") {
		t.Fatalf("resolved Git version = %q", version)
	}
}

func TestPrepareRunnerSourceExecutesRevisionInsteadOfWorktree(t *testing.T) {
	gitExecutable, _, err := resolveGitToolchain(context.Background(), withSourceRootEnv(t.TempDir()))
	if err != nil {
		t.Fatalf("resolveGitToolchain: %v", err)
	}
	repository := t.TempDir()
	writeRunnerFixture(t, repository, "package fixture\n\nimport \"testing\"\n\nfunc TestSnapshot(*testing.T) {}\n")
	runConformanceGit(t, repository, "init")
	runConformanceGit(t, repository, "config", "user.name", "Conformance Test")
	runConformanceGit(t, repository, "config", "user.email", "conformance@example.invalid")
	runConformanceGit(t, repository, "add", "go.mod", "fixture/fixture_test.go")
	runConformanceGit(t, repository, "commit", "-m", "passing runner source")
	passingRevision := runConformanceGit(t, repository, "rev-parse", "HEAD")

	failingTest := "package fixture\n\nimport \"testing\"\n\nfunc TestSnapshot(t *testing.T) { t.Fatal(\"worktree source executed\") }\n"
	if err := os.WriteFile(filepath.Join(repository, "fixture", "fixture_test.go"), []byte(failingTest), 0o600); err != nil {
		t.Fatal(err)
	}
	assertRunnerRevisionPasses(t, gitExecutable, repository, passingRevision)

	runConformanceGit(t, repository, "add", "fixture/fixture_test.go")
	runConformanceGit(t, repository, "commit", "-m", "failing head source")
	if head := runConformanceGit(t, repository, "rev-parse", "HEAD"); head == passingRevision {
		t.Fatal("fixture HEAD did not advance")
	}
	t.Setenv("PATH", t.TempDir())
	assertRunnerRevisionPasses(t, gitExecutable, repository, passingRevision)
}

func TestExtractRunnerArchiveRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name    string
		headers []tar.Header
		want    string
	}{
		{name: "path escape", headers: []tar.Header{{Name: "../escape", Typeflag: tar.TypeReg}}, want: "unsafe path"},
		{name: "symlink", headers: []tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "target"}}, want: "unsupported type"},
		{name: "hard link", headers: []tar.Header{{Name: "link", Typeflag: tar.TypeLink, Linkname: "target"}}, want: "unsupported type"},
		{name: "special file", headers: []tar.Header{{Name: "pipe", Typeflag: tar.TypeFifo}}, want: "unsupported type"},
		{name: "duplicate", headers: []tar.Header{{Name: "same", Typeflag: tar.TypeReg}, {Name: "same", Typeflag: tar.TypeReg}}, want: "duplicates path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := makeRunnerArchive(t, test.headers)
			err := extractRunnerArchive(bytes.NewReader(archive), t.TempDir(), strings.Repeat("a", 40))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("extractRunnerArchive() error = %v, want containing %q", err, test.want)
			}
		})
	}
	if err := extractRunnerArchive(bytes.NewReader(nil), t.TempDir(), strings.Repeat("a", 40)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("extractRunnerArchive(empty) = %v", err)
	}
}

func assertRunnerRevisionPasses(t *testing.T, gitExecutable, repository, revision string) {
	t.Helper()
	ctx := context.Background()
	snapshot, err := prepareRunnerSource(ctx, gitExecutable, repository, revision)
	if err != nil {
		t.Fatalf("prepareRunnerSource: %v", err)
	}
	defer cleanupRunnerSource(snapshot)
	info, err := os.Stat(filepath.Join(snapshot, "fixture", "fixture_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("archived runner source mode = %o, want read-only", info.Mode().Perm())
	}
	goTool, err := resolveGoToolchain(ctx, runtime.Version(), withSourceRootEnv(repository))
	if err != nil {
		t.Fatalf("resolveGoToolchain: %v", err)
	}
	command := exec.CommandContext(ctx, goTool, "test", "-json", "-mod=readonly", "-count=1", "./fixture", "-run", `^TestSnapshot$`)
	command.Dir = snapshot
	command.Env = withSourceRootEnv(repository)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runGoTestCommand(ctx, command, `^TestSnapshot$`, 1, &stdout, &stderr); err != nil {
		t.Fatalf("archived runner test = %v; stdout = %q; stderr = %q", err, stdout.String(), stderr.String())
	}
}

func writeRunnerFixture(t *testing.T, root, testSource string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.invalid/runner\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fixture", "fixture_test.go"), []byte(testSource), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runConformanceGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func makeRunnerArchive(t *testing.T, headers []tar.Header) []byte {
	t.Helper()
	var document bytes.Buffer
	writer := tar.NewWriter(&document)
	if err := writer.WriteHeader(&tar.Header{
		Name:       "pax_global_header",
		Typeflag:   tar.TypeXGlobalHeader,
		PAXRecords: map[string]string{"comment": strings.Repeat("a", 40)},
	}); err != nil {
		t.Fatalf("write archive identity: %v", err)
	}
	for index := range headers {
		header := headers[index]
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatalf("write archive header: %v", err)
		}
		if header.Size > 0 {
			if _, err := io.CopyN(writer, bytes.NewReader(make([]byte, header.Size)), header.Size); err != nil {
				t.Fatalf("write archive body: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return document.Bytes()
}

func TestLoadRunnerIdentityRequiresCleanGitBuild(t *testing.T) {
	const revision = "0123456789abcdef0123456789abcdef01234567"
	valid := debug.BuildInfo{
		GoVersion: "go1.26.5",
		Settings: []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: revision},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	identity, err := loadRunnerIdentity(func() (*debug.BuildInfo, bool) { return &valid, true })
	if err != nil {
		t.Fatalf("loadRunnerIdentity(valid) = %v", err)
	}
	if identity.revision != revision || identity.toolchain != "go1.26.5" {
		t.Fatalf("runner identity = %#v", identity)
	}

	for name, test := range map[string]struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		"reader missing": {want: "reader is required"},
		"unavailable":    {want: "unavailable"},
		"toolchain missing": {
			info: &debug.BuildInfo{Settings: valid.Settings}, ok: true, want: "toolchain",
		},
		"VCS missing": {
			info: &debug.BuildInfo{GoVersion: valid.GoVersion}, ok: true, want: "VCS must be git",
		},
		"revision missing": {
			info: &debug.BuildInfo{GoVersion: valid.GoVersion, Settings: []debug.BuildSetting{
				{Key: "vcs", Value: "git"},
				{Key: "vcs.modified", Value: "false"},
			}}, ok: true, want: "revision",
		},
		"revision uppercase": {
			info: &debug.BuildInfo{GoVersion: valid.GoVersion, Settings: []debug.BuildSetting{
				{Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: strings.ToUpper(revision)},
				{Key: "vcs.modified", Value: "false"},
			}}, ok: true, want: "revision",
		},
		"modified state missing": {
			info: &debug.BuildInfo{GoVersion: valid.GoVersion, Settings: []debug.BuildSetting{
				{Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: revision},
			}}, ok: true, want: "unmodified VCS state",
		},
		"modified": {
			info: &debug.BuildInfo{GoVersion: valid.GoVersion, Settings: []debug.BuildSetting{
				{Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: revision},
				{Key: "vcs.modified", Value: "true"},
			}}, ok: true, want: "modified",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var reader func() (*debug.BuildInfo, bool)
			if name != "reader missing" {
				reader = func() (*debug.BuildInfo, bool) { return test.info, test.ok }
			}
			_, err := loadRunnerIdentity(reader)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadRunnerIdentity() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestRunGoTestCommandRequiresPassingExecutedTests(t *testing.T) {
	for _, test := range []struct {
		name       string
		mode       string
		pattern    string
		matches    int
		wantErr    string
		wantOutput string
	}{
		{name: "zero matches", mode: "zero", pattern: `^TestMapped$`, matches: 1, wantErr: "no tests matched"},
		{name: "all skipped", mode: "skip", pattern: `^TestMapped$`, matches: 1, wantErr: "skipped", wantOutput: "SKIP"},
		{name: "pass", mode: "pass", pattern: `^TestMapped$`, matches: 1, wantOutput: "human-readable diagnostic"},
		{name: "scaffold only", mode: "pass", pattern: `^TestMapped/required-subtest$`, matches: 1, wantErr: "matching the Suite case mapping"},
		{name: "missing required mapped test", mode: "pass", pattern: `^(TestMapped|TestRequired)$`, matches: 2, wantErr: "1 tests matching"},
		{name: "unexpected mapped test", mode: "two-pass", pattern: `^(TestMapped|TestRequired)$`, matches: 1, wantErr: "2 tests matching"},
		{name: "failure", mode: "fail", pattern: `^TestMapped$`, matches: 1, wantErr: "failed", wantOutput: "FAIL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			ctx := context.Background()
			err := runGoTestCommand(ctx, conformanceHelperCommand(ctx, test.mode), test.pattern, test.matches, &stdout, &stderr)
			if test.wantErr == "" && err != nil {
				t.Fatalf("runGoTestCommand() = %v; stderr = %q", err, stderr.String())
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("runGoTestCommand() error = %v, want containing %q", err, test.wantErr)
			}
			if test.wantOutput != "" && !strings.Contains(stdout.String(), test.wantOutput) {
				t.Fatalf("human output = %q, want containing %q", stdout.String(), test.wantOutput)
			}
			if strings.Contains(stdout.String(), `"Action"`) {
				t.Fatalf("human output exposes raw JSON event: %q", stdout.String())
			}
		})
	}
}

func TestImmutableCapabilityMappingNamesExistingTests(t *testing.T) {
	test := testCases["capability-discovery-immutable-schema"]
	if test.ExpectedMatches != 2 {
		t.Fatalf("expected matches = %d, want 2", test.ExpectedMatches)
	}
	for _, name := range []string{
		"TestLockedCapabilityResponseSchema",
		"TestNewCapabilitiesHandlerReadsSourceOnceAndFreezesResponse",
	} {
		if matched, err := regexp.MatchString(test.Run, name); err != nil || !matched {
			t.Fatalf("mapping %q does not match %q: %v", test.Run, name, err)
		}
	}
}

func TestRunGoTestCommandPreservesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout bytes.Buffer
	writer := cancelOnReadyWriter{writer: &stdout, cancel: cancel}
	err := runGoTestCommand(ctx, conformanceHelperCommand(ctx, "block"), `^TestMapped$`, 1, &writer, &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runGoTestCommand() error = %v, want context.Canceled", err)
	}
	if !strings.Contains(stdout.String(), "ready") {
		t.Fatalf("human output = %q, want cancellation readiness evidence", stdout.String())
	}
}

func TestConformanceGoTestHelper(*testing.T) {
	mode := os.Getenv(conformanceHelperModeEnv)
	if mode == "" {
		return
	}
	encode := json.NewEncoder(os.Stdout)
	emit := func(event goTestEvent) {
		if err := encode.Encode(event); err != nil {
			os.Exit(2)
		}
	}
	emit(goTestEvent{Action: "start", Package: "example.test"})
	switch mode {
	case "zero":
		emit(goTestEvent{Action: "output", Package: "example.test", Output: "testing: warning: no tests to run\n"})
		emit(goTestEvent{Action: "pass", Package: "example.test"})
	case "skip":
		emit(goTestEvent{Action: "run", Package: "example.test", Test: "TestMapped"})
		emit(goTestEvent{Action: "output", Package: "example.test", Test: "TestMapped", Output: "--- SKIP: TestMapped\n"})
		emit(goTestEvent{Action: "skip", Package: "example.test", Test: "TestMapped"})
		emit(goTestEvent{Action: "pass", Package: "example.test"})
	case "pass":
		emit(goTestEvent{Action: "run", Package: "example.test", Test: "TestMapped"})
		emit(goTestEvent{Action: "output", Package: "example.test", Test: "TestMapped", Output: "human-readable diagnostic\n"})
		emit(goTestEvent{Action: "pass", Package: "example.test", Test: "TestMapped"})
		emit(goTestEvent{Action: "output", Package: "example.test", Output: "PASS\n"})
		emit(goTestEvent{Action: "pass", Package: "example.test"})
	case "two-pass":
		for _, test := range []string{"TestMapped", "TestRequired"} {
			emit(goTestEvent{Action: "run", Package: "example.test", Test: test})
			emit(goTestEvent{Action: "pass", Package: "example.test", Test: test})
		}
		emit(goTestEvent{Action: "pass", Package: "example.test"})
	case "fail":
		emit(goTestEvent{Action: "run", Package: "example.test", Test: "TestMapped"})
		emit(goTestEvent{Action: "output", Package: "example.test", Test: "TestMapped", Output: "--- FAIL: TestMapped\n"})
		emit(goTestEvent{Action: "fail", Package: "example.test", Test: "TestMapped"})
		emit(goTestEvent{Action: "fail", Package: "example.test"})
		os.Exit(1)
	case "block":
		emit(goTestEvent{Action: "run", Package: "example.test", Test: "TestMapped"})
		emit(goTestEvent{Action: "output", Package: "example.test", Test: "TestMapped", Output: "ready\n"})
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func conformanceHelperCommand(ctx context.Context, mode string) *exec.Cmd {
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConformanceGoTestHelper$")
	key := conformanceHelperModeEnv + "="
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, key) {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, key+mode)
	return command
}

type cancelOnReadyWriter struct {
	writer *bytes.Buffer
	cancel context.CancelFunc
}

func (writer *cancelOnReadyWriter) Write(value []byte) (int, error) {
	written, err := writer.writer.Write(value)
	if strings.Contains(string(value), "ready") {
		writer.cancel()
	}
	return written, err
}

func TestValidateCasesRequiresKnownUniqueIDs(t *testing.T) {
	if err := validateCases([]string{"capability-discovery-mtls-only", "protected-admission-expiry"}); err != nil {
		t.Fatalf("validateCases(valid) = %v", err)
	}
	for name, ids := range map[string][]string{
		"empty":     nil,
		"blank":     {" "},
		"duplicate": {"capability-discovery-mtls-only", "capability-discovery-mtls-only"},
		"unknown":   {"future-case"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCases(ids); err == nil {
				t.Fatal("validateCases() error = nil")
			}
		})
	}
}

func TestLocalSuiteCasesHaveRunnerMappings(t *testing.T) {
	ids := []string{
		"capability-discovery-mtls-only",
		"capability-discovery-admitted-identity",
		"capability-discovery-immutable-schema",
		"capability-discovery-terminal-profile-advertisement",
		"capability-discovery-terminal-session-contract-consistency",
		"capability-discovery-coding-shell-profile-advertisement",
		"capability-discovery-coding-shell-contract-consistency",
		"capability-discovery-coding-shell-rejection-fixtures",
		"capability-discovery-browser-profile-advertisement",
		"capability-discovery-browser-contract-consistency",
		"capability-discovery-browser-rejection-fixtures",
		"capability-discovery-desktop-profile-advertisement",
		"capability-discovery-desktop-contract-consistency",
		"capability-discovery-desktop-rejection-fixtures",
		"capability-discovery-empty-request",
		"capability-discovery-no-mutation-routes",
		"protected-admission-context-schema",
		"protected-admission-jws-profile-schema",
		"protected-admission-issuer-local-authority-binding",
		"protected-admission-token-binding",
		"protected-admission-digest-substitution",
		"protected-admission-expiry",
		"protected-admission-replay-and-fencing",
		"lifecycle-create-request-schema",
		"lifecycle-operation-state-schema",
		"lifecycle-idempotency-generation-fencing",
		"lifecycle-deadline-outcome",
		"exec-request-schema",
		"exec-cancel-schema",
		"exec-result-schema",
		"exec-semantic-bounds",
		"exec-rejection-fixtures",
		"runtime-session-open-schema",
		"runtime-session-operation-schema",
		"runtime-session-handoff-schema",
		"runtime-session-semantic-bounds",
		"runtime-session-rejection-fixtures",
		"terminal-connect-schema-and-fixtures",
		"terminal-connect-capability-advertisement",
		"terminal-connect-admission-and-websocket-contract",
		"browser-session-open-schema",
		"browser-session-operation-schema",
		"browser-session-handoff-schema",
		"browser-session-semantic-bounds",
		"browser-session-rejection-fixtures",
		"browser-session-usage-evidence",
		"browser-session-protected-admission-bindings",
		"desktop-session-open-schema",
		"desktop-session-close-schema",
		"desktop-session-operation-schema",
		"desktop-session-handoff-schema",
		"desktop-session-semantic-bounds",
		"desktop-session-rejection-fixtures",
		"desktop-session-usage-evidence",
		"desktop-session-protected-admission-bindings",
		"artifact-staging-request-schema",
		"artifact-staging-evidence-schema",
		"artifact-staging-semantic-bounds",
		"artifact-staging-rejection-fixtures",
		"usage-evidence-schema",
		"usage-evidence-semantic-bounds",
		"artifact-usage-protected-admission-bindings",
		"artifact-operation-read-schema",
		"artifact-usage-read-state-matrix",
	}
	if err := validateCases(ids); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalConnectDefinitionSuiteCasesHaveRunnerMappings(t *testing.T) {
	suite, err := suitedigest.Load(filepath.Join("..", "..", "contract", "conformance", "provider-v1", "suite.json"), suitedigest.DigestProfile)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := suite.RequiredProfile("sandbox-runtime-provider-v1")
	if err != nil {
		t.Fatal(err)
	}
	suiteCases := make(map[string]struct{}, len(profile.Tests))
	for _, id := range profile.Tests {
		suiteCases[id] = struct{}{}
	}
	for _, id := range []string{"terminal-connect-schema-and-fixtures", "terminal-connect-capability-advertisement", "terminal-connect-admission-and-websocket-contract"} {
		if _, ok := suiteCases[id]; !ok {
			t.Fatalf("lock-selected local Suite is missing terminal-connect case %q", id)
		}
		mapping := testCases[id]
		if mapping.Package != "./providerapi/v1" || mapping.Run == "" {
			t.Fatalf("terminal-connect Suite case %q mapping = %#v", id, mapping)
		}
	}
}

func TestLifecycleSuiteCasesExecuteBehaviorPackages(t *testing.T) {
	want := map[string]testCase{
		"lifecycle-create-request-schema":                            {Package: "./providerapi"},
		"lifecycle-operation-state-schema":                           {Package: "./providerapi"},
		"lifecycle-idempotency-generation-fencing":                   {Package: "./provider/lifecycle/coordinator"},
		"lifecycle-deadline-outcome":                                 {Package: "./provider/lifecycle/coordinator"},
		"capability-discovery-terminal-profile-advertisement":        {Package: "./providerapi"},
		"capability-discovery-terminal-session-contract-consistency": {Package: "./providerapi/v1"},
		"capability-discovery-coding-shell-profile-advertisement":    {Package: "./providerapi"},
		"capability-discovery-coding-shell-contract-consistency":     {Package: "./providerapi/v1"},
		"capability-discovery-coding-shell-rejection-fixtures":       {Package: "./providerapi"},
		"capability-discovery-browser-profile-advertisement":         {Package: "./providerapi"},
		"capability-discovery-browser-contract-consistency":          {Package: "./providerapi/v1"},
		"capability-discovery-browser-rejection-fixtures":            {Package: "./providerapi"},
		"capability-discovery-desktop-profile-advertisement":         {Package: "./providerapi"},
		"capability-discovery-desktop-contract-consistency":          {Package: "./providerapi/v1"},
		"capability-discovery-desktop-rejection-fixtures":            {Package: "./providerapi"},
		"protected-admission-jws-profile-schema":                     {Package: "./provider/admission"},
		"protected-admission-issuer-local-authority-binding":         {Package: "./provider/admission"},
		"exec-request-schema":                                        {Package: "./providerapi/v1"},
		"exec-cancel-schema":                                         {Package: "./providerapi/v1"},
		"exec-result-schema":                                         {Package: "./providerapi/v1"},
		"exec-semantic-bounds":                                       {Package: "./providerapi/v1"},
		"exec-rejection-fixtures":                                    {Package: "./providerapi/v1"},
		"runtime-session-open-schema":                                {Package: "./providerapi/v1"},
		"runtime-session-operation-schema":                           {Package: "./providerapi/v1"},
		"runtime-session-handoff-schema":                             {Package: "./providerapi/v1"},
		"runtime-session-semantic-bounds":                            {Package: "./providerapi/v1"},
		"runtime-session-rejection-fixtures":                         {Package: "./providerapi/v1"},
		"browser-session-open-schema":                                {Package: "./providerapi/v1"},
		"browser-session-operation-schema":                           {Package: "./providerapi/v1"},
		"browser-session-handoff-schema":                             {Package: "./providerapi/v1"},
		"browser-session-semantic-bounds":                            {Package: "./providerapi/v1"},
		"browser-session-rejection-fixtures":                         {Package: "./providerapi/v1"},
		"browser-session-usage-evidence":                             {Package: "./providerapi/v1"},
		"browser-session-protected-admission-bindings":               {Package: "./provider/admission"},
		"desktop-session-open-schema":                                {Package: "./providerapi/v1"},
		"desktop-session-close-schema":                               {Package: "./providerapi/v1"},
		"desktop-session-operation-schema":                           {Package: "./providerapi/v1"},
		"desktop-session-handoff-schema":                             {Package: "./providerapi/v1"},
		"desktop-session-semantic-bounds":                            {Package: "./providerapi/v1"},
		"desktop-session-rejection-fixtures":                         {Package: "./providerapi/v1"},
		"desktop-session-usage-evidence":                             {Package: "./providerapi/v1"},
		"desktop-session-protected-admission-bindings":               {Package: "./provider/admission"},
		"artifact-staging-request-schema":                            {Package: "./providerapi/v1"},
		"artifact-staging-evidence-schema":                           {Package: "./providerapi/v1"},
		"artifact-staging-semantic-bounds":                           {Package: "./providerapi/v1"},
		"artifact-staging-rejection-fixtures":                        {Package: "./providerapi/v1"},
		"usage-evidence-schema":                                      {Package: "./providerapi/v1"},
		"usage-evidence-semantic-bounds":                             {Package: "./providerapi/v1"},
		"artifact-usage-protected-admission-bindings":                {Package: "./provider/admission"},
		"artifact-operation-read-schema":                             {Package: "./providerapi/v1"},
		"artifact-usage-read-state-matrix":                           {Package: "./providerapi/v1"},
	}
	for id, expected := range want {
		got := testCases[id]
		if got.Package != expected.Package || got.Run == "" {
			t.Fatalf("Suite case %q mapping = %#v, want package %q and a behavior pattern", id, got, expected.Package)
		}
	}
}

func TestWithSourceRootEnvReplacesExistingValue(t *testing.T) {
	const key = "SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT="
	original := os.Getenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT")
	if err := os.Setenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT", "/wrong"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if original == "" {
			_ = os.Unsetenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT")
			return
		}
		_ = os.Setenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT", original)
	})
	for name, value := range map[string]string{
		"GOENV":       "/unsafe/go/env",
		"GOFLAGS":     "-overlay=/unsafe/overlay.json",
		"GOROOT":      "/unsafe/go/root",
		"GOTOOLCHAIN": "auto",
		"GOWORK":      "/unsafe/go.work",
	} {
		t.Setenv(name, value)
	}
	values := withSourceRootEnv("/right")
	var matches []string
	result := make(map[string]string)
	for _, value := range values {
		if strings.HasPrefix(value, key) {
			matches = append(matches, value)
		}
		name, setting, ok := strings.Cut(value, "=")
		if ok {
			result[name] = setting
		}
	}
	if len(matches) != 1 || matches[0] != key+"/right" {
		t.Fatalf("Contract source-root environment = %#v", matches)
	}
	for name, want := range map[string]string{"GOENV": "off", "GOFLAGS": "", "GOTOOLCHAIN": "local", "GOWORK": "off"} {
		if result[name] != want {
			t.Fatalf("%s = %q, want %q", name, result[name], want)
		}
	}
	if _, exists := result["GOROOT"]; exists {
		t.Fatalf("GOROOT was inherited into Conformance Suite environment")
	}
}
