package remoteconformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/contractlock"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

const (
	capabilityDocument       = `{"provider_revision_id":"remote-provider-revision-1","api_version":"v1","capabilities":[],"runtime_profiles":[],"snapshot_restore_profiles":[{"profile_id":"sandbox-snapshot-workspace-v1","level":"workspace","suite_id":"sandbox-provider","suite_version":"1.0.0","suite_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"limits":{"max_cpu_millis":1000,"max_memory_bytes":1073741824,"max_ephemeral_storage_bytes":1073741824,"max_lease_seconds":3600,"max_exec_seconds":300}}`
	expectedProviderRevision = "remote-provider-revision-1"
	testServerName           = "127.0.0.1"
	admittedClientIdentity   = "spiffe://caller.example/remote-conformance"
	deniedClientIdentity     = "spiffe://caller.example/not-admitted"
)

type capabilityValidator struct {
	calls atomic.Int64
}

func (v *capabilityValidator) Validate(name string, document []byte) error {
	v.calls.Add(1)
	if name != "provider-capabilities.schema.json" || string(document) != capabilityDocument {
		return errors.New("unexpected Schema input")
	}
	var value map[string]any
	return json.Unmarshal(document, &value)
}

func TestExecutorRunsLockedDiscoveryCases(t *testing.T) {
	server := startDiscoveryServer(t, discoveryServerOptions{mode: tlsClientCertificateRequired})
	validator := &capabilityValidator{}
	executor, err := newExecutor(server.options, validator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(executor.close)

	for _, id := range requiredCases {
		if err := executor.runCase(context.Background(), id); err != nil {
			t.Fatalf("case %q: %v", id, err)
		}
	}
	if validator.calls.Load() != 1 {
		t.Fatalf("Schema validation calls = %d, want 1", validator.calls.Load())
	}
	if executor.providerRevision != expectedProviderRevision || executor.capabilityDigest != digestString(capabilityDocument) {
		t.Fatalf("Provider identity = (%q, %q)", executor.providerRevision, executor.capabilityDigest)
	}
	if !executor.unsafeMethodProbesSent {
		t.Fatal("unsafe method probes were not recorded")
	}
}

func TestClientCertificateCaseRejectsListenerWithoutTLSRejection(t *testing.T) {
	for _, mode := range []clientCertificateMode{tlsClientCertificateOptional, tlsClientCertificateHTTPUnauthorized} {
		server := startDiscoveryServer(t, discoveryServerOptions{mode: mode})
		executor, err := newExecutor(server.options, &capabilityValidator{})
		if err != nil {
			t.Fatal(err)
		}
		if err := executor.mtlsSuccess(context.Background()); err != nil {
			executor.close()
			t.Fatal(err)
		}
		err = executor.clientCertificateRequired(context.Background())
		executor.close()
		if errorCode(err) != "client_certificate_not_required" {
			t.Fatalf("mode %d client certificate error = %v", mode, err)
		}
	}
}

func TestClientCertificateCaseRejectsTrustedDeniedIdentityAcceptance(t *testing.T) {
	server := startDiscoveryServer(t, discoveryServerOptions{
		mode:                 tlsClientCertificateRequired,
		acceptDeniedIdentity: true,
	})
	executor, err := newExecutor(server.options, &capabilityValidator{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(executor.close)
	if err := executor.mtlsSuccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code := errorCode(executor.clientCertificateRequired(context.Background())); code != "client_identity_not_enforced" {
		t.Fatalf("denied identity error code = %q", code)
	}
}

func TestSchemaRequiresExactProviderRevision(t *testing.T) {
	validator := &acceptingValidator{}
	executor := &executor{
		baseline: []byte(capabilityDocument), expectedProviderRevision: "different-provider-revision",
		validator: validator,
	}
	err := executor.schema(context.Background())
	if errorCode(err) != "provider_revision_mismatch" {
		t.Fatalf("schema error = %v", err)
	}
	if executor.providerRevision != expectedProviderRevision {
		t.Fatalf("observed Provider revision = %q", executor.providerRevision)
	}
	if validator.calls.Load() != 1 {
		t.Fatalf("Schema validation calls = %d, want 1", validator.calls.Load())
	}
}

func TestSchemaRejectsNonStrictJSONBeforeValidation(t *testing.T) {
	tests := map[string][]byte{
		"duplicate root member":   []byte(`{"provider_revision_id":"remote-provider-revision-1","provider_revision_id":"remote-provider-revision-1"}`),
		"duplicate nested member": []byte(`{"provider_revision_id":"remote-provider-revision-1","nested":{"value":1,"value":2}}`),
		"trailing value":          []byte(capabilityDocument + `{}`),
		"invalid UTF-8":           {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"lone high surrogate":     []byte(`{"provider_revision_id":"remote-\uD800"}`),
		"lone low surrogate":      []byte(`{"provider_revision_id":"remote-\uDC00"}`),
		"mismatched surrogate":    []byte(`{"provider_revision_id":"remote-\uD800\u0041"}`),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			validator := &acceptingValidator{}
			executor := &executor{
				baseline: document, expectedProviderRevision: expectedProviderRevision,
				validator: validator,
			}
			if code := errorCode(executor.schema(context.Background())); code != "schema_validation_failed" {
				t.Fatalf("schema failure code = %q", code)
			}
			if validator.calls.Load() != 0 {
				t.Fatalf("Schema validator called %d times", validator.calls.Load())
			}
		})
	}
}

func TestImmutableReadsSequentially(t *testing.T) {
	var active atomic.Int64
	var maximum atomic.Int64
	server := startDiscoveryServer(t, discoveryServerOptions{
		mode: tlsClientCertificateRequired,
		onAdmittedGET: func(http.ResponseWriter, *http.Request) bool {
			current := active.Add(1)
			defer active.Add(-1)
			for observed := maximum.Load(); current > observed && !maximum.CompareAndSwap(observed, current); observed = maximum.Load() {
			}
			time.Sleep(5 * time.Millisecond)
			return false
		},
	})
	executor, err := newExecutor(server.options, &capabilityValidator{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(executor.close)
	if err := executor.mtlsSuccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.immutable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent immutable reads = %d, want 1", got)
	}
}

type acceptingValidator struct {
	calls atomic.Int64
}

func (v *acceptingValidator) Validate(name string, _ []byte) error {
	v.calls.Add(1)
	if name != "provider-capabilities.schema.json" {
		return errors.New("unexpected Schema name")
	}
	return nil
}

func TestNewExecutorRejectsUnsafeConfigurationWithoutLeakingIt(t *testing.T) {
	server := startDiscoveryServer(t, discoveryServerOptions{mode: tlsClientCertificateRequired})
	base := server.options

	keyContent, err := os.ReadFile(base.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	permissiveKey := filepath.Join(t.TempDir(), "permissive-private-key.pem")
	if err := os.WriteFile(permissiveKey, keyContent, 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "client-key-link.pem")
	if err := os.Symlink(base.ClientKey, symlink); err != nil {
		t.Fatal(err)
	}

	tests := map[string]Options{
		"plaintext target":   cloneOptions(base, func(options *Options) { options.Target = "http://provider.example" }),
		"target path":        cloneOptions(base, func(options *Options) { options.Target += "/v1" }),
		"target query":       cloneOptions(base, func(options *Options) { options.Target += "?secret=value" }),
		"relative server CA": cloneOptions(base, func(options *Options) { options.CAFile = "ca.pem" }),
		"relative client CA": cloneOptions(base, func(options *Options) { options.ClientCAFile = "client-ca.pem" }),
		"same certificate":   cloneOptions(base, func(options *Options) { options.DeniedClientCert = options.ClientCert }),
		"permissive key":     cloneOptions(base, func(options *Options) { options.ClientKey = permissiveKey }),
		"symlink key":        cloneOptions(base, func(options *Options) { options.ClientKey = symlink }),
		"missing servername": cloneOptions(base, func(options *Options) { options.ServerName = "" }),
		"invalid servername": cloneOptions(base, func(options *Options) { options.ServerName = "bad/name" }),
		"missing revision":   cloneOptions(base, func(options *Options) { options.ProviderRevision = "" }),
		"blank revision":     cloneOptions(base, func(options *Options) { options.ProviderRevision = " \t" }),
		"oversized revision": cloneOptions(base, func(options *Options) { options.ProviderRevision = strings.Repeat("r", maxProviderRevisionRunes+1) }),
	}
	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := newExecutor(options, &capabilityValidator{})
			if errorCode(err) != "invalid_configuration" {
				t.Fatalf("newExecutor() error = %v", err)
			}
			for _, private := range []string{
				options.Target, options.CAFile, options.ClientCAFile, options.ClientCert,
				options.ClientKey, options.DeniedClientCert, options.DeniedClientKey,
				options.ServerName, options.ProviderRevision,
			} {
				if private != "" && strings.Contains(err.Error(), private) {
					t.Fatalf("error leaked private configuration %q: %v", private, err)
				}
			}
		})
	}
}

func TestNewExecutorStrictlyValidatesBothClientIdentities(t *testing.T) {
	server := startDiscoveryServer(t, discoveryServerOptions{mode: tlsClientCertificateRequired})
	material := server.material
	otherCA := newTestCA(t, "other-client-ca")
	multipleClientCAFile := material.write("multiple-client-ca.pem", append(append([]byte(nil), material.clientCA.pem...), otherCA.pem...), 0o644)

	tests := map[string]func(*Options){
		"same admitted URI": func(options *Options) {
			options.DeniedClientCert, options.DeniedClientKey, _ = material.issueClient("same-uri", []string{admittedClientIdentity}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		},
		"admitted missing URI": func(options *Options) {
			options.ClientCert, options.ClientKey, _ = material.issueClient("missing-uri", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		},
		"denied multiple URIs": func(options *Options) {
			options.DeniedClientCert, options.DeniedClientKey, _ = material.issueClient("multiple-uri", []string{deniedClientIdentity, "spiffe://caller.example/other"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		},
		"denied missing client auth": func(options *Options) {
			options.DeniedClientCert, options.DeniedClientKey, _ = material.issueClient("wrong-eku", []string{deniedClientIdentity}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		},
		"admitted any EKU": func(options *Options) {
			options.ClientCert, options.ClientKey, _ = material.issueClient("any-eku", []string{admittedClientIdentity}, []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageClientAuth})
		},
		"different trusted roots": func(options *Options) {
			originalCA := material.clientCA
			material.clientCA = otherCA
			options.DeniedClientCert, options.DeniedClientKey, _ = material.issueClient("other-root", []string{deniedClientIdentity}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			material.clientCA = originalCA
			options.ClientCAFile = multipleClientCAFile
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := server.options
			mutate(&options)
			if _, err := newExecutor(options, &capabilityValidator{}); errorCode(err) != "invalid_configuration" {
				t.Fatalf("newExecutor() error = %v", err)
			}
		})
	}
}

func TestValidateRemoteSuiteRequiresExactOrderedInventory(t *testing.T) {
	valid := contractlock.VerifiedSuite{
		ID: "sandbox-provider-remote", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("a", 64),
		DigestProfile: "rfc8785-full-document-excluding-suite-digest-v1",
		ProfileID:     "sandbox-runtime-provider-remote-discovery-v1",
		Cases:         append([]string(nil), requiredCases...),
	}
	if err := validateRemoteSuite(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*contractlock.VerifiedSuite){
		"missing identity": func(suite *contractlock.VerifiedSuite) { suite.DigestProfile = "" },
		"missing case":     func(suite *contractlock.VerifiedSuite) { suite.Cases = suite.Cases[:len(suite.Cases)-1] },
		"changed case":     func(suite *contractlock.VerifiedSuite) { suite.Cases[0] = "local-component-case" },
		"changed order": func(suite *contractlock.VerifiedSuite) {
			suite.Cases[0], suite.Cases[1] = suite.Cases[1], suite.Cases[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Cases = append([]string(nil), valid.Cases...)
			mutate(&candidate)
			if errorCode(validateRemoteSuite(candidate)) != "remote_suite_invalid" {
				t.Fatal("invalid remote Suite was accepted")
			}
		})
	}
}

func TestRunnerIdentityRequiresExactCleanBuild(t *testing.T) {
	valid := &debug.BuildInfo{
		GoVersion: "go1.26.5",
		Path:      runnerMainPath,
		Settings: []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: strings.Repeat("a", 40)},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	identity, err := parseRunnerIdentity(valid)
	if err != nil {
		t.Fatal(err)
	}
	if identity.MainPath != runnerMainPath || identity.Revision != strings.Repeat("a", 40) || identity.GoVersion != "go1.26.5" || identity.Modified {
		t.Fatalf("identity = %+v", identity)
	}

	for name, mutate := range map[string]func(*debug.BuildInfo){
		"wrong main path": func(info *debug.BuildInfo) { info.Path = "example.invalid/runner" },
		"missing VCS":     func(info *debug.BuildInfo) { info.Settings = info.Settings[1:] },
		"missing revision": func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings[:1], info.Settings[2:]...)
		},
		"modified":         func(info *debug.BuildInfo) { info.Settings[2].Value = "true" },
		"unknown modified": func(info *debug.BuildInfo) { info.Settings[2].Value = "" },
		"uppercase revision": func(info *debug.BuildInfo) {
			info.Settings[1].Value = strings.Repeat("A", 40)
		},
		"duplicate VCS": func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs", Value: "git"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			candidate.Settings = append([]debug.BuildSetting(nil), valid.Settings...)
			mutate(&candidate)
			if _, err := parseRunnerIdentity(&candidate); err == nil {
				t.Fatal("invalid runner build identity was accepted")
			}
		})
	}
}

func TestRunRejectsUnverifiableTestBinaryIdentity(t *testing.T) {
	_, err := Run(context.Background(), Options{})
	if errorCode(err) != "runner_identity_unverified" {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunPreservesCancellationAndStopsRemainingCases(t *testing.T) {
	entered := make(chan struct{})
	var admittedReads atomic.Int64
	server := startDiscoveryServer(t, discoveryServerOptions{
		mode: tlsClientCertificateRequired,
		onAdmittedGET: func(_ http.ResponseWriter, request *http.Request) bool {
			if admittedReads.Add(1) == 4 {
				close(entered)
				<-request.Context().Done()
				return true
			}
			return false
		},
	})
	optionsWithRepository(t, &server.options)
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		report Report
		err    error
	}
	finished := make(chan result, 1)
	go func() {
		report, err := run(ctx, server.options, testRunnerIdentity())
		finished <- result{report: report, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("runner did not reach the immutable case")
	}
	cancel()
	select {
	case got := <-finished:
		if !errors.Is(got.err, context.Canceled) || errorCode(got.err) != "run_canceled" {
			t.Fatalf("Run cancellation error = %v", got.err)
		}
		if len(got.report.Cases) != len(requiredCases) || got.report.Cases[3].Status != "not_executed" || got.report.Summary.NotExecuted != 3 {
			t.Fatalf("canceled report cases = %+v summary=%+v", got.report.Cases, got.report.Summary)
		}
		if got.report.SuiteExercised || got.report.ProfilePassed || got.report.UnsafeMethodProbesSent {
			t.Fatalf("canceled report flags = %+v", got.report)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not stop promptly after cancellation")
	}
}

func TestRunPreservesExpiredDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := run(ctx, Options{}, testRunnerIdentity())
	if !errors.Is(err, context.DeadlineExceeded) || errorCode(err) != "run_deadline_exceeded" {
		t.Fatalf("expired deadline error = %v", err)
	}
}

func TestRawRequestCancellationClosesConnection(t *testing.T) {
	entered := make(chan struct{})
	server := startDiscoveryServer(t, discoveryServerOptions{
		mode: tlsClientCertificateRequired,
		onAdmittedGET: func(_ http.ResponseWriter, request *http.Request) bool {
			close(entered)
			<-request.Context().Done()
			return true
		},
	})
	executor, err := newExecutor(server.options, &capabilityValidator{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(executor.close)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		_, err := executor.rawRequest(ctx, "GET /v1/capabilities HTTP/1.1\r\nHost: "+executor.target.Host+"\r\nConnection: close\r\n\r\n")
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("raw request did not reach server")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || errorCode(err) != "run_canceled" {
			t.Fatalf("raw request cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("raw request remained blocked after cancellation")
	}
}

func TestRunMarksBaselineDependentsNotExecuted(t *testing.T) {
	var admittedReads atomic.Int64
	server := startDiscoveryServer(t, discoveryServerOptions{
		mode: tlsClientCertificateRequired,
		onAdmittedGET: func(response http.ResponseWriter, _ *http.Request) bool {
			if admittedReads.Add(1) == 1 {
				response.WriteHeader(http.StatusServiceUnavailable)
				return true
			}
			return false
		},
	})
	optionsWithRepository(t, &server.options)
	report, err := run(context.Background(), server.options, testRunnerIdentity())
	if errorCode(err) != "cases_incomplete" {
		t.Fatalf("Run() error = %v", err)
	}
	if report.SuiteExercised || report.ProfilePassed || report.Summary != (Summary{Total: 6, Passed: 3, Failed: 1, NotExecuted: 2}) {
		t.Fatalf("incomplete report flags=%+v summary=%+v", report, report.Summary)
	}
	if report.Cases[2].Status != "not_executed" || report.Cases[3].Status != "not_executed" {
		t.Fatalf("baseline-dependent cases = %+v", report.Cases)
	}
	if !report.UnsafeMethodProbesSent || report.ContractMutationRoutesCalled {
		t.Fatalf("probe report fields = unsafe:%t mutation:%t", report.UnsafeMethodProbesSent, report.ContractMutationRoutesCalled)
	}
}

func TestRemoteConformanceRunsAgainstRealProviderServer(t *testing.T) {
	material := newTestTLSMaterial(t)
	port := reservePort(t)
	snapshot, err := provider.NewCapabilitySnapshot(expectedProviderRevision, provider.Limits{
		MaxCPUMillis: 1000, MaxMemoryBytes: 1 << 30, MaxEphemeralStorageBytes: 1 << 30,
		MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
	}, []provider.SnapshotRestoreProfile{{
		ProfileID: "sandbox-snapshot-workspace-v1", Level: provider.SnapshotLevelWorkspace,
		SuiteID: provider.CompatibilitySuiteSandboxProvider, SuiteVersion: "1.0.0",
		SuiteDigest: provider.SHA256Digest("sha256:" + strings.Repeat("a", 64)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	source, err := provider.NewStaticCapabilitySource(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	server, err := providerapi.NewServer(context.Background(), providerapi.TransportOptions{
		Address:               option.HTTP{Host: "127.0.0.1", Port: port},
		ServerCertificateFile: material.serverCertFile, ServerPrivateKeyFile: material.serverKeyFile,
		ClientCABundleFile:         material.clientCAFile,
		AllowedClientURIIdentities: []string{admittedClientIdentity},
	}, source)
	if err != nil {
		t.Fatal(err)
	}
	startupContext, cancelStartup := context.WithCancel(context.Background())
	startupResult := make(chan error, 1)
	go func() { startupResult <- server.Startup(startupContext) }()
	waitForPort(t, port, startupResult)
	t.Cleanup(func() {
		cancelStartup()
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		select {
		case err := <-startupResult:
			if err != nil {
				t.Errorf("Startup: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Provider server did not stop")
		}
	})

	options := material.options(fmt.Sprintf("https://127.0.0.1:%d", port))
	optionsWithRepository(t, &options)
	lock, err := contractlock.Load(options.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := run(context.Background(), options, testRunnerIdentity())
	if err != nil {
		t.Fatalf("run remote conformance: %v; report=%+v", err, report)
	}
	if report.Contract.LockedRevision != lock.Source.Revision || report.Contract.ContractTree != lock.Source.ContractTree {
		t.Fatalf("reported Contract identity = %+v, want lock %+v", report.Contract, lock.Source)
	}
	if report.Summary != (Summary{Total: 6, Passed: 6}) || len(report.Cases) != 6 || !report.SuiteExercised || !report.ProfilePassed {
		t.Fatalf("remote profile result = summary %+v, cases %d", report.Summary, len(report.Cases))
	}
	if report.Runner != testRunnerIdentity() || report.Provider.ExpectedRevisionID != expectedProviderRevision || report.Provider.ObservedRevisionID != expectedProviderRevision {
		t.Fatalf("reported identities = runner:%+v provider:%+v", report.Runner, report.Provider)
	}
	if report.ContractMutationRoutesCalled || !report.UnsafeMethodProbesSent || report.Provider.CapabilityDocumentDigest == "" {
		t.Fatalf("remote evidence fields = %+v", report)
	}
}

func TestRemoteRunnerImportBoundary(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "./internal/remoteconformance", "./cmd/run-remote-conformance")
	command.Dir = filepath.Join("..", "..")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dependency := range strings.Fields(string(output)) {
		for _, forbidden := range []string{
			"github.com/shell-echo/sandbox-runtime/provider",
			"github.com/shell-echo/sandbox-runtime/providerapi",
			"github.com/shell-echo/sandbox-runtime/driver",
		} {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") {
				t.Fatalf("remote runner imports forbidden implementation dependency %q", dependency)
			}
		}
	}
}

func TestExitCodeSummaryAndSuiteExercise(t *testing.T) {
	cases := []CaseResult{{ID: requiredCases[0], Status: "passed"}, {ID: requiredCases[1], Status: "failed"}, {ID: requiredCases[2], Status: "not_executed"}}
	if got := summarize(cases); got != (Summary{Total: 3, Passed: 1, Failed: 1, NotExecuted: 1}) {
		t.Fatalf("summary = %#v", got)
	}
	all := make([]CaseResult, len(requiredCases))
	for index, id := range requiredCases {
		all[index] = CaseResult{ID: id, Status: "passed"}
	}
	if !suiteExercised(all) {
		t.Fatal("complete ordered results were not recognized")
	}
	all[2].Status = "not_executed"
	if suiteExercised(all) {
		t.Fatal("not-executed case counted as Suite exercise")
	}
	if ExitCode(nil) != 0 || ExitCode(failure("cases_failed")) != 1 || ExitCode(failure("invalid_configuration")) != 2 {
		t.Fatal("unexpected exit-code mapping")
	}
}

type clientCertificateMode int

const (
	tlsClientCertificateRequired clientCertificateMode = iota
	tlsClientCertificateOptional
	tlsClientCertificateHTTPUnauthorized
)

type discoveryServerOptions struct {
	mode                 clientCertificateMode
	acceptDeniedIdentity bool
	onAdmittedGET        func(http.ResponseWriter, *http.Request) bool
}

type discoveryServer struct {
	options  Options
	material *testTLSMaterial
}

func startDiscoveryServer(t *testing.T, behavior discoveryServerOptions) discoveryServer {
	t.Helper()
	material := newTestTLSMaterial(t)
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/capabilities" {
			http.NotFound(response, request)
			return
		}
		identity := requestClientIdentity(request)
		if behavior.mode == tlsClientCertificateHTTPUnauthorized && identity == "" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if identity != "" && identity != admittedClientIdentity && !behavior.acceptDeniedIdentity {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if request.URL.ForceQuery || request.URL.RawQuery != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if identity == admittedClientIdentity && behavior.onAdmittedGET != nil && behavior.onAdmittedGET(response, request) {
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(capabilityDocument))
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{material.serverCertificate},
	}
	switch behavior.mode {
	case tlsClientCertificateRequired:
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = material.clientCAPool
	case tlsClientCertificateHTTPUnauthorized:
		server.TLS.ClientAuth = tls.RequestClientCert
		server.TLS.ClientCAs = material.clientCAPool
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return discoveryServer{options: material.options(server.URL), material: material}
}

func requestClientIdentity(request *http.Request) string {
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 || len(request.TLS.PeerCertificates[0].URIs) != 1 {
		return ""
	}
	return request.TLS.PeerCertificates[0].URIs[0].String()
}

type testCertificateAuthority struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	pem         []byte
}

type testTLSMaterial struct {
	directory         string
	serverCA          testCertificateAuthority
	clientCA          testCertificateAuthority
	serverCertificate tls.Certificate
	serverCertFile    string
	serverKeyFile     string
	serverCAFile      string
	clientCAFile      string
	clientCAPool      *x509.CertPool
	admittedCertFile  string
	admittedKeyFile   string
	deniedCertFile    string
	deniedKeyFile     string
}

func newTestTLSMaterial(t *testing.T) *testTLSMaterial {
	t.Helper()
	directory := t.TempDir()
	serverCA := newTestCA(t, "remote-conformance-server-ca")
	clientCA := newTestCA(t, "remote-conformance-client-ca")
	material := &testTLSMaterial{directory: directory, serverCA: serverCA, clientCA: clientCA}
	material.serverCAFile = material.write("server-ca.pem", serverCA.pem, 0o644)
	material.clientCAFile = material.write("client-ca.pem", clientCA.pem, 0o644)
	material.clientCAPool = x509.NewCertPool()
	material.clientCAPool.AddCert(clientCA.certificate)
	material.serverCertFile, material.serverKeyFile, material.serverCertificate = material.issueServer("server")
	material.admittedCertFile, material.admittedKeyFile, _ = material.issueClient("admitted", []string{admittedClientIdentity}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.deniedCertFile, material.deniedKeyFile, _ = material.issueClient("denied", []string{deniedClientIdentity}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return material
}

func newTestCA(t *testing.T, commonName string) testCertificateAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: randomSerial(t), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificateAuthority{
		certificate: certificate, privateKey: privateKey,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}),
	}
}

func (m *testTLSMaterial) issueServer(name string) (string, string, tls.Certificate) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: randomSerialValue(), Subject: pkix.Name{CommonName: testServerName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(testServerName)},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, m.serverCA.certificate, publicKey, m.serverCA.privateKey)
	if err != nil {
		panic(err)
	}
	certFile := m.write(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), 0o644)
	keyFile := m.write(name+"-key.pem", marshalPrivateKey(privateKey), 0o600)
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}
	return certFile, keyFile, certificate
}

func (m *testTLSMaterial) issueClient(name string, identities []string, usages []x509.ExtKeyUsage) (string, string, tls.Certificate) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	uriSANs := make([]*url.URL, len(identities))
	for index, identity := range identities {
		uriSANs[index], err = url.Parse(identity)
		if err != nil {
			panic(err)
		}
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: randomSerialValue(), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, URIs: uriSANs,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, m.clientCA.certificate, publicKey, m.clientCA.privateKey)
	if err != nil {
		panic(err)
	}
	certFile := m.write(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), 0o644)
	keyFile := m.write(name+"-key.pem", marshalPrivateKey(privateKey), 0o600)
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}
	return certFile, keyFile, certificate
}

func (m *testTLSMaterial) write(name string, contents []byte, mode os.FileMode) string {
	path := filepath.Join(m.directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		panic(err)
	}
	return path
}

func (m *testTLSMaterial) options(target string) Options {
	return Options{
		Target: target, CAFile: m.serverCAFile, ClientCAFile: m.clientCAFile,
		ClientCert: m.admittedCertFile, ClientKey: m.admittedKeyFile,
		DeniedClientCert: m.deniedCertFile, DeniedClientKey: m.deniedKeyFile,
		ServerName: testServerName, ProviderRevision: expectedProviderRevision,
	}
}

func marshalPrivateKey(privateKey ed25519.PrivateKey) []byte {
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func randomSerialValue() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(err)
	}
	return serial
}

func optionsWithRepository(t *testing.T, options *Options) {
	t.Helper()
	sourceRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	options.SourceRoot = sourceRoot
	options.LockPath = filepath.Join(sourceRoot, "compatibility", "sandbox-runtime", "contract.lock.json")
}

func testRunnerIdentity() RunnerIdentity {
	return RunnerIdentity{MainPath: runnerMainPath, Revision: strings.Repeat("a", 40), GoVersion: "go1.26.5", Modified: false}
}

func reservePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitForPort(t *testing.T, port int, startup <-chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for time.Now().Before(deadline) {
		select {
		case err := <-startup:
			t.Fatalf("Provider server exited during startup: %v", err)
		default:
		}
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Provider server did not start")
}

func cloneOptions(source Options, change func(*Options)) Options {
	copy := source
	change(&copy)
	return copy
}
