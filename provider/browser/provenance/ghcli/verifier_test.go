package ghcli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

type fakeRunner struct {
	path      string
	arguments []string
	output    []byte
	err       error
	calls     int
}

func (r *fakeRunner) Run(_ context.Context, path string, arguments []string) ([]byte, error) {
	r.calls++
	r.path = path
	r.arguments = append([]string(nil), arguments...)
	return append([]byte(nil), r.output...), r.err
}

func trustedExecutable(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gh")
	if err := os.WriteFile(path, []byte("pinned gh executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := digestExecutable(path, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	return path, digest
}

func verifierWithRunner(t *testing.T, runner commandRunner) (*Verifier, string, string) {
	t.Helper()
	path, digest := trustedExecutable(t)
	return &Verifier{executablePath: path, executableDigest: digest, runner: runner}, path, digest
}

func validVerification(publication browserimage.Publication) verification {
	repositoryURL := "https://github.com/" + publication.RepositoryName
	workflowIdentity := "https://" + publication.Workflow + "@" + workflowRef
	runInvocation := repositoryURL + "/actions/runs/33724368530/attempts/1"
	return verification{
		Attestation: json.RawMessage(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
		VerificationResult: verificationResult{
			Signature: verificationSignature{Certificate: certificate{
				BuildConfigDigest: publication.SourceCommit, BuildConfigURI: workflowIdentity,
				BuildSignerDigest: publication.SourceCommit, BuildSignerURI: workflowIdentity,
				BuildTrigger: publicationTrigger, GitHubWorkflowRef: workflowRef,
				GitHubWorkflowRepository: publication.RepositoryName, GitHubWorkflowSHA: publication.SourceCommit,
				GitHubWorkflowTrigger: publicationTrigger, Issuer: githubOIDCIssuer,
				RunInvocationURI: runInvocation, RunnerEnvironment: "github-hosted",
				SourceRepositoryDigest: publication.SourceCommit, SourceRepositoryRef: workflowRef,
				SourceRepositoryURI: repositoryURL, SourceRepositoryVisibilityAtSigning: "public",
				SubjectAlternativeName: workflowIdentity,
			}},
			Statement: statement{
				Type: "https://in-toto.io/Statement/v1", PredicateType: predicateTypeSLSAProvenance,
				Subject: []statementSubject{{Name: publication.Repository, Digest: map[string]string{
					"sha256": strings.TrimPrefix(publication.Digest, "sha256:"),
				}}},
				Predicate: predicate{
					BuildDefinition: buildDefinition{
						BuildType: "https://actions.github.io/buildtypes/workflow/v1",
						ExternalParameters: externalParameters{Workflow: workflowParameter{
							Path: ".github/workflows/browser-image.yml", Ref: workflowRef, Repository: repositoryURL,
						}},
						InternalParameters: internalParameters{GitHub: githubParameters{
							EventName: publicationTrigger, RunnerEnvironment: "github-hosted",
						}},
						ResolvedDependencies: []resolvedDependency{{
							URI:    "git+" + repositoryURL + "@" + workflowRef,
							Digest: map[string]string{"gitCommit": publication.SourceCommit},
						}},
					},
					RunDetails: runDetails{
						Builder: builder{ID: workflowIdentity}, Metadata: metadata{InvocationID: runInvocation},
					},
				},
			},
			VerifiedTimestamps: []json.RawMessage{json.RawMessage(`{"type":"transparency-log"}`)},
		},
	}
}

func encodedVerification(t *testing.T, results []verification) []byte {
	t.Helper()
	encoded, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestNewRequiresPinnedExecutable(t *testing.T) {
	path, digest := trustedExecutable(t)
	if verifier, err := New(Options{ExecutablePath: path, ExecutableDigest: digest}); err != nil || verifier.executablePath != path {
		t.Fatalf("New() = %#v, %v", verifier, err)
	}
	tests := map[string]Options{
		"relative path":   {ExecutablePath: "gh", ExecutableDigest: digest},
		"missing path":    {ExecutableDigest: digest},
		"missing digest":  {ExecutablePath: path},
		"invalid digest":  {ExecutablePath: path, ExecutableDigest: "sha256:abc"},
		"digest mismatch": {ExecutablePath: path, ExecutableDigest: "sha256:" + strings.Repeat("a", 64)},
		"missing binary":  {ExecutablePath: filepath.Join(t.TempDir(), "missing"), ExecutableDigest: digest},
	}
	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			if verifier, err := New(options); verifier != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("New() = %#v, %v", verifier, err)
			}
		})
	}
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	if verifier, err := New(Options{ExecutablePath: path, ExecutableDigest: digest}); verifier != nil || !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("writable executable New() = %#v, %v", verifier, err)
	}
}

func TestVerifyUsesExactConstraints(t *testing.T) {
	publication := browserimage.LockedPublication()
	runner := &fakeRunner{output: encodedVerification(t, []verification{validVerification(publication)})}
	verifier, path, _ := verifierWithRunner(t, runner)
	if err := verifier.Verify(context.Background(), publication); err != nil {
		t.Fatal(err)
	}
	if runner.path != path || runner.calls != 1 {
		t.Fatalf("runner path/calls = %q/%d", runner.path, runner.calls)
	}
	wantArguments := []string{
		"attestation", "verify", "oci://" + publication.Image(),
		"--hostname", "github.com", "--repo", publication.RepositoryName,
		"--signer-workflow", publication.Workflow, "--source-digest", publication.SourceCommit,
		"--deny-self-hosted-runners", "--predicate-type", predicateTypeSLSAProvenance,
		"--cert-oidc-issuer", githubOIDCIssuer, "--bundle-from-oci",
		"--limit", "2", "--format", "json",
	}
	if !reflect.DeepEqual(runner.arguments, wantArguments) {
		t.Fatalf("arguments = %#v", runner.arguments)
	}
}

func TestVerifyRejectsIdentityDrift(t *testing.T) {
	publication := browserimage.LockedPublication()
	tests := map[string]func(*verification){
		"missing attestation": func(result *verification) { result.Attestation = nil },
		"missing timestamp": func(result *verification) {
			result.VerificationResult.VerifiedTimestamps = nil
		},
		"runner": func(result *verification) {
			result.VerificationResult.Signature.Certificate.RunnerEnvironment = "self-hosted"
		},
		"run": func(result *verification) {
			result.VerificationResult.Signature.Certificate.RunInvocationURI = "https://github.com/example/actions/runs/1"
		},
		"source": func(result *verification) {
			result.VerificationResult.Signature.Certificate.SourceRepositoryDigest = strings.Repeat("0", 40)
		},
		"workflow": func(result *verification) {
			result.VerificationResult.Signature.Certificate.SubjectAlternativeName = "https://github.com/example/unsafe.yml@refs/heads/main"
		},
		"predicate": func(result *verification) {
			result.VerificationResult.Statement.PredicateType = "https://example.invalid/predicate"
		},
		"subject": func(result *verification) {
			result.VerificationResult.Statement.Subject[0].Digest["sha256"] = strings.Repeat("0", 64)
		},
		"builder": func(result *verification) {
			result.VerificationResult.Statement.Predicate.RunDetails.Builder.ID = "https://github.com/example/unsafe.yml@refs/heads/main"
		},
		"dependency": func(result *verification) {
			result.VerificationResult.Statement.Predicate.BuildDefinition.ResolvedDependencies[0].Digest["gitCommit"] = strings.Repeat("0", 40)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validVerification(publication)
			mutate(&result)
			runner := &fakeRunner{output: encodedVerification(t, []verification{result})}
			verifier, _, _ := verifierWithRunner(t, runner)
			if err := verifier.Verify(context.Background(), publication); !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestVerifyRejectsAmbiguousMalformedOrOversizedOutput(t *testing.T) {
	publication := browserimage.LockedPublication()
	valid := validVerification(publication)
	outputs := map[string][]byte{
		"empty":     nil,
		"malformed": []byte(`{"verificationResult":`),
		"trailing":  append(encodedVerification(t, []verification{valid}), []byte(` {}`)...),
		"ambiguous": encodedVerification(t, []verification{valid, valid}),
		"oversized": make([]byte, maxVerificationOutput+1),
	}
	for name, output := range outputs {
		t.Run(name, func(t *testing.T) {
			verifier, _, _ := verifierWithRunner(t, &fakeRunner{output: output})
			if err := verifier.Verify(context.Background(), publication); !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestVerifyPreservesContextAndHidesCommandFailure(t *testing.T) {
	publication := browserimage.LockedPublication()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakeRunner{}
	verifier, _, _ := verifierWithRunner(t, runner)
	if err := verifier.Verify(canceled, publication); !errors.Is(err, context.Canceled) || runner.calls != 0 {
		t.Fatalf("canceled Verify() = %v, calls=%d", err, runner.calls)
	}
	for name, commandErr := range map[string]error{
		"canceled": context.Canceled,
		"deadline": context.DeadlineExceeded,
		"private":  errors.New("registry credential private detail"),
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{err: commandErr}
			verifier, _, _ := verifierWithRunner(t, runner)
			err := verifier.Verify(context.Background(), publication)
			if errors.Is(commandErr, context.Canceled) || errors.Is(commandErr, context.DeadlineExceeded) {
				if !errors.Is(err, commandErr) {
					t.Fatalf("Verify() error = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrVerificationFailed) || strings.Contains(err.Error(), "private detail") {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestVerifyRejectsPublicationAndExecutableDriftBeforeExecution(t *testing.T) {
	publication := browserimage.LockedPublication()
	runner := &fakeRunner{output: encodedVerification(t, []verification{validVerification(publication)})}
	verifier, path, _ := verifierWithRunner(t, runner)
	drifted := publication
	drifted.SourceCommit = strings.Repeat("0", 40)
	if err := verifier.Verify(context.Background(), drifted); !errors.Is(err, ErrVerificationFailed) || runner.calls != 0 {
		t.Fatalf("publication drift = %v, calls=%d", err, runner.calls)
	}
	if err := os.WriteFile(path, []byte("replaced gh executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), publication); !errors.Is(err, ErrVerificationFailed) || runner.calls != 0 {
		t.Fatalf("executable drift = %v, calls=%d", err, runner.calls)
	}
}

func TestBoundedBufferRejectsOverflow(t *testing.T) {
	var buffer boundedBuffer
	if written, err := buffer.Write(make([]byte, maxVerificationOutput)); written != maxVerificationOutput || err != nil {
		t.Fatalf("bounded write = %d, %v", written, err)
	}
	if written, err := buffer.Write([]byte("x")); written != 0 || !errors.Is(err, errOutputTooLarge) {
		t.Fatalf("overflow write = %d, %v", written, err)
	}
}

func TestCommandEnvironmentAllowsOnlyVerifierDependencies(t *testing.T) {
	t.Setenv("GH_TOKEN", "short-lived-read-token")
	t.Setenv("SANDBOX_RUNTIME_PRIVATE_VALUE", "must-not-be-inherited")
	environment := map[string]string{}
	for _, entry := range commandEnvironment() {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("invalid environment entry %q", entry)
		}
		environment[key] = value
	}
	if environment["GH_TOKEN"] != "short-lived-read-token" || environment["GH_PROMPT_DISABLED"] != "1" ||
		environment["NO_COLOR"] != "1" {
		t.Fatalf("required environment = %#v", environment)
	}
	if _, inherited := environment["SANDBOX_RUNTIME_PRIVATE_VALUE"]; inherited {
		t.Fatal("unrelated control-plane environment was inherited")
	}
}
