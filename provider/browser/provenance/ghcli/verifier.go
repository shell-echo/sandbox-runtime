// Package ghcli verifies the locked Browser image provenance with the GitHub
// CLI and an attestation bundle attached to the immutable OCI image.
package ghcli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	browserdocker "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
)

const (
	maxExecutableBytes          = 256 << 20
	maxVerificationOutput       = 1 << 20
	predicateTypeSLSAProvenance = "https://slsa.dev/provenance/v1"
	githubOIDCIssuer            = "https://token.actions.githubusercontent.com"
	workflowRef                 = "refs/heads/main"
	publicationTrigger          = "workflow_dispatch"
)

var (
	ErrInvalidOptions       = errors.New("invalid Browser provenance verifier options")
	ErrVerificationFailed   = errors.New("Browser image provenance verification failed")
	errOutputTooLarge       = errors.New("provenance verifier output exceeds its limit")
	executableDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Options binds the verifier to one deployment-supplied GitHub CLI binary.
// The digest must be computed and distributed independently by the operator.
type Options struct {
	ExecutablePath   string
	ExecutableDigest string
}

type commandRunner interface {
	Run(context.Context, string, []string) ([]byte, error)
}

type Verifier struct {
	executablePath   string
	executableDigest string
	runner           commandRunner
}

func New(options Options) (*Verifier, error) {
	resolved, err := validateExecutable(options.ExecutablePath, options.ExecutableDigest)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	return &Verifier{
		executablePath: resolved, executableDigest: options.ExecutableDigest,
		runner: execRunner{},
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, publication browserimage.Publication) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil || v.runner == nil || publication.Validate() != nil {
		return ErrVerificationFailed
	}
	resolved, err := validateExecutable(v.executablePath, v.executableDigest)
	if err != nil || resolved != v.executablePath {
		return ErrVerificationFailed
	}
	output, err := v.runner.Run(ctx, v.executablePath, verificationArguments(publication))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrVerificationFailed
	}
	if len(output) == 0 || len(output) > maxVerificationOutput || verifyOutput(output, publication) != nil {
		return ErrVerificationFailed
	}
	return nil
}

func verificationArguments(publication browserimage.Publication) []string {
	return []string{
		"attestation", "verify", "oci://" + publication.Image(),
		"--hostname", "github.com",
		"--repo", publication.RepositoryName,
		"--signer-workflow", publication.Workflow,
		"--source-digest", publication.SourceCommit,
		"--deny-self-hosted-runners",
		"--predicate-type", predicateTypeSLSAProvenance,
		"--cert-oidc-issuer", githubOIDCIssuer,
		"--bundle-from-oci",
		"--limit", "2",
		"--format", "json",
	}
}

func validateExecutable(path, expectedDigest string) (string, error) {
	if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) ||
		!executableDigestPattern.MatchString(expectedDigest) {
		return "", ErrInvalidOptions
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil || !filepath.IsAbs(resolved) {
		return "", ErrInvalidOptions
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 ||
		info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 ||
		info.Size() <= 0 || info.Size() > maxExecutableBytes {
		return "", ErrInvalidOptions
	}
	actualDigest, err := digestExecutable(resolved, info.Size())
	if err != nil || subtle.ConstantTimeCompare([]byte(actualDigest), []byte(expectedDigest)) != 1 {
		return "", ErrInvalidOptions
	}
	return resolved, nil
}

func digestExecutable(path string, size int64) (string, error) {
	if size <= 0 || size > maxExecutableBytes {
		return "", ErrInvalidOptions
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxExecutableBytes+1))
	if err != nil || written != size || written > maxExecutableBytes {
		return "", ErrInvalidOptions
	}
	return "sha256:" + fmt.Sprintf("%x", hash.Sum(nil)), nil
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, executable string, arguments []string) ([]byte, error) {
	var output boundedBuffer
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = nil
	command.Stdout = &output
	command.Stderr = io.Discard
	command.Env = commandEnvironment()
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		return nil, err
	}
	return append([]byte(nil), output.Bytes()...), nil
}

func commandEnvironment() []string {
	const promptKey = "GH_PROMPT_DISABLED"
	const colorKey = "NO_COLOR"
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if allowedCommandEnvironment(key) {
			environment = append(environment, entry)
		}
	}
	return append(environment, promptKey+"=1", colorKey+"=1")
}

func allowedCommandEnvironment(key string) bool {
	switch key {
	case "ALL_PROXY", "DOCKER_CONFIG", "GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN",
		"HOME", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "PATH", "SSL_CERT_DIR",
		"SSL_CERT_FILE", "TEMP", "TMP", "TMPDIR", "USERPROFILE", "WINDIR",
		"XDG_CONFIG_HOME", "all_proxy", "https_proxy", "http_proxy", "no_proxy":
		return true
	default:
		return false
	}
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(value []byte) (int, error) {
	remaining := maxVerificationOutput - b.Len()
	if remaining <= 0 {
		return 0, errOutputTooLarge
	}
	if len(value) > remaining {
		written, _ := b.Buffer.Write(value[:remaining])
		return written, errOutputTooLarge
	}
	return b.Buffer.Write(value)
}

type verification struct {
	Attestation        json.RawMessage    `json:"attestation"`
	VerificationResult verificationResult `json:"verificationResult"`
}

type verificationResult struct {
	Signature          verificationSignature `json:"signature"`
	Statement          statement             `json:"statement"`
	VerifiedTimestamps []json.RawMessage     `json:"verifiedTimestamps"`
}

type verificationSignature struct {
	Certificate certificate `json:"certificate"`
}

type certificate struct {
	BuildConfigDigest                   string `json:"buildConfigDigest"`
	BuildConfigURI                      string `json:"buildConfigURI"`
	BuildSignerDigest                   string `json:"buildSignerDigest"`
	BuildSignerURI                      string `json:"buildSignerURI"`
	BuildTrigger                        string `json:"buildTrigger"`
	GitHubWorkflowRef                   string `json:"githubWorkflowRef"`
	GitHubWorkflowRepository            string `json:"githubWorkflowRepository"`
	GitHubWorkflowSHA                   string `json:"githubWorkflowSHA"`
	GitHubWorkflowTrigger               string `json:"githubWorkflowTrigger"`
	Issuer                              string `json:"issuer"`
	RunInvocationURI                    string `json:"runInvocationURI"`
	RunnerEnvironment                   string `json:"runnerEnvironment"`
	SourceRepositoryDigest              string `json:"sourceRepositoryDigest"`
	SourceRepositoryRef                 string `json:"sourceRepositoryRef"`
	SourceRepositoryURI                 string `json:"sourceRepositoryURI"`
	SourceRepositoryVisibilityAtSigning string `json:"sourceRepositoryVisibilityAtSigning"`
	SubjectAlternativeName              string `json:"subjectAlternativeName"`
}

type statement struct {
	Type          string             `json:"_type"`
	PredicateType string             `json:"predicateType"`
	Subject       []statementSubject `json:"subject"`
	Predicate     predicate          `json:"predicate"`
}

type statementSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type predicate struct {
	BuildDefinition buildDefinition `json:"buildDefinition"`
	RunDetails      runDetails      `json:"runDetails"`
}

type buildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   externalParameters   `json:"externalParameters"`
	InternalParameters   internalParameters   `json:"internalParameters"`
	ResolvedDependencies []resolvedDependency `json:"resolvedDependencies"`
}

type externalParameters struct {
	Workflow workflowParameter `json:"workflow"`
}

type workflowParameter struct {
	Path       string `json:"path"`
	Ref        string `json:"ref"`
	Repository string `json:"repository"`
}

type internalParameters struct {
	GitHub githubParameters `json:"github"`
}

type githubParameters struct {
	EventName         string `json:"event_name"`
	RunnerEnvironment string `json:"runner_environment"`
}

type resolvedDependency struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type runDetails struct {
	Builder  builder  `json:"builder"`
	Metadata metadata `json:"metadata"`
}

type builder struct {
	ID string `json:"id"`
}

type metadata struct {
	InvocationID string `json:"invocationId"`
}

func verifyOutput(output []byte, publication browserimage.Publication) error {
	decoder := json.NewDecoder(bytes.NewReader(output))
	var results []verification
	if err := decoder.Decode(&results); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrVerificationFailed
	}
	if len(results) != 1 {
		return ErrVerificationFailed
	}
	result := results[0]
	if len(result.Attestation) == 0 || string(result.Attestation) == "null" ||
		len(result.VerificationResult.VerifiedTimestamps) == 0 {
		return ErrVerificationFailed
	}
	for _, timestamp := range result.VerificationResult.VerifiedTimestamps {
		if len(timestamp) == 0 || string(timestamp) == "null" {
			return ErrVerificationFailed
		}
	}
	return verifyIdentity(result.VerificationResult, publication)
}

func verifyIdentity(result verificationResult, publication browserimage.Publication) error {
	repositoryURL := "https://github.com/" + publication.RepositoryName
	workflowURL := "https://" + publication.Workflow
	workflowIdentity := workflowURL + "@" + workflowRef
	runInvocation := repositoryURL + "/actions/runs/" + strconv.FormatInt(publication.RunID, 10) + "/attempts/1"
	workflowPrefix := "github.com/" + publication.RepositoryName + "/"
	workflowPath := strings.TrimPrefix(publication.Workflow, workflowPrefix)
	if workflowPath == publication.Workflow || workflowPath == "" {
		return ErrVerificationFailed
	}

	certificate := result.Signature.Certificate
	if certificate.BuildConfigDigest != publication.SourceCommit || certificate.BuildSignerDigest != publication.SourceCommit ||
		certificate.BuildConfigURI != workflowIdentity || certificate.BuildSignerURI != workflowIdentity ||
		certificate.SubjectAlternativeName != workflowIdentity || certificate.BuildTrigger != publicationTrigger ||
		certificate.GitHubWorkflowTrigger != publicationTrigger || certificate.GitHubWorkflowRef != workflowRef ||
		certificate.GitHubWorkflowRepository != publication.RepositoryName || certificate.GitHubWorkflowSHA != publication.SourceCommit ||
		certificate.Issuer != githubOIDCIssuer || certificate.RunnerEnvironment != "github-hosted" ||
		certificate.RunInvocationURI != runInvocation || certificate.SourceRepositoryDigest != publication.SourceCommit ||
		certificate.SourceRepositoryRef != workflowRef || certificate.SourceRepositoryURI != repositoryURL ||
		certificate.SourceRepositoryVisibilityAtSigning != "public" {
		return ErrVerificationFailed
	}

	statement := result.Statement
	if statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != predicateTypeSLSAProvenance ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != publication.Repository ||
		len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != strings.TrimPrefix(publication.Digest, "sha256:") {
		return ErrVerificationFailed
	}
	definition := statement.Predicate.BuildDefinition
	workflow := definition.ExternalParameters.Workflow
	github := definition.InternalParameters.GitHub
	if definition.BuildType != "https://actions.github.io/buildtypes/workflow/v1" ||
		workflow.Path != workflowPath || workflow.Ref != workflowRef || workflow.Repository != repositoryURL ||
		github.EventName != publicationTrigger || github.RunnerEnvironment != "github-hosted" ||
		len(definition.ResolvedDependencies) != 1 {
		return ErrVerificationFailed
	}
	dependency := definition.ResolvedDependencies[0]
	if dependency.URI != "git+"+repositoryURL+"@"+workflowRef || len(dependency.Digest) != 1 ||
		dependency.Digest["gitCommit"] != publication.SourceCommit ||
		statement.Predicate.RunDetails.Builder.ID != workflowIdentity ||
		statement.Predicate.RunDetails.Metadata.InvocationID != runInvocation {
		return ErrVerificationFailed
	}
	return nil
}

var _ browserdocker.ProvenanceVerifier = (*Verifier)(nil)
