package artifact

import (
	"errors"
	"testing"
	"time"
)

var artifactTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func validArtifactRequest() Request {
	return Request{
		SandboxID: "sandbox-1", TenantID: "tenant-1", OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1",
		FencingToken: 3, ExpectedGeneration: 4, IdempotencyKey: "artifact-idempotency-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      artifactTestNow.Add(time.Hour), ArtifactReference: "artifact-ref:platform/artifact-1",
		SourcePath: "/outputs/report.json", ExpectedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedMediaType: "application/json", MaxBytes: 1 << 20, Retention: 30 * time.Minute,
	}
}

func validArtifactEvidence() Evidence {
	return Evidence{
		OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1", FencingToken: 3, SandboxID: "sandbox-1",
		ArtifactReference: "artifact-ref:platform/artifact-1", StagingReference: "ref:staging/artifact-1", Status: StatusStaged,
		ContentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MediaType: "application/json", SizeBytes: 512,
		TenantBindingCheck: Check{Status: CheckPassed, CheckedAt: artifactTestNow}, ActiveContentCheck: Check{Status: CheckPassed, CheckedAt: artifactTestNow}, MalwareCheck: Check{Status: CheckPassed, CheckedAt: artifactTestNow},
		ObservedAt: artifactTestNow, ExpiresAt: artifactTestNow.Add(time.Hour), EvidenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
}

func TestRequestValidateBoundsAndExpiry(t *testing.T) {
	request := validArtifactRequest()
	if err := request.Validate(artifactTestNow); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Request){
		"output traversal":          func(r *Request) { r.SourcePath = "/outputs/../etc/passwd" },
		"public artifact reference": func(r *Request) { r.ArtifactReference = "https://public.invalid/artifact" },
		"wrong digest":              func(r *Request) { r.ExpectedDigest = "sha256:bad" },
		"oversized":                 func(r *Request) { r.MaxBytes = MaxArtifactBytes + 1 },
		"retention past deadline":   func(r *Request) { r.Retention = 2 * time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if err := candidate.Validate(artifactTestNow); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestEvidenceRequiresPassedChecksAndRejectsExpiry(t *testing.T) {
	evidence := validArtifactEvidence()
	if err := evidence.Validate(artifactTestNow); err != nil {
		t.Fatal(err)
	}
	evidence.ActiveContentCheck.Status = CheckNotRun
	if !errors.Is(evidence.Validate(artifactTestNow), ErrInvalidEvidence) {
		t.Fatal("staged evidence with incomplete check was accepted")
	}
	evidence = validArtifactEvidence()
	if !errors.Is(evidence.Validate(evidence.ExpiresAt), ErrEvidenceExpired) {
		t.Fatal("expired evidence was not rejected")
	}
}
