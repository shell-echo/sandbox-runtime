// Package memory provides a concurrency-safe artifact staging adapter for
// tests and single-process development. It is not a publication store or a
// multi-controller implementation.
package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"mime"
	"path/filepath"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

var (
	ErrNotFound = artifact.ErrSourceMissing
	ErrConflict = errors.New("artifact staging evidence conflict")
	ErrClosed   = errors.New("artifact staging adapter is closed")
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// CheckFunc represents one provider-local safety check. The calling platform
// still owns authorization and final publication policy.
type CheckFunc func(context.Context, []byte) (artifact.CheckStatus, error)

type Adapter struct {
	mu            sync.RWMutex
	clock         Clock
	files         map[string][]byte
	tenantBound   bool
	activeContent CheckFunc
	malware       CheckFunc
	evidence      map[string]record
	closed        bool
}

type record struct {
	request  artifact.Request
	evidence artifact.Evidence
}

func NewAdapter(clock Clock, files map[string][]byte, tenantBound bool, activeContent, malware CheckFunc) (*Adapter, error) {
	if clock == nil || activeContent == nil || malware == nil {
		return nil, errors.New("artifact memory adapter dependencies are required")
	}
	copyFiles := make(map[string][]byte, len(files))
	for path, content := range files {
		copyFiles[path] = append([]byte(nil), content...)
	}
	return &Adapter{clock: clock, files: copyFiles, tenantBound: tenantBound, activeContent: activeContent, malware: malware, evidence: make(map[string]record)}, nil
}

func (a *Adapter) Stage(ctx context.Context, request artifact.Request, acceptedAt time.Time) (artifact.Evidence, error) {
	if err := contextError(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	now := a.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return artifact.Evidence{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return artifact.Evidence{}, ErrClosed
	}
	if previous, ok := a.evidence[request.OperationID]; ok {
		if !sameRequest(previous.request, request) {
			return artifact.Evidence{}, ErrConflict
		}
		return previous.evidence, nil
	}
	content, ok := a.files[request.SourcePath]
	if !ok {
		return artifact.Evidence{}, ErrNotFound
	}
	content = append([]byte(nil), content...)
	evidence := artifact.Evidence{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.SandboxID, ArtifactReference: request.ArtifactReference,
		ContentDigest: digest(content), MediaType: mime.TypeByExtension(filepath.Ext(request.SourcePath)), SizeBytes: int64(len(content)),
		TenantBindingCheck: artifact.Check{Status: artifact.CheckFailed, CheckedAt: now},
		ActiveContentCheck: artifact.Check{Status: artifact.CheckNotRun, CheckedAt: now},
		MalwareCheck:       artifact.Check{Status: artifact.CheckNotRun, CheckedAt: now},
		ObservedAt:         now, ExpiresAt: request.ExpiresAt(acceptedAt), EvidenceDigest: digest([]byte(request.OperationID + ":" + digest(content))),
	}
	if evidence.MediaType == "" {
		evidence.MediaType = "application/octet-stream"
	}
	if a.tenantBound {
		evidence.TenantBindingCheck.Status = artifact.CheckPassed
	}
	contentMatches := evidence.ContentDigest == request.ExpectedDigest && evidence.MediaType == request.ExpectedMediaType && evidence.SizeBytes <= request.MaxBytes
	if contentMatches {
		evidence.ActiveContentCheck.Status = check(ctx, a.activeContent, content)
		evidence.MalwareCheck.Status = check(ctx, a.malware, content)
		if err := contextError(ctx); err != nil {
			return artifact.Evidence{}, err
		}
	}
	if contentMatches && evidence.TenantBindingCheck.Status == artifact.CheckPassed && evidence.ActiveContentCheck.Status == artifact.CheckPassed && evidence.MalwareCheck.Status == artifact.CheckPassed {
		evidence.Status = artifact.StatusStaged
		evidence.StagingReference = "ref:staging/" + request.OperationID
	} else {
		evidence.Status = artifact.StatusRejected
	}
	if err := evidence.Validate(now); err != nil {
		return artifact.Evidence{}, err
	}
	a.evidence[request.OperationID] = record{request: request.Clone(), evidence: evidence}
	return evidence, nil
}

func (a *Adapter) Get(ctx context.Context, operationID string) (artifact.Evidence, error) {
	if err := contextError(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return artifact.Evidence{}, ErrClosed
	}
	stored, ok := a.evidence[operationID]
	if !ok {
		return artifact.Evidence{}, ErrNotFound
	}
	if !a.clock.Now().UTC().Before(stored.evidence.ExpiresAt) {
		return artifact.Evidence{}, artifact.ErrEvidenceExpired
	}
	return stored.evidence, nil
}

func (a *Adapter) GetEvidence(ctx context.Context, operationID string, now time.Time) (artifact.Evidence, error) {
	if err := contextError(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return artifact.Evidence{}, ErrClosed
	}
	stored, ok := a.evidence[operationID]
	if !ok {
		return artifact.Evidence{}, artifact.ErrEvidenceNotFound
	}
	if now.IsZero() || !now.UTC().Before(stored.evidence.ExpiresAt) {
		return artifact.Evidence{}, artifact.ErrEvidenceExpired
	}
	return stored.evidence, nil
}

func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func check(ctx context.Context, fn CheckFunc, content []byte) artifact.CheckStatus {
	status, err := fn(ctx, content)
	if err != nil {
		return artifact.CheckFailed
	}
	return status
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var _ artifact.Stager = (*Adapter)(nil)
var _ artifact.EvidenceReader = (*Adapter)(nil)

func sameRequest(left, right artifact.Request) bool {
	return left.SandboxID == right.SandboxID && left.TenantID == right.TenantID && left.OperationID == right.OperationID && left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken && left.ExpectedGeneration == right.ExpectedGeneration && left.IdempotencyKey == right.IdempotencyKey && left.RequestDigest == right.RequestDigest && left.Deadline.Equal(right.Deadline) && left.ArtifactReference == right.ArtifactReference && left.SourcePath == right.SourcePath && left.ExpectedDigest == right.ExpectedDigest && left.ExpectedMediaType == right.ExpectedMediaType && left.MaxBytes == right.MaxBytes && left.Retention == right.Retention
}
