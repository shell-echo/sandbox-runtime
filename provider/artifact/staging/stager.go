package staging

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Stager struct {
	outputs       artifact.OutputReader
	tenantBinding artifact.TenantBindingChecker
	activeContent artifact.ContentChecker
	malware       artifact.ContentChecker
	stagingRoot   string
	clock         Clock
}

func New(outputs artifact.OutputReader, tenantBinding artifact.TenantBindingChecker, activeContent, malware artifact.ContentChecker, stagingRoot string, clock Clock) (*Stager, error) {
	if outputs == nil || tenantBinding == nil || activeContent == nil || malware == nil || clock == nil {
		return nil, artifact.ErrUnsupportedChecks
	}
	root, err := prepareStagingRoot(stagingRoot)
	if err != nil {
		return nil, err
	}
	return &Stager{outputs: outputs, tenantBinding: tenantBinding, activeContent: activeContent, malware: malware, stagingRoot: root, clock: clock}, nil
}

func (s *Stager) CheckSupport(ctx context.Context, request artifact.Request) error {
	if ctx == nil {
		return context.Canceled
	}
	if s == nil || s.outputs == nil || s.tenantBinding == nil || s.activeContent == nil || s.malware == nil || s.clock == nil || s.stagingRoot == "" {
		return artifact.ErrUnsupportedChecks
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, checker := range []any{s.activeContent, s.malware} {
		if supported, ok := checker.(artifact.SupportChecker); ok {
			if err := supported.CheckSupport(ctx, request.Clone()); err != nil {
				return err
			}
		}
	}
	info, err := os.Lstat(s.stagingRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return artifact.ErrUnsupportedChecks
	}
	return nil
}

func (s *Stager) Stage(ctx context.Context, request artifact.Request, acceptedAt time.Time) (artifact.Evidence, error) {
	if err := s.CheckSupport(ctx, request); err != nil {
		return artifact.Evidence{}, err
	}
	now := s.clock.Now().UTC()
	acceptedAt = acceptedAt.UTC()
	evidenceExpiresAt := request.ExpiresAt(acceptedAt)
	if err := request.Validate(acceptedAt); err != nil || !request.Deadline.After(now) || !evidenceExpiresAt.After(now) {
		return artifact.Evidence{}, artifact.ErrDeadlineExpired
	}
	stageDeadline := request.Deadline
	if evidenceExpiresAt.Before(stageDeadline) {
		stageDeadline = evidenceExpiresAt
	}
	stageContext, cancel := context.WithTimeout(ctx, stageDeadline.Sub(now))
	defer cancel()
	ctx = stageContext
	tenantStatus, err := s.tenantBinding.CheckTenantBinding(ctx, request.Clone())
	if err != nil {
		return artifact.Evidence{}, err
	}
	if tenantStatus != artifact.CheckPassed {
		return artifact.Evidence{}, artifact.ErrTenantBinding
	}
	tenantCheck := artifact.Check{Status: artifact.CheckPassed, CheckedAt: s.clock.Now().UTC()}

	output, err := s.outputs.OpenOutput(ctx, request.SandboxID, request.ExpectedGeneration, request.SourcePath)
	if err != nil {
		return artifact.Evidence{}, err
	}
	if output.Content == nil || output.SizeBytes < 0 || output.SizeBytes > artifact.MaxArtifactBytes {
		if output.Content != nil {
			_ = output.Content.Close()
		}
		return artifact.Evidence{}, artifact.ErrInvalidEvidence
	}
	defer output.Content.Close()
	content, err := io.ReadAll(io.LimitReader(output.Content, artifact.MaxArtifactBytes+1))
	if err != nil || int64(len(content)) != output.SizeBytes || len(content) > artifact.MaxArtifactBytes {
		return artifact.Evidence{}, artifact.ErrOutcomeUnknown
	}
	if err := ctx.Err(); err != nil {
		return artifact.Evidence{}, err
	}

	observedAt := s.clock.Now().UTC()
	if !evidenceExpiresAt.After(observedAt) {
		return artifact.Evidence{}, artifact.ErrDeadlineExpired
	}
	evidence := artifact.Evidence{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.SandboxID, ArtifactReference: request.ArtifactReference,
		ContentDigest: digest(content), MediaType: detectMediaType(request.SourcePath, content), SizeBytes: output.SizeBytes,
		TenantBindingCheck: tenantCheck,
		ActiveContentCheck: artifact.Check{Status: artifact.CheckNotRun, CheckedAt: observedAt},
		MalwareCheck:       artifact.Check{Status: artifact.CheckNotRun, CheckedAt: observedAt},
		ObservedAt:         observedAt, ExpiresAt: evidenceExpiresAt,
	}
	contentMatches := evidence.ContentDigest == request.ExpectedDigest && evidence.MediaType == request.ExpectedMediaType && evidence.SizeBytes <= request.MaxBytes
	if !contentMatches {
		return finishEvidence(evidence, artifact.StatusRejected)
	}

	evidence.ActiveContentCheck.CheckedAt = s.clock.Now().UTC()
	evidence.ActiveContentCheck.Status, err = s.activeContent.CheckContent(ctx, request.Clone(), content)
	if err != nil {
		return artifact.Evidence{}, err
	}
	evidence.ObservedAt = s.clock.Now().UTC()
	if !evidenceExpiresAt.After(evidence.ObservedAt) {
		return artifact.Evidence{}, artifact.ErrDeadlineExpired
	}
	if evidence.ActiveContentCheck.Status != artifact.CheckPassed {
		return finishEvidence(evidence, artifact.StatusRejected)
	}
	evidence.MalwareCheck.CheckedAt = s.clock.Now().UTC()
	evidence.MalwareCheck.Status, err = s.malware.CheckContent(ctx, request.Clone(), content)
	if err != nil {
		return artifact.Evidence{}, err
	}
	evidence.ObservedAt = s.clock.Now().UTC()
	if !evidenceExpiresAt.After(evidence.ObservedAt) {
		return artifact.Evidence{}, artifact.ErrDeadlineExpired
	}
	if evidence.MalwareCheck.Status != artifact.CheckPassed {
		return finishEvidence(evidence, artifact.StatusRejected)
	}
	if err := ctx.Err(); err != nil {
		return artifact.Evidence{}, err
	}
	stagingReference, err := s.stageBytes(ctx, request, content)
	if err != nil {
		return artifact.Evidence{}, err
	}
	evidence.StagingReference = stagingReference
	evidence.ObservedAt = s.clock.Now().UTC()
	if !evidenceExpiresAt.After(evidence.ObservedAt) {
		return artifact.Evidence{}, artifact.ErrOutcomeUnknown
	}
	return finishEvidence(evidence, artifact.StatusStaged)
}

func (s *Stager) stageBytes(ctx context.Context, request artifact.Request, content []byte) (string, error) {
	root, err := os.OpenRoot(s.stagingRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	keySum := sha256.Sum256([]byte(request.OperationID + "\x00" + request.AttemptID + "\x00" + request.RequestDigest))
	key := hex.EncodeToString(keySum[:])
	destination := key + ".artifact"
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	temporary := ".stage-" + hex.EncodeToString(random[:]) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = root.Remove(temporary)
		}
	}()
	if err := writeAll(ctx, file, content); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := root.Link(temporary, destination); err != nil {
		return "", err
	}
	if err := root.Remove(temporary); err != nil {
		_ = root.Remove(destination)
		return "", err
	}
	cleanupTemporary = false
	directory, err := root.Open(".")
	if err != nil {
		_ = root.Remove(destination)
		return "", err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil || ctx.Err() != nil {
		_ = root.Remove(destination)
		return "", errors.Join(syncErr, closeErr, ctx.Err())
	}
	return "ref:staging/" + key, nil
}

func finishEvidence(evidence artifact.Evidence, status artifact.Status) (artifact.Evidence, error) {
	evidence.Status = status
	evidence.EvidenceDigest = evidenceDigest(evidence)
	if err := evidence.Validate(evidence.ObservedAt); err != nil {
		return artifact.Evidence{}, err
	}
	return evidence, nil
}

func evidenceDigest(evidence artifact.Evidence) string {
	evidence.EvidenceDigest = ""
	encoded, _ := json.Marshal(evidence)
	return digest(encoded)
}

func detectMediaType(sourcePath string, content []byte) string {
	detected := mime.TypeByExtension(filepath.Ext(sourcePath))
	if detected == "" {
		detected = http.DetectContentType(content)
	}
	mediaType, _, err := mime.ParseMediaType(detected)
	if err != nil || mediaType == "" {
		return "application/octet-stream"
	}
	return strings.ToLower(mediaType)
}

func writeAll(ctx context.Context, writer io.Writer, content []byte) error {
	for len(content) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := content
		if len(chunk) > 64<<10 {
			chunk = chunk[:64<<10]
		}
		written, err := writer.Write(chunk)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func prepareStagingRoot(configured string) (string, error) {
	if strings.TrimSpace(configured) == "" {
		return "", artifact.ErrUnsupportedChecks
	}
	root := filepath.Clean(configured)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("prepare artifact staging root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", artifact.ErrUnsupportedChecks
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var _ artifact.Stager = (*Stager)(nil)
var _ artifact.SupportChecker = (*Stager)(nil)
