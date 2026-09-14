// Package qualificationsupervisor implements bounded local adapter preflight,
// process ownership, protocol observation and sanitized transcript evidence.
// Disposable-harness orchestration, independent observations and external
// qualification remain separate gates.
package qualificationsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	ErrUnsupportedPlatform = errors.New("adapter executable preflight requires Darwin or Linux")
	ErrExecutable          = errors.New("adapter executable preflight failed")
)

// MaxExecutableBytes is a local preflight safety ceiling, not a Provider wire
// limit. The operator must also supply a positive, no-larger per-artifact bound.
const MaxExecutableBytes int64 = 1 << 30

// Executable holds a read-only descriptor and its preflight identity. It is
// single-owner; Close and Recheck must not race. No descriptor, host path, or
// inode is exported into evidence. This is not an immutable executable snapshot.
type Executable struct {
	claim  *custodyClaim
	budget *runBudget
	file   *os.File
	path   string
	stat   os.FileInfo
	digest string
	limit  int64
}

// ExecutableIdentity is a sanitized snapshot of the successful initial check.
type ExecutableIdentity struct {
	Digest string
	Bytes  int64
}

func supportedPlatform(goos string) bool { return goos == "darwin" || goos == "linux" }

// OpenExecutable does no PATH lookup, shell expansion, symlink resolution or
// process execution. Every path component must be non-symlink. Files must be
// regular, singly linked, executable by some class, free of set-id bits and not
// group/other writable. These are local supervisor admission restrictions.
// The operator must keep the artifact and directory namespace under trusted
// custody until execution ends. Neither this check nor Recheck eliminates a
// malicious owner's concurrent write/rename race with a future exec operation.
// OpenExecutable binds this read to the same run budget as the prepared static
// configuration. It may be the first preflight read and therefore starts that
// budget immediately before opening the artifact.
func OpenExecutable(ctx context.Context, prepared *PreparedConfiguration, path, expectedDigest string, maxBytes int64) (*Executable, error) {
	if !supportedPlatform(runtime.GOOS) {
		return nil, ErrUnsupportedPlatform
	}
	if ctx == nil || prepared == nil || prepared.budget == nil {
		return nil, ErrExecutable
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 ||
		maxBytes <= 0 || maxBytes > MaxExecutableBytes || !validDigest(expectedDigest) {
		return nil, ErrExecutable
	}
	runContext, err := prepared.budget.startContext()
	if err != nil {
		return nil, err
	}
	operationContext, release, err := clippedContext(runContext, ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx = operationContext
	f, err := openNoFollow(path)
	if err != nil {
		return nil, ErrExecutable
	}
	before, err := f.Stat()
	if err != nil || !admissibleFile(before, maxBytes) {
		_ = f.Close()
		return nil, ErrExecutable
	}
	executable := &Executable{claim: &custodyClaim{}, budget: prepared.budget, file: f, path: path, stat: before, digest: expectedDigest, limit: maxBytes}
	if err := executable.Recheck(ctx); err != nil {
		_ = executable.Close()
		return nil, err
	}
	return executable, nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Identity returns the initial snapshot, not proof that a process executed it.
func (e *Executable) Identity() ExecutableIdentity {
	if e == nil || e.stat == nil {
		return ExecutableIdentity{}
	}
	return ExecutableIdentity{Digest: e.digest, Bytes: e.stat.Size()}
}

// Recheck rehashes the held file and verifies the current no-follow pathname
// still identifies it. It detects specified replacement/content/mode changes;
// it cannot attest loadability, interpreters, dynamic libraries, mount policy or
// future process identity. Cancellation is checked between bounded reads, not
// inside a potentially kernel-blocked local filesystem syscall.
func (e *Executable) Recheck(ctx context.Context) error {
	if ctx == nil || e == nil || e.file == nil {
		return ErrExecutable
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	before, err := e.file.Stat()
	if err != nil || !admissibleFile(before, e.limit) || !sameSnapshot(e.stat, before) {
		return ErrExecutable
	}
	digest, n, err := digestReader(ctx, io.NewSectionReader(e.file, 0, e.limit+1), e.limit)
	if err != nil {
		return err
	}
	if digest != e.digest || n != before.Size() {
		return ErrExecutable
	}
	after, err := e.file.Stat()
	if err != nil || !admissibleFile(after, e.limit) || !sameSnapshot(before, after) {
		return ErrExecutable
	}
	current, err := openNoFollow(e.path)
	if err != nil {
		return ErrExecutable
	}
	currentInfo, statErr := current.Stat()
	closeErr := current.Close()
	if statErr != nil || closeErr != nil || !admissibleFile(currentInfo, e.limit) || !sameSnapshot(after, currentInfo) {
		return ErrExecutable
	}
	return contextFailure(ctx)
}

func sameSnapshot(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime())
}

func digestReader(ctx context.Context, r io.Reader, limit int64) (string, int64, error) {
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	r = io.LimitReader(r, limit+1)
	for {
		if err := contextFailure(ctx); err != nil {
			return "", 0, err
		}
		n, err := r.Read(buffer)
		total += int64(n)
		if total > limit {
			return "", 0, ErrExecutable
		}
		_, _ = h.Write(buffer[:n])
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return "", 0, ErrExecutable
			}
			if err := contextFailure(ctx); err != nil {
				return "", 0, err
			}
			return "sha256:" + hex.EncodeToString(h.Sum(nil)), total, nil
		}
		if n == 0 {
			return "", 0, ErrExecutable
		}
	}
}

func (e *Executable) Close() error {
	if e == nil || e.file == nil {
		return nil
	}
	f := e.file
	e.file = nil
	if f.Close() != nil {
		return ErrExecutable
	}
	return nil
}
