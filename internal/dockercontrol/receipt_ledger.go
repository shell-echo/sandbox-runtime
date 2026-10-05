package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const MaxReceiptStateBytes = 32 << 20

var ErrReceiptReplay = errors.New("private Docker-control create already recorded; inspect only")

// CodingReceiptLedger is an offline durability primitive, not an activated
// Docker-control daemon. Its lock belongs to one process for the ledger's
// entire lifetime; the separate, explicit initializer never recreates a
// missing ledger after a crash or operator error.
type CodingReceiptLedger struct {
	mu              sync.Mutex
	path            string
	binding         CodingReceiptBinding
	lock            *os.File
	current         CodingReceiptState
	clock           func() time.Time
	writeFault      func(string) error // test-only deterministic fsync/rename fault hook
	completionStage func(string)       // test-only timing/cancellation boundary hook
	cleanupStage    func(string)       // test-only cleanup evidence/commit boundary hook
	// A returned, non-ambiguous create callback is an in-process qualification
	// only. Reopen deliberately loses it: an old Unknown cannot be completed
	// from a stale snapshot after a restart without a separate recovery fence.
	createReturned     map[string]bool
	completionInFlight bool
	cleanupInFlight    bool
	inFlight           int
	drained            chan struct{}
	closed             bool
}

// InitializeCodingReceiptLedger is a one-time ceremony. The callback must
// independently prove the exact physical namespace is empty; it cannot be a
// Docker-control receipt or a presumed clean local directory. It runs after
// the permanent lock marker is created, so an interrupted ceremony fails
// closed instead of silently being retried with a new empty ledger.
func InitializeCodingReceiptLedger(ctx context.Context, path string, binding CodingReceiptBinding,
	confirmCleanNamespace func(context.Context) error) (*CodingReceiptLedger, error) {
	if ctx == nil || ctx.Err() != nil || confirmCleanNamespace == nil ||
		!validReceiptPath(path) || binding.Validate() != nil {
		return nil, ErrInvalidReceiptState
	}
	binding = binding.clone()
	// An existing lock is an initialization marker even when its state file
	// disappeared. Do not create a fresh empty ledger over Unknown effects.
	fd, err := syscall.Open(path+".lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrInvalidReceiptState
	}
	lock := os.NewFile(uintptr(fd), path+".lock")
	if !validReceiptLock(lock) || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = lock.Close()
		return nil, ErrInvalidReceiptState
	}
	ledger := &CodingReceiptLedger{path: path, binding: binding, lock: lock, clock: time.Now,
		createReturned: make(map[string]bool)}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		_ = ledger.Close()
		return nil, ErrInvalidReceiptState
	}
	if confirmCleanNamespace(ctx) != nil || ctx.Err() != nil {
		_ = ledger.Close()
		return nil, ErrInvalidReceiptState
	}
	state, err := NewCodingReceiptState(binding)
	if err != nil || writeReceiptState(path, state) != nil {
		_ = ledger.Close()
		return nil, ErrInvalidReceiptState
	}
	ledger.current = state
	return ledger, nil
}

func OpenCodingReceiptLedger(path string, binding CodingReceiptBinding) (*CodingReceiptLedger, error) {
	if !validReceiptPath(path) || binding.Validate() != nil {
		return nil, ErrInvalidReceiptState
	}
	binding = binding.clone()
	fd, err := syscall.Open(path+".lock", syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidReceiptState
	}
	lock := os.NewFile(uintptr(fd), path+".lock")
	if !validReceiptLock(lock) || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = lock.Close()
		return nil, ErrInvalidReceiptState
	}
	state, err := readReceiptState(path, binding)
	if err != nil || validateCommittedCompletionEvidence(path, state) != nil ||
		validateCommittedReleaseEvidence(path, state, binding) != nil {
		_ = lock.Close()
		return nil, ErrInvalidReceiptState
	}
	return &CodingReceiptLedger{path: path, binding: binding, lock: lock, current: state,
		clock: time.Now, createReturned: make(map[string]bool)}, nil
}

func (l *CodingReceiptLedger) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), MaxAuthorityAge+5*time.Second)
	defer cancel()
	return l.CloseContext(ctx)
}

// CloseContext stops new dispatches, waits for physical callbacks, and only
// then releases the one-writer lock. A timed-out close keeps that lock and may
// be retried; it never reports quiescence while a callback can still run.
func (l *CodingReceiptLedger) CloseContext(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrInvalidReceiptState
	}
	l.mu.Lock()
	if l.lock == nil {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	for l.inFlight != 0 {
		wait := l.drained
		l.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
		l.mu.Lock()
	}
	if l.lock == nil {
		l.mu.Unlock()
		return nil
	}
	lock := l.lock
	l.lock = nil
	l.mu.Unlock()
	return lock.Close()
}

// DispatchCodingCreate commits Unknown before the callback can begin. A
// callback failure, process crash or ambiguous file-sync error never restores
// the one-time permit. A replay can only use read-only Lookup.
func (l *CodingReceiptLedger) DispatchCodingCreate(ctx context.Context, authority CodingCreateAuthority,
	physical func(context.Context, CodingCreateAuthority) error) (CodingReceipt, error) {
	if l == nil || ctx == nil || physical == nil || ctx.Err() != nil {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.mu.Lock()
	if l.checkDiskLocked() != nil || l.completionInFlight || l.cleanupInFlight {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	now := l.clock().UTC()
	next, receipt, fresh, err := l.current.beginUnknown(l.binding, authority, now)
	if err != nil {
		l.mu.Unlock()
		return CodingReceipt{}, err
	}
	if !fresh {
		l.mu.Unlock()
		return receipt, ErrReceiptReplay
	}
	if ctx.Err() != nil {
		l.mu.Unlock()
		return CodingReceipt{}, ctx.Err()
	}
	if writeReceiptStateWithFault(l.path, next, l.writeFault) != nil {
		// Atomic rename or directory sync might have happened already. Never
		// grant a permit after an ambiguous persistence failure.
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.current = next
	if ctx.Err() != nil {
		l.mu.Unlock()
		return receipt, ctx.Err()
	}
	if authority.Validate(l.clock().UTC()) != nil {
		l.mu.Unlock()
		return receipt, ErrInvalidAuthority
	}
	physicalContext, cancel := context.WithDeadline(ctx, authority.ExpiresAt)
	if physicalContext.Err() != nil {
		l.mu.Unlock()
		cancel()
		return receipt, physicalContext.Err()
	}
	if l.inFlight == 0 {
		l.drained = make(chan struct{})
	}
	l.inFlight++
	l.mu.Unlock()
	defer func() {
		cancel()
		l.mu.Lock()
		l.inFlight--
		if l.inFlight == 0 {
			close(l.drained)
		}
		l.mu.Unlock()
	}()
	if ctx.Err() != nil || authority.Validate(l.clock().UTC()) != nil || physicalContext.Err() != nil {
		return receipt, ErrInvalidAuthority
	}
	physicalErr := physical(physicalContext, authority)
	if physicalErr == nil {
		if ctx.Err() != nil || physicalContext.Err() != nil || authority.Validate(l.clock().UTC()) != nil {
			return receipt, ErrInvalidAuthority
		}
		l.mu.Lock()
		l.createReturned[authority.EffectID] = true
		l.mu.Unlock()
	}
	return receipt, physicalErr
}

// DispatchCodingCleanup commits the separate fenced retirement intent before
// its callback can delete anything. It only admits an already Completed
// create receipt and requires local callbacks to have drained. Neither that
// drain nor a successful callback proves daemon-side quiescence or resource
// absence: physical cleanup must separately obtain those proofs, and this
// method never marks a receipt Released.
func (l *CodingReceiptLedger) DispatchCodingCleanup(ctx context.Context, createRequestID string,
	intent CodingCleanupAuthority, physical func(context.Context, CodingCleanupAuthority) error) (CodingReceipt, error) {
	if l == nil || ctx == nil || physical == nil || ctx.Err() != nil {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.mu.Lock()
	if l.checkDiskLocked() != nil || l.inFlight != 0 || l.completionInFlight || l.cleanupInFlight {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	now := l.clock().UTC()
	next, receipt, fresh, err := l.current.beginCleanup(l.binding, createRequestID, intent, now)
	if err != nil {
		l.mu.Unlock()
		return CodingReceipt{}, err
	}
	if !fresh {
		l.mu.Unlock()
		return receipt, ErrReceiptReplay
	}
	if ctx.Err() != nil {
		l.mu.Unlock()
		return CodingReceipt{}, ctx.Err()
	}
	if writeReceiptStateWithFault(l.path, next, l.writeFault) != nil {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.current = next
	if ctx.Err() != nil {
		l.mu.Unlock()
		return receipt, ctx.Err()
	}
	if intent.Validate(l.clock().UTC()) != nil {
		l.mu.Unlock()
		return receipt, ErrInvalidAuthority
	}
	physicalContext, cancel := context.WithDeadline(ctx, intent.ExpiresAt)
	if physicalContext.Err() != nil {
		l.mu.Unlock()
		cancel()
		return receipt, physicalContext.Err()
	}
	l.drained = make(chan struct{})
	l.cleanupInFlight = true
	l.inFlight++
	l.mu.Unlock()
	defer func() {
		cancel()
		l.mu.Lock()
		l.cleanupInFlight = false
		l.inFlight--
		if l.inFlight == 0 {
			close(l.drained)
		}
		l.mu.Unlock()
	}()
	if ctx.Err() != nil || intent.Validate(l.clock().UTC()) != nil || physicalContext.Err() != nil {
		return receipt, ErrInvalidAuthority
	}
	return receipt, physical(physicalContext, intent)
}

func (l *CodingReceiptLedger) Lookup(requestID string) (CodingReceipt, error) {
	receipt, _, _, err := l.LookupProjection(requestID)
	return receipt, err
}

// LookupProjection takes the receipt and its enclosing Control state seal
// under one ledger lock. A wire status handler must not combine Lookup with a
// later, independently sampled revision/digest: another effect can commit in
// between and make that projection claim a state it never observed.
func (l *CodingReceiptLedger) LookupProjection(requestID string) (CodingReceipt, uint64, string, error) {
	if l == nil || !controlDigest.MatchString(requestID) {
		return CodingReceipt{}, 0, "", ErrInvalidReceiptState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.checkDiskLocked() != nil {
		return CodingReceipt{}, 0, "", ErrInvalidReceiptState
	}
	for _, receipt := range l.current.Records {
		if receipt.Authority.RequestID == requestID {
			if receipt.Status == ReceiptReleased &&
				validateReleaseEvidenceForReceipt(l.path, l.current.Revision,
					receipt, l.binding) != nil {
				return CodingReceipt{}, 0, "", ErrInvalidReceiptState
			}
			return receipt, l.current.Revision, l.current.StateDigest, nil
		}
	}
	return CodingReceipt{}, 0, "", os.ErrNotExist
}

// LookupBoundProjection is the Control-owned, read-only status entry. It
// checks the historical create authority against this ledger's frozen plan,
// policy and the authenticated Provider principal before looking up the
// original request. Expiry does not grant a new mutation permit here.
func (l *CodingReceiptLedger) LookupBoundProjection(authority CodingCreateAuthority,
	authenticatedPeerDigest string, now time.Time,
) (CodingReceipt, uint64, string, error) {
	if l == nil || now.IsZero() || authority.IssuedAt.After(now) ||
		authenticatedPeerDigest != l.binding.PeerPrincipalDigest ||
		authority.BindControl(l.binding.Plan, l.binding.ControlPolicyDigest,
			authenticatedPeerDigest, l.binding.SpecBySlot[authority.SlotID], authority.IssuedAt) != nil {
		return CodingReceipt{}, 0, "", ErrInvalidAuthority
	}
	receipt, revision, stateDigest, err := l.LookupProjection(authority.RequestID)
	if err != nil {
		return CodingReceipt{}, 0, "", err
	}
	if receipt.Authority != authority || receipt.AuthorityDigest != authority.Digest() {
		return CodingReceipt{}, 0, "", ErrReceiptConflict
	}
	return receipt, revision, stateDigest, nil
}

func (l *CodingReceiptLedger) checkDiskLocked() error {
	if l.closed || l.lock == nil || !validReceiptLock(l.lock) {
		return ErrInvalidReceiptState
	}
	state, err := readReceiptState(l.path, l.binding)
	if err != nil || state.Revision != l.current.Revision || state.StateDigest != l.current.StateDigest ||
		validateCommittedCompletionEvidence(l.path, state) != nil {
		return ErrInvalidReceiptState
	}
	return nil
}

func readReceiptState(path string, binding CodingReceiptBinding) (CodingReceiptState, error) {
	info, err := os.Lstat(path)
	if err != nil || !validReceiptRegular(info) {
		return CodingReceiptState{}, ErrInvalidReceiptState
	}
	document, err := secretfile.Read(path, MaxReceiptStateBytes)
	if err != nil {
		return CodingReceiptState{}, ErrInvalidReceiptState
	}
	defer clear(document)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var state CodingReceiptState
	if decoder.Decode(&state) != nil {
		return CodingReceiptState{}, ErrInvalidReceiptState
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CodingReceiptState{}, ErrInvalidReceiptState
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, document) || state.Validate(binding) != nil {
		return CodingReceiptState{}, ErrInvalidReceiptState
	}
	return state, nil
}

func writeReceiptState(path string, state CodingReceiptState) error {
	return writeReceiptStateWithFault(path, state, nil)
}

func writeReceiptStateWithFault(path string, state CodingReceiptState, fault func(string) error) error {
	if !validReceiptPath(path) {
		return ErrInvalidReceiptState
	}
	if fault != nil && fault("before-write") != nil {
		return ErrInvalidReceiptState
	}
	document, err := json.Marshal(state)
	if err != nil || len(document) == 0 || len(document) > MaxReceiptStateBytes {
		return ErrInvalidReceiptState
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".docker-control-receipts-*")
	if err != nil {
		return ErrInvalidReceiptState
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil || writeReceiptExact(temporary, document) != nil ||
		temporary.Sync() != nil || temporary.Close() != nil || os.Rename(temporaryPath, path) != nil {
		_ = temporary.Close()
		return ErrInvalidReceiptState
	}
	if fault != nil && fault("after-rename") != nil {
		return ErrInvalidReceiptState
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return ErrInvalidReceiptState
	}
	defer directoryFile.Close()
	if directoryFile.Sync() != nil {
		return ErrInvalidReceiptState
	}
	return nil
}

func writeReceiptExact(writer io.Writer, document []byte) error {
	for len(document) > 0 {
		count, err := writer.Write(document)
		if err != nil || count < 1 {
			return ErrInvalidReceiptState
		}
		document = document[count:]
	}
	return nil
}

func validReceiptPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	parent := filepath.Dir(path)
	for ancestor := parent; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		stat, ok := receiptFileStat(info)
		if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			(info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return false
		}
		if ancestor == filepath.Dir(ancestor) {
			break
		}
	}
	info, err := os.Lstat(parent)
	stat, ok := receiptFileStat(info)
	return err == nil && ok && stat.Uid == uint32(os.Getuid()) && info.Mode().Perm()&0o022 == 0
}

func receiptFileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func validReceiptRegular(info os.FileInfo) bool {
	stat, ok := receiptFileStat(info)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 &&
		stat.Uid == uint32(os.Getuid()) && stat.Nlink == 1
}

func validReceiptLock(lock *os.File) bool {
	if lock == nil {
		return false
	}
	opened, err := lock.Stat()
	path, pathErr := os.Lstat(lock.Name())
	return err == nil && pathErr == nil && os.SameFile(opened, path) &&
		validReceiptRegular(opened) && validReceiptRegular(path)
}
