//go:build darwin || linux

package controlstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"golang.org/x/sys/unix"
)

const manifestMax = 1 << 20
const manifestName = "namespace.json"
const lockName = "namespace.lock"
const pendingName = "pending.object"
const pendingManifest = "pending.namespace"

type identity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func id(s *unix.Stat_t) identity { return identity{uint64(s.Dev), uint64(s.Ino)} }

type entry struct {
	Class  Class  `json:"class"`
	ID     string `json:"id"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

func (e entry) name() string { return string(e.Class) + "-" + e.ID }

type manifest struct {
	Source   *sourceIdentity     `json:"source_identity,omitempty"`
	Backend  *DedicatedBackend   `json:"dedicated_backend,omitempty"`
	Kernel   *kernelRootIdentity `json:"kernel_root,omitempty"`
	Binding  Binding             `json:"binding"`
	Root     identity            `json:"root"`
	Revision uint64              `json:"revision"`
	Entries  []entry             `json:"entries"`
}

// Store owns the entire root for its lifetime, including the persistent lock.
// No other scope/writer may use it. A caller must independently bind the mount
// and prove its physical namespace before initialization. Files are opaque to
// this library: accepting bytes is never a receipt/state-machine transition.
type Store struct {
	mu           sync.Mutex
	path         string
	fd           int
	lock         int
	root         identity
	lockIdentity identity
	current      manifest
	poisoned     bool
	closed       bool
	kernel       *kernelRootSession
	backend      *DedicatedBackend
	source       *sourceSession
	fault        func(string) error          // deterministic tests only
	writeError   func(string, string, error) // private syscall observation in tests only
}

// StateSnapshot is a checked, caller-owned copy. Revision covers the entire
// namespace manifest, not just this state's content. Absence is represented
// only in a healthy initialized namespace; it never initializes missing state.
type StateSnapshot struct {
	Revision uint64
	Digest   string
	Data     []byte
	Found    bool
}

func (s *Store) ReadState(ctx context.Context, key string) (StateSnapshot, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !identifier.MatchString(key) {
		return StateSnapshot{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inspect() != nil {
		return StateSnapshot{}, ErrInvalid
	}
	result := StateSnapshot{Revision: s.current.Revision}
	for _, e := range s.current.Entries {
		if e.Class != State {
			continue
		}
		if e.ID != key {
			return StateSnapshot{}, ErrInvalid
		}
		d, _, err := s.read(e.name(), s.current.Binding.Layout.Coding.LedgerBytes)
		if err != nil || sum(d) != e.Digest || ctx.Err() != nil {
			return StateSnapshot{}, ErrInvalid
		}
		result.Data, result.Digest, result.Found = d, e.Digest, true
	}
	return result, nil
}

// CompareState is a single owner-locked comparison and publication. Comparing
// the whole manifest revision prevents a stale application writer overwriting
// a concurrent evidence/state change. It does not make the object's and
// manifest's two filesystem commits a recoverable transaction.
func (s *Store) CompareState(ctx context.Context, key string, expected StateSnapshot, data []byte) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inspect() != nil || s.current.Revision != expected.Revision {
		return ErrInvalid
	}
	found := false
	for _, e := range s.current.Entries {
		if e.Class != State {
			continue
		}
		if e.ID != key || !expected.Found || e.Digest != expected.Digest {
			return ErrInvalid
		}
		found = true
	}
	if found != expected.Found || !found && expected.Digest != "" {
		return ErrInvalid
	}
	return s.putLocked(ctx, State, key, data)
}

// Initialize accepts an existing private EMPTY root. The permanent lock is
// created before the independent physical-empty check. Interrupted ceremonies
// retain their marker and cannot be retried as a new namespace.
func Initialize(ctx context.Context, path string, b Binding, confirmPhysicalEmpty func(context.Context) error) (*Store, error) {
	return initializeStorage(ctx, path, b, confirmPhysicalEmpty, false, nil, nil)
}

// InitializeKernelChecked checks the actual root fd and mount on Linux, without
// accepting a caller success flag or callback. This is kernel/file evidence only:
// it does NOT prove Docker volume identity, sole external writer or a stable hard
// quota, and must not activate a runtime. Darwin rejects before creating a marker.
func InitializeKernelChecked(ctx context.Context, path string, b Binding) (*Store, error) {
	return initializeStorage(ctx, path, b, nil, true, nil, nil)
}

func initializeStorage(ctx context.Context, path string, b Binding, confirmPhysicalEmpty func(context.Context) error, kernelChecked bool, backend *DedicatedBackend, source *sourceSession) (*Store, error) {
	if ctx == nil || ctx.Err() != nil || (!kernelChecked && confirmPhysicalEmpty == nil) {
		return nil, ErrInvalid
	}
	s, err := openRoot(path, b)
	if err != nil {
		return nil, err
	}
	s.source = source
	ok := false
	defer func() {
		if !ok {
			_ = s.Close()
		}
	}()
	if kernelChecked {
		if s.bindDedicatedBackend(backend) != nil || s.bindKernelRoot(true) != nil || s.checkDedicatedBackend() != nil {
			return nil, ErrInvalid
		}
	}
	names, err := s.names()
	if err != nil || len(names) != 0 {
		return nil, ErrInvalid
	}
	s.lock, err = unix.Openat(s.fd, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrInvalid
	}
	if s.bindLock() != nil || unix.Fsync(s.lock) != nil || unix.Fsync(s.fd) != nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	if kernelChecked {
		if s.checkKernelRoot() != nil {
			return nil, ErrInvalid
		}
	} else if confirmPhysicalEmpty(ctx) != nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	s.current = manifest{Binding: b, Root: s.root, Revision: 1, Entries: []entry{}}
	if kernelChecked {
		k := s.kernel.Identity
		s.current.Kernel = &k
		s.current.Backend = s.backend
		if s.source != nil {
			v := s.source.identity
			s.current.Source = &v
		}
	}

	d, _ := json.Marshal(s.current)
	if s.writeNew(manifestName, d) != nil || unix.Fsync(s.fd) != nil || s.inspect() != nil {
		return nil, ErrInvalid
	}
	ok = true
	return s, nil
}

// Open never initializes, upgrades, cleans temporary files or repairs state.
// Every retained byte and object is checked before any writer becomes usable.
func Open(path string, b Binding) (*Store, error) { return openStorage(path, b, false, nil, nil) }

// OpenKernelChecked never upgrades a legacy manifest. Mount ID is a session
// anchor; stable filesystem/root identity is revalidated against retained bytes.
func OpenKernelChecked(path string, b Binding) (*Store, error) {
	return openStorage(path, b, true, nil, nil)
}

func openStorage(path string, b Binding, kernelChecked bool, backend *DedicatedBackend, source *sourceSession) (*Store, error) {
	s, err := openRoot(path, b)
	if err != nil {
		return nil, err
	}
	s.source = source
	ok := false
	defer func() {
		if !ok {
			_ = s.Close()
		}
	}()
	if kernelChecked && (s.bindDedicatedBackend(backend) != nil || s.bindKernelRoot(false) != nil || s.checkDedicatedBackend() != nil) {
		return nil, ErrInvalid
	}
	s.lock, err = unix.Openat(s.fd, lockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil || s.bindLock() != nil {
		return nil, ErrInvalid
	}
	d, _, err := s.read(manifestName, manifestMax)
	if err != nil || json.Unmarshal(d, &s.current) != nil {
		return nil, ErrInvalid
	}
	canonical, _ := json.Marshal(s.current)
	if !bytes.Equal(d, canonical) || s.current.Binding != b || s.current.Root != s.root || s.inspect() != nil {
		return nil, ErrInvalid
	}
	ok = true
	return s, nil
}

func openRoot(path string, b Binding) (*Store, error) {
	if b.Validate() != nil || b.UID != uint32(os.Geteuid()) || b.GID != uint32(os.Getegid()) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrInvalid
	}
	// Reject symlink ancestors and untrusted writable parents before acquiring
	// the descriptor. All subsequent data work is relative to that descriptor.
	for p := path; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Mode&0o022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			return nil, ErrInvalid
		}
		if p == "/" {
			break
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	s := &Store{path: path, fd: fd, lock: -1, current: manifest{Binding: b}}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		_ = s.Close()
		return nil, ErrInvalid
	}
	s.root = id(&st)
	if s.anchor() != nil {
		_ = s.Close()
		return nil, ErrInvalid
	}
	return s, nil
}

func (s *Store) bindLock() error {
	var st unix.Stat_t
	if unix.Fstat(s.lock, &st) != nil || !s.regular(&st) || st.Size != 0 || unix.Flock(s.lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrInvalid
	}
	s.lockIdentity = id(&st)
	return nil
}

func (s *Store) anchor() error {
	if s.closed || s.fd < 0 {
		return ErrInvalid
	}
	var st, path unix.Stat_t
	b := s.current.Binding
	if unix.Fstat(s.fd, &st) != nil || unix.Lstat(s.path, &path) != nil || id(&st) != s.root || id(&path) != s.root ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o700 || st.Uid != b.UID || st.Gid != b.GID || st.Nlink < 1 {
		return ErrInvalid
	}
	for p := s.path; ; p = filepath.Dir(p) {
		var parent unix.Stat_t
		if unix.Lstat(p, &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || (parent.Mode&0o022 != 0 && !(parent.Uid == 0 && parent.Mode&unix.S_ISVTX != 0)) {
			return ErrInvalid
		}
		if p == "/" {
			break
		}
	}
	if s.kernel != nil && (s.checkKernelRoot() != nil || s.checkDedicatedBackend() != nil) {
		return ErrInvalid
	}
	return nil
}
func (s *Store) regular(st *unix.Stat_t) bool {
	b := s.current.Binding
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o7777 == 0o600 && st.Uid == b.UID && st.Gid == b.GID && st.Nlink == 1 && uint64(st.Dev) == s.root.Device && st.Size >= 0
}
func (s *Store) names() ([]string, error) {
	fd, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	f := os.NewFile(uintptr(fd), "control-storage-directory")
	defer f.Close()
	// Bound hostile/unexplained directories as well as the accepted manifest.
	names, err := f.Readdirnames(s.current.Binding.Layout.Coding.MaxCodingFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	if len(names) > s.current.Binding.Layout.Coding.MaxCodingFiles {
		return nil, ErrCapacity
	}
	slices.Sort(names)
	return names, nil
}

func (s *Store) read(name string, max int64) ([]byte, int64, error) {
	fd, err := unix.Openat(s.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, ErrInvalid
	}
	f := os.NewFile(uintptr(fd), "control-storage-object")
	defer f.Close()
	var before, after, linked unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !s.regular(&before) || before.Size > max {
		return nil, 0, ErrInvalid
	}
	d, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(d)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(s.fd, name, &linked, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!s.regular(&after) || !s.regular(&linked) || id(&before) != id(&after) || id(&after) != id(&linked) || after.Size != before.Size || linked.Size != before.Size {
		return nil, 0, ErrInvalid
	}
	charge, err := physicalCharge(&after)
	return d, charge, err
}
func physicalCharge(st *unix.Stat_t) (int64, error) {
	// Reject absurd kernel facts before multiplication/rounding. Sparse or
	// compressed files do not reduce the logical reservation.
	if st.Size < 0 || st.Size > 1<<30 || st.Blocks < 0 || st.Blocks > (1<<30)/512 {
		return 0, ErrInvalid
	}
	return max(rounded(st.Size), rounded(st.Blocks*512)), nil
}

func (s *Store) inspect() error {
	if (s.source == nil) != (s.current.Source == nil) || (s.source != nil && s.source.identity != *s.current.Source) {
		return ErrInvalid
	}
	if (s.backend == nil) != (s.current.Backend == nil) || (s.backend != nil && *s.backend != *s.current.Backend) {
		return ErrInvalid
	}
	if (s.kernel == nil) != (s.current.Kernel == nil) || (s.kernel != nil && s.kernel.Identity != *s.current.Kernel) {
		return ErrInvalid
	}
	if s.poisoned || s.anchor() != nil || s.current.Revision == 0 || s.current.Root != s.root || s.current.Binding.Validate() != nil || s.current.Entries == nil {
		return ErrInvalid
	}
	if s.filesystem(0) != nil {
		return ErrInvalid
	}
	var lock unix.Stat_t
	if unix.Fstatat(s.fd, lockName, &lock, unix.AT_SYMLINK_NOFOLLOW) != nil || !s.regular(&lock) || lock.Size != 0 || id(&lock) != s.lockIdentity {
		return ErrInvalid
	}
	d, metadata, err := s.read(manifestName, manifestMax)
	expect, _ := json.Marshal(s.current)
	if err != nil || !bytes.Equal(d, expect) {
		return ErrInvalid
	}
	names, err := s.names()
	if err != nil || len(names) != len(s.current.Entries)+2 || len(names)+3 > s.current.Binding.Layout.Coding.MaxCodingFiles {
		return ErrInvalid
	}
	var rootStat unix.Stat_t
	if unix.Fstat(s.fd, &rootStat) != nil {
		return ErrInvalid
	}
	rootCharge, err := physicalCharge(&rootStat)
	if err != nil {
		return err
	}
	metadata += max(rootCharge, rounded(1)) + rounded(1) // root and persistent lock
	if metadata+2*manifestMax > s.current.Binding.Layout.Coding.PhysicalHeadroomBytes {
		return ErrCapacity
	}
	expected := []string{lockName, manifestName}
	used := map[Class]int64{}
	counts := map[Class]int{}
	last := ""
	for _, e := range s.current.Entries {
		lim, ok := s.current.Binding.Layout.limit(e.Class)
		if !ok || !identifier.MatchString(e.ID) || e.name() <= last || e.Size < 1 || e.Size > lim.file || !hashPattern.MatchString(e.Digest) {
			return ErrInvalid
		}
		last = e.name()
		expected = append(expected, e.name())
		d, charge, err := s.read(e.name(), lim.file)
		if err != nil || int64(len(d)) != e.Size || sum(d) != e.Digest {
			return ErrInvalid
		}
		used[e.Class] += charge
		counts[e.Class]++
		if used[e.Class] > lim.bytes || counts[e.Class] > lim.objects || (e.Class == State && counts[e.Class] > 1) {
			return ErrCapacity
		}
	}
	slices.Sort(expected)
	if !slices.Equal(names, expected) || s.anchor() != nil {
		return ErrInvalid
	}
	return nil
}

// Put publishes immutable bounded evidence/output, or replaces the SINGLE
// state object with the same ID. It reserves the old+new state peak and two
// manifest copies. Caller bytes are opaque: no execution/closure outcome is
// inferred. There is no removal/expiry API and no physical occupancy release.
func (s *Store) Put(ctx context.Context, c Class, key string, data []byte) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(ctx, c, key, data)
}

func (s *Store) putLocked(ctx context.Context, c Class, key string, data []byte) error {
	lim, ok := s.current.Binding.Layout.limit(c)
	if !ok || !identifier.MatchString(key) || len(data) == 0 || int64(len(data)) > lim.file {
		return ErrInvalid
	}
	if s.inspect() != nil {
		return ErrInvalid
	}
	if s.current.Revision == ^uint64(0) {
		return ErrCapacity
	}
	e := entry{Class: c, ID: key, Size: int64(len(data)), Digest: sum(data)}
	next := s.current
	next.Entries = slices.Clone(next.Entries)
	next.Revision++
	used := int64(0)
	count := 0
	replace := -1
	for i, old := range next.Entries {
		if old.Class != c {
			continue
		}
		count++
		_, charge, err := s.read(old.name(), lim.file)
		if err != nil {
			return ErrInvalid
		}
		used += charge
		if old.name() == e.name() {
			replace = i
		}
	}
	if c == State {
		if count > 0 && replace < 0 {
			return ErrInvalid
		}
	} else if replace >= 0 {
		return ErrInvalid
	}
	// The new file is first staged. Immutable files are renamed, not copied;
	// caller capture/sealed copies each remain separately counted entries.
	if rounded(e.Size) > lim.bytes-used || count+1 > lim.objects || len(next.Entries)+5 > s.current.Binding.Layout.Coding.MaxCodingFiles {
		return ErrCapacity
	}
	if replace >= 0 {
		next.Entries[replace] = e
	} else {
		next.Entries = append(next.Entries, e)
	}
	slices.SortFunc(next.Entries, func(a, b entry) int { return bytes.Compare([]byte(a.name()), []byte(b.name())) })
	d, _ := json.Marshal(next)
	if len(d) > manifestMax {
		return ErrCapacity
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Observe space for the write and retain the full close/headroom allowance
	// for ordinary writes. This is an instant local check, not a mount quota or
	// a guarantee against other processes consuming the underlying filesystem.
	reserve := s.current.Binding.Layout.Coding.PhysicalHeadroomBytes
	if c != Closure {
		reserve += s.current.Binding.Layout.Coding.ClosureReserveBytes
	}
	if s.filesystem(rounded(e.Size)+2*manifestMax+reserve) != nil {
		return ErrCapacity
	}
	// From here any failure may have reached storage. Poison before writing;
	// never clean residue or grant authority after an ambiguous sync/rename.
	s.poisoned = true
	if s.fail("before-object") != nil || s.writeNew(pendingName, data) != nil || s.fail("after-object-sync") != nil {
		return ErrUncertain
	}
	_, actual, err := s.read(pendingName, lim.file)
	if err != nil || actual > lim.bytes-used || s.anchor() != nil || ctx.Err() != nil {
		return ErrUncertain
	}
	if s.publishObject(e.name(), replace >= 0) != nil || s.fail("after-object-rename") != nil || unix.Fsync(s.fd) != nil {
		return ErrUncertain
	}
	if s.writeNew(pendingManifest, d) != nil || s.fail("after-manifest-sync") != nil || unix.Renameat(s.fd, pendingManifest, s.fd, manifestName) != nil || s.fail("after-manifest-rename") != nil || unix.Fsync(s.fd) != nil || ctx.Err() != nil {
		return ErrUncertain
	}
	s.current = next
	s.poisoned = false
	if s.inspect() != nil {
		s.poisoned = true
		return ErrUncertain
	}
	return nil
}

func (s *Store) publishObject(name string, replace bool) error {
	if replace {
		return unix.Renameat(s.fd, pendingName, s.fd, name)
	}
	// Immutable publication must never overwrite even an unexpected entrant.
	// The temporary second link is removed before any successful observation.
	// A crash in between leaves a hardlink/pending file and fails closed.
	if unix.Linkat(s.fd, pendingName, s.fd, name, 0) != nil {
		return ErrInvalid
	}
	return unix.Unlinkat(s.fd, pendingName, 0)
}

func (s *Store) filesystem(required int64) error {
	var st unix.Statfs_t
	if unix.Fstatfs(s.fd, &st) != nil || st.Bsize <= 0 || int64(st.Bsize) > s.current.Binding.Layout.Coding.AllocationUnitBytes ||
		s.current.Binding.Layout.Coding.AllocationUnitBytes%int64(st.Bsize) != 0 {
		return ErrInvalid
	}
	// Compare in blocks, without multiplying an untrusted block count.
	blocks := (required + int64(st.Bsize) - 1) / int64(st.Bsize)
	if uint64(st.Bavail) < uint64(blocks) {
		return ErrCapacity
	}
	return nil
}

func (s *Store) fail(stage string) error {
	if s.fault != nil {
		return s.fault(stage)
	}
	return nil
}
func (s *Store) writeNew(name string, data []byte) (result error) {
	failure := func(stage string, err error) error {
		if s.writeError != nil {
			s.writeError(name, stage, err)
		}
		return ErrInvalid
	}
	fd, err := unix.Openat(s.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return failure("open", err)
	}
	f := os.NewFile(uintptr(fd), "control-storage-write")
	defer func() {
		if err := f.Close(); err != nil {
			result = failure("close", err)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return failure("chmod", err)
	}
	n, err := f.Write(data)
	if err != nil {
		return failure("write", err)
	}
	if n != len(data) {
		return failure("write", io.ErrShortWrite)
	}
	if err := f.Sync(); err != nil {
		return failure("sync", err)
	}
	return nil
}

// Check verifies current storage; it is not a readiness or execution receipt.
func (s *Store) Check() error {
	if s == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inspect()
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.source != nil {
		err = s.source.close()
	}
	if s.lock >= 0 {
		err = errors.Join(err, unix.Close(s.lock))
	}
	if s.fd >= 0 {
		err = errors.Join(err, unix.Close(s.fd))
	}
	return err
}
