//go:build linux

package trustanchor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"golang.org/x/sys/unix"
)

var errRetainedDirectory = errors.New("retained trust anchor unavailable or changed")

const maxTrustMountInfoBytes = 1 << 20

// DirectorySession pins both inodes and the original mount. An observation
// failure poisons the session; callers must create a fresh session to retry.
type DirectorySession struct {
	mu          sync.Mutex
	directory   int
	file        int
	path        string
	digest      string
	initial     DirectoryObservation
	closed      bool
	initialized bool
}

// RetainDirectory accepts only the new fixed, root-owned trust-v4 directory
// shape. It does not change the legacy Load byte-returning path.
func RetainDirectory(ctx context.Context, anchor phase6security.TrustAnchor, now time.Time) (*DirectorySession, error) {
	if ctx == nil || ctx.Err() != nil || now.IsZero() || !validDirectoryAnchor(anchor) {
		return nil, errRetainedDirectory
	}
	directory, err := openTrustDirectory(anchor.MountDirectory)
	if err != nil {
		return nil, errRetainedDirectory
	}
	file, err := unix.Openat(directory, "bundle.pem", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(directory)
		return nil, errRetainedDirectory
	}
	s := &DirectorySession{directory: directory, file: file, path: anchor.MountDirectory, digest: anchor.BundleDigest, initialized: true}
	if s.initial, err = s.inspect(ctx, now, nil); err != nil {
		_ = s.Close()
		return nil, errRetainedDirectory
	}
	return s, nil
}

// Roots returns an independent pool from the original, freshly verified FD.
// It does not authorize a role or a listener; callers must keep observing the
// session for as long as the returned roots are in use.
func (s *DirectorySession) Roots(ctx context.Context, now time.Time) (*x509.CertPool, error) {
	if s == nil {
		return nil, errRetainedDirectory
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized || s.closed || ctx == nil || ctx.Err() != nil || now.IsZero() {
		s.closeLocked()
		return nil, errRetainedDirectory
	}
	before, err := s.inspect(ctx, now, &s.initial)
	if err != nil {
		s.closeLocked()
		return nil, errRetainedDirectory
	}
	raw, err := readRetainedBundle(ctx, s.file, before.File.Size)
	if err != nil {
		s.closeLocked()
		return nil, errRetainedDirectory
	}
	defer clear(raw)
	hash := sha256.Sum256(raw)
	pool := x509.NewCertPool()
	if s.digest != "sha256:"+hex.EncodeToString(hash[:]) || strictBundle(raw, now) != nil || !pool.AppendCertsFromPEM(raw) {
		s.closeLocked()
		return nil, errRetainedDirectory
	}
	after, err := s.inspect(ctx, now, &s.initial)
	if err != nil || before != after {
		s.closeLocked()
		return nil, errRetainedDirectory
	}
	return pool, nil
}

func validDirectoryAnchor(a phase6security.TrustAnchor) bool {
	if (a.ID != "internal-client-ca" && a.ID != "internal-server-ca") ||
		a.WriterAuthority != "operator" || a.OwnerUID != 0 || a.OwnerGID != 0 ||
		a.MountDirectory != "/run/trust/"+a.ID || a.TargetPath != a.MountDirectory+"/bundle.pem" ||
		filepath.Clean(a.MountDirectory) != a.MountDirectory || len(a.BundleDigest) != len("sha256:")+64 ||
		!strings.HasPrefix(a.BundleDigest, "sha256:") {
		return false
	}
	for _, c := range a.ID[1:] {
		if c < 'a' || c > 'z' {
			if c < '0' || c > '9' {
				if c != '-' {
					return false
				}
			}
		}
	}
	for _, c := range a.BundleDigest[len("sha256:"):] {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

// Walk each component under retained parent descriptors so an ancestor
// symlink cannot redirect the fixed absolute path.
func openTrustDirectory(path string) (int, error) {
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	current := root
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		var st unix.Stat_t
		if err = unix.Fstat(current, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mode&0o022 != 0 {
			_ = unix.Close(current)
			return -1, errRetainedDirectory
		}
		next, openErr := unix.Openat(current, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
	}
	return current, nil
}

// Observe rereads the original file FD and checks both names before and after
// reading. The returned value never contains certificate bytes.
func (s *DirectorySession) Observe(ctx context.Context, now time.Time) (DirectoryObservation, error) {
	if s == nil {
		return DirectoryObservation{}, errRetainedDirectory
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized || s.closed || ctx == nil || ctx.Err() != nil || now.IsZero() {
		s.closeLocked()
		return DirectoryObservation{}, errRetainedDirectory
	}
	got, err := s.inspect(ctx, now, &s.initial)
	if err != nil {
		s.closeLocked()
		return DirectoryObservation{}, errRetainedDirectory
	}
	return got, nil
}

func (s *DirectorySession) inspect(ctx context.Context, now time.Time, expected *DirectoryObservation) (DirectoryObservation, error) {
	before, err := s.checkNames(ctx)
	if err != nil {
		return DirectoryObservation{}, err
	}
	if expected != nil && before != *expected {
		return DirectoryObservation{}, errRetainedDirectory
	}
	raw, err := readRetainedBundle(ctx, s.file, before.File.Size)
	if err != nil {
		return DirectoryObservation{}, err
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	if s.digest != "sha256:"+hex.EncodeToString(digest[:]) || strictBundle(raw, now) != nil {
		return DirectoryObservation{}, errRetainedDirectory
	}
	after, err := s.checkNames(ctx)
	if err != nil || before != after || ctx.Err() != nil {
		return DirectoryObservation{}, errRetainedDirectory
	}
	return after, nil
}

func (s *DirectorySession) checkNames(ctx context.Context) (DirectoryObservation, error) {
	if ctx.Err() != nil {
		return DirectoryObservation{}, ctx.Err()
	}
	dir, dirMount, dirLinks, dirType, err := trustFDIdentity(s.directory)
	if err != nil || dirType != unix.S_IFDIR || dir.Mode != 0o555 ||
		dir.UID != 0 || dir.GID != 0 || dirMount == 0 || dirLinks == 0 {
		return DirectoryObservation{}, errRetainedDirectory
	}
	file, fileMount, fileLinks, fileType, err := trustFDIdentity(s.file)
	if err != nil || fileType != unix.S_IFREG || file.Mode != 0o444 ||
		file.UID != 0 || file.GID != 0 || file.Size < 1 || file.Size > maxBundleBytes || fileLinks != 1 || fileMount != dirMount {
		return DirectoryObservation{}, errRetainedDirectory
	}
	if err := soleBundleEntry(s.directory); err != nil {
		return DirectoryObservation{}, err
	}
	pathDir, err := openTrustDirectory(s.path)
	if err != nil {
		return DirectoryObservation{}, err
	}
	defer unix.Close(pathDir)
	pathDirID, pathMount, _, pathDirType, err := trustFDIdentity(pathDir)
	if err != nil || pathDirID != dir || pathMount != dirMount || pathDirType != dirType {
		return DirectoryObservation{}, errRetainedDirectory
	}
	pathFile, err := unix.Openat(pathDir, "bundle.pem", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return DirectoryObservation{}, err
	}
	defer unix.Close(pathFile)
	pathFileID, pathFileMount, pathLinks, pathFileType, err := trustFDIdentity(pathFile)
	if err != nil || pathFileID != file || pathFileMount != fileMount || pathLinks != fileLinks || pathFileType != fileType {
		return DirectoryObservation{}, errRetainedDirectory
	}
	info, err := readTrustMountInfo(ctx)
	if err != nil || !verifyTrustMountInfo(info, s.path, dirMount) {
		return DirectoryObservation{}, errRetainedDirectory
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(s.directory, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 || ctx.Err() != nil {
		return DirectoryObservation{}, errRetainedDirectory
	}
	return DirectoryObservation{BundleDigest: s.digest, Directory: dir, File: file, MountID: dirMount}, nil
}

func trustFDIdentity(fd int) (FileIdentity, uint64, uint64, uint32, error) {
	var st unix.Stat_t
	var sx unix.Statx_t
	if unix.Fstat(fd, &st) != nil || unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_INO|unix.STATX_MNT_ID, &sx) != nil || sx.Mask&(unix.STATX_INO|unix.STATX_MNT_ID) != unix.STATX_INO|unix.STATX_MNT_ID ||
		sx.Mnt_id == 0 || sx.Ino != st.Ino || sx.Dev_major != unix.Major(uint64(st.Dev)) || sx.Dev_minor != unix.Minor(uint64(st.Dev)) {
		return FileIdentity{}, 0, 0, 0, errRetainedDirectory
	}
	return FileIdentity{Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 0o7777, Size: st.Size}, sx.Mnt_id, uint64(st.Nlink), st.Mode & unix.S_IFMT, nil
}

func soleBundleEntry(directory int) error {
	fd, err := unix.Openat(directory, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "trust-directory")
	defer f.Close()
	names, err := f.Readdirnames(2)
	if (err != nil && err != io.EOF) || len(names) != 1 || names[0] != "bundle.pem" {
		return errRetainedDirectory
	}
	return nil
}

func readRetainedBundle(ctx context.Context, fd int, size int64) ([]byte, error) {
	if size < 1 || size > maxBundleBytes {
		return nil, errRetainedDirectory
	}
	data := make([]byte, 0, int(size)+1)
	chunk := make([]byte, 16<<10)
	for int64(len(data)) <= size {
		if err := ctx.Err(); err != nil {
			clear(data)
			return nil, err
		}
		want := int(size-int64(len(data))) + 1
		if want > len(chunk) {
			want = len(chunk)
		}
		n, err := unix.Pread(fd, chunk[:want], int64(len(data)))
		if err != nil {
			clear(data)
			return nil, err
		}
		if n == 0 {
			break
		}
		data = append(data, chunk[:n]...)
	}
	if int64(len(data)) != size || ctx.Err() != nil {
		clear(data)
		return nil, errRetainedDirectory
	}
	return data, nil
}

func readTrustMountInfo(ctx context.Context) ([]byte, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data := make([]byte, 0, 64<<10)
	chunk := make([]byte, 16<<10)
	for len(data) <= maxTrustMountInfoBytes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := f.Read(chunk)
		data = append(data, chunk[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil || n == 0 {
			return nil, errRetainedDirectory
		}
	}
	if len(data) > maxTrustMountInfoBytes || ctx.Err() != nil {
		return nil, errRetainedDirectory
	}
	return data, nil
}

// The mount point itself must have one live read-only mount record with the
// retained statx ID. Any mount below it could substitute the sole file.
func verifyTrustMountInfo(data []byte, path string, mountID uint64) bool {
	if len(data) == 0 || len(data) > maxTrustMountInfoBytes || data[len(data)-1] != '\n' || strings.IndexByte(string(data), 0) >= 0 {
		return false
	}
	seenIDs := make(map[uint64]bool)
	matches := 0
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > 8192 {
		return false
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return false
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 || seenIDs[id] {
			return false
		}
		seenIDs[id] = true
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(fields) != sep+4 {
			return false
		}
		mountPoint, ok := decodeTrustMountField(fields[4])
		if !ok {
			return false
		}
		if strings.HasPrefix(mountPoint, path+"/") {
			return false
		}
		if mountPoint == path {
			matches++
			if id != mountID || !mountOptionsRO(fields[5]) {
				return false
			}
		}
	}
	return matches == 1
}

func decodeTrustMountField(field string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] != '\\' {
			out.WriteByte(field[i])
			continue
		}
		if i+3 >= len(field) {
			return "", false
		}
		switch field[i+1 : i+4] {
		case "040":
			out.WriteByte(' ')
		case "011":
			out.WriteByte('\t')
		case "012":
			out.WriteByte('\n')
		case "134":
			out.WriteByte('\\')
		default:
			return "", false
		}
		i += 3
	}
	return out.String(), true
}

func mountOptionsRO(options string) bool {
	ro := false
	seen := make(map[string]bool)
	for _, option := range strings.Split(options, ",") {
		if option == "" || seen[option] || option == "rw" {
			return false
		}
		seen[option] = true
		ro = ro || option == "ro"
	}
	return ro
}

// Close is idempotent and safe against a concurrent Observe.
func (s *DirectorySession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}

func (s *DirectorySession) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if !s.initialized {
		return nil
	}
	fileErr := unix.Close(s.file)
	dirErr := unix.Close(s.directory)
	s.file, s.directory = -1, -1
	return errors.Join(fileErr, dirErr)
}
