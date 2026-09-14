//go:build darwin || linux

package evidencefiles

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"golang.org/x/sys/unix"
)

const publishedFileMode = 0o600

// Root is an open evidence-root directory. Its methods resolve evidence paths
// relative to the held directory descriptor, so replacement of the pathname
// cannot redirect reads or receipt publication to another directory.
type Root struct {
	mu       sync.Mutex
	path     string
	fd       int
	identity fileIdentity
	closed   bool
}

// Publication identifies one file created exclusively through Root.Publish.
// Read and Remove verify that the directory entry still names the inode that
// Publish created.
type Publication struct {
	root     *Root
	path     string
	identity fileIdentity
	size     int64
	digest   string
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

type inventoryState struct {
	entries    []Entry
	fileCount  int
	totalBytes int64
}

// OpenRoot opens root as a non-symlink directory and pins its identity until
// Close. The filesystem root is never a valid evidence root.
func OpenRoot(root string) (*Root, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if filepath.Dir(absolute) == absolute {
		return nil, errors.New("evidence root must not be the filesystem root")
	}
	var before unix.Stat_t
	if err := unix.Lstat(absolute, &before); err != nil {
		return nil, fmt.Errorf("inspect evidence root: %w", err)
	}
	if !isDirectory(&before) || isSymlink(&before) {
		return nil, errors.New("evidence root must be a directory, not a symlink")
	}
	fd, err := unix.Open(absolute, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !isDirectory(&opened) || identityOf(&before) != identityOf(&opened) {
		_ = unix.Close(fd)
		return nil, errors.New("evidence root was replaced while opening")
	}
	var after unix.Stat_t
	if err := unix.Lstat(absolute, &after); err != nil || !isDirectory(&after) || isSymlink(&after) || identityOf(&opened) != identityOf(&after) {
		_ = unix.Close(fd)
		return nil, errors.New("evidence root was replaced while opening")
	}
	return &Root{path: absolute, fd: fd, identity: identityOf(&opened)}, nil
}

// Close releases the held evidence-root directory descriptor. It is safe to
// call Close more than once.
func (root *Root) Close() error {
	if root == nil {
		return nil
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.closed {
		return nil
	}
	root.closed = true
	fd := root.fd
	root.fd = -1
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close evidence root: %w", err)
	}
	return nil
}

// Read inventories the root directory pinned by OpenRoot. It rejects every
// child directory and resolves files with openat and O_NOFOLLOW.
func (root *Root) Read(exclusions []string, options Options) (Inventory, error) {
	if err := validateOptions(options); err != nil {
		return Inventory{}, err
	}
	excluded, err := normalizeExclusions(exclusions)
	if err != nil {
		return Inventory{}, err
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if err := root.verifyPathLocked(); err != nil {
		return Inventory{}, err
	}
	state := inventoryState{entries: make([]Entry, 0)}
	if err := root.readRootLocked(excluded, options, &state); err != nil {
		return Inventory{}, err
	}
	if err := root.verifyPathLocked(); err != nil {
		return Inventory{}, err
	}
	sort.Slice(state.entries, func(i, j int) bool { return state.entries[i].Path < state.entries[j].Path })
	digest, err := DigestEntries(state.entries)
	if err != nil {
		return Inventory{}, err
	}
	return Inventory{Entries: state.entries, Digest: digest, FileCount: state.fileCount, TotalBytes: state.totalBytes}, nil
}

// ReadFile reads one bounded regular file through the directory descriptor
// pinned by OpenRoot.
func (root *Root) ReadFile(relative string, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("evidence file maximum must be positive")
	}
	if err := validateRootFilePath(relative); err != nil {
		return nil, fmt.Errorf("evidence file path %q: %w", relative, err)
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if err := root.verifyPathLocked(); err != nil {
		return nil, err
	}
	contents, _, err := readRegularAt(root.fd, relative, relative, maximum, nil)
	if err != nil {
		return nil, err
	}
	if err := root.verifyPathLocked(); err != nil {
		return nil, err
	}
	return contents, nil
}

// Publish exclusively creates one root-level evidence file with mode 0600.
// The create, write, stat, and read-back operations are all relative to the
// descriptor pinned by OpenRoot. Existing files and symlinks are never
// replaced. After the created inode can be identified, failure cleanup only
// unlinks a directory entry that still has that identity.
func (root *Root) Publish(relative string, contents []byte, maximum int64) (publication *Publication, err error) {
	if maximum <= 0 {
		return nil, errors.New("published evidence file maximum must be positive")
	}
	if int64(len(contents)) > maximum {
		return nil, fmt.Errorf("published evidence file %q exceeds %d bytes", relative, maximum)
	}
	if err := validateRootFilePath(relative); err != nil {
		return nil, fmt.Errorf("published evidence file path %q: %w", relative, err)
	}

	root.mu.Lock()
	defer root.mu.Unlock()
	if err := root.verifyPathLocked(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(root.fd, relative, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, publishedFileMode)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("published evidence file %q already exists", relative)
		}
		return nil, fmt.Errorf("create published evidence file %q: %w", relative, err)
	}
	created := true
	var createdIdentity fileIdentity
	defer func() {
		_ = unix.Close(fd)
		if created {
			if cleanupErr := root.removeIdentityLocked(relative, createdIdentity); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("clean up published evidence file %q: %w", relative, cleanupErr))
			}
		}
	}()

	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !isRegular(&opened) {
		return nil, fmt.Errorf("inspect published evidence file %q", relative)
	}
	createdIdentity = identityOf(&opened)
	if err := unix.Fchmod(fd, publishedFileMode); err != nil {
		return nil, fmt.Errorf("set published evidence file %q permissions: %w", relative, err)
	}
	if err := unix.Fstat(fd, &opened); err != nil || !isRegular(&opened) || identityOf(&opened) != createdIdentity {
		return nil, fmt.Errorf("inspect published evidence file %q after setting permissions", relative)
	}
	if linkCount(&opened) != 1 || permissionBits(&opened) != publishedFileMode {
		return nil, fmt.Errorf("published evidence file %q has unsafe identity or permissions", relative)
	}
	if err := writeAll(fd, contents); err != nil {
		return nil, fmt.Errorf("write published evidence file %q: %w", relative, err)
	}
	if err := unix.Fsync(fd); err != nil {
		return nil, fmt.Errorf("synchronize published evidence file %q: %w", relative, err)
	}
	var written unix.Stat_t
	if err := unix.Fstat(fd, &written); err != nil || !isRegular(&written) || identityOf(&written) != createdIdentity || written.Size != int64(len(contents)) || linkCount(&written) != 1 || permissionBits(&written) != publishedFileMode {
		return nil, fmt.Errorf("published evidence file %q changed while writing", relative)
	}
	var linked unix.Stat_t
	if err := unix.Fstatat(root.fd, relative, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil || !isRegular(&linked) || identityOf(&linked) != createdIdentity || !stableFileStat(&written, &linked) {
		return nil, fmt.Errorf("published evidence file %q directory entry changed", relative)
	}
	readBack, _, err := readRegularAt(root.fd, relative, relative, maximum, &createdIdentity)
	if err != nil {
		return nil, fmt.Errorf("read back published evidence file %q: %w", relative, err)
	}
	if !bytes.Equal(readBack, contents) {
		return nil, fmt.Errorf("published evidence file %q read-back differs", relative)
	}
	if err := unix.Fsync(root.fd); err != nil {
		return nil, fmt.Errorf("synchronize evidence root after publishing %q: %w", relative, err)
	}
	if err := root.verifyPathLocked(); err != nil {
		return nil, err
	}
	created = false
	return &Publication{root: root, path: relative, identity: createdIdentity, size: int64(len(contents)), digest: rawDigest(contents)}, nil
}

// Path returns the normalized root-relative path created by Publish.
func (publication *Publication) Path() string {
	if publication == nil {
		return ""
	}
	return publication.path
}

// Size returns the exact byte count observed by Publish.
func (publication *Publication) Size() int64 {
	if publication == nil {
		return 0
	}
	return publication.size
}

// Read opens the published inode again through the same held root descriptor
// and rejects a replaced directory entry.
func (publication *Publication) Read(maximum int64) ([]byte, error) {
	if publication == nil || publication.root == nil {
		return nil, errors.New("published evidence file is not initialized")
	}
	if maximum <= 0 {
		return nil, errors.New("published evidence file maximum must be positive")
	}
	publication.root.mu.Lock()
	defer publication.root.mu.Unlock()
	if err := publication.root.verifyPathLocked(); err != nil {
		return nil, err
	}
	contents, size, err := readRegularAt(publication.root.fd, publication.path, publication.path, maximum, &publication.identity)
	if err != nil {
		return nil, err
	}
	if size != publication.size {
		return nil, fmt.Errorf("published evidence file %q size changed", publication.path)
	}
	if err := publication.root.verifyPathLocked(); err != nil {
		return nil, err
	}
	return contents, nil
}

// Commit publishes a staged root-level file under destination without
// overwriting an existing entry. The staged inode must still be singly linked;
// the destination becomes visible only after the caller's validation checks.
func (publication *Publication) Commit(destination string) (err error) {
	if publication == nil || publication.root == nil {
		return errors.New("published evidence file is not initialized")
	}
	if err := validateRootFilePath(destination); err != nil || destination == publication.path {
		return errors.New("committed evidence file must use a distinct root-level path")
	}
	root := publication.root
	root.mu.Lock()
	defer root.mu.Unlock()
	committed := false
	defer func() {
		if !committed {
			if cleanupErr := root.removeIdentityLocked(publication.path, publication.identity); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("clean up staged evidence file %q: %w", publication.path, cleanupErr))
			}
		}
	}()
	if err := root.verifyPathLocked(); err != nil {
		return err
	}
	var staged unix.Stat_t
	if err := unix.Fstatat(root.fd, publication.path, &staged, unix.AT_SYMLINK_NOFOLLOW); err != nil || !isRegular(&staged) || identityOf(&staged) != publication.identity || staged.Size != publication.size {
		return fmt.Errorf("staged evidence file %q identity changed", publication.path)
	}
	if linkCount(&staged) != 1 {
		return fmt.Errorf("staged evidence file %q has unexpected link count", publication.path)
	}
	stagedContents, _, err := readRegularAt(root.fd, publication.path, publication.path, publication.size, &publication.identity)
	if err != nil || rawDigest(stagedContents) != publication.digest {
		return errors.New("staged evidence file contents changed")
	}
	var destinationStat unix.Stat_t
	if err := unix.Fstatat(root.fd, destination, &destinationStat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return fmt.Errorf("committed evidence file %q already exists", destination)
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect committed evidence file %q: %w", destination, err)
	}
	if err := unix.Linkat(root.fd, publication.path, root.fd, destination, 0); err != nil {
		return fmt.Errorf("commit evidence file %q: %w", destination, err)
	}
	var linked unix.Stat_t
	if err := unix.Fstatat(root.fd, destination, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil || !isRegular(&linked) || identityOf(&linked) != publication.identity || linkCount(&linked) != 2 || linked.Size != publication.size {
		return fmt.Errorf("committed evidence file %q identity changed", destination)
	}
	if err := unix.Unlinkat(root.fd, publication.path, 0); err != nil {
		return fmt.Errorf("remove staged evidence file %q: %w", publication.path, err)
	}
	publication.path = destination
	committedContents, _, err := readRegularAt(root.fd, destination, destination, publication.size, &publication.identity)
	if err != nil || rawDigest(committedContents) != publication.digest {
		return errors.New("committed evidence file contents changed")
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("synchronize evidence root after committing %q: %w", destination, err)
	}
	if err := unix.Fstatat(root.fd, destination, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil || !isRegular(&linked) || identityOf(&linked) != publication.identity || linkCount(&linked) != 1 || linked.Size != publication.size || permissionBits(&linked) != publishedFileMode {
		return fmt.Errorf("committed evidence file %q changed", destination)
	}
	if err := root.verifyPathLocked(); err != nil {
		return err
	}
	committed = true
	return nil
}

// Remove verifies that the root-relative directory entry still names the
// singly linked inode created by Publish immediately before unlinking it.
func (publication *Publication) Remove() error {
	if publication == nil || publication.root == nil {
		return errors.New("published evidence file is not initialized")
	}
	publication.root.mu.Lock()
	defer publication.root.mu.Unlock()
	if err := publication.root.ensureOpenLocked(); err != nil {
		return err
	}
	var linked unix.Stat_t
	if err := unix.Fstatat(publication.root.fd, publication.path, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect published evidence file %q: %w", publication.path, err)
	}
	if !isRegular(&linked) || identityOf(&linked) != publication.identity || linkCount(&linked) != 1 {
		return fmt.Errorf("published evidence file %q identity changed", publication.path)
	}
	if err := unix.Unlinkat(publication.root.fd, publication.path, 0); err != nil {
		return fmt.Errorf("remove published evidence file %q: %w", publication.path, err)
	}
	if err := unix.Fsync(publication.root.fd); err != nil {
		return fmt.Errorf("synchronize evidence root after removing %q: %w", publication.path, err)
	}
	return nil
}

func (root *Root) ensureOpenLocked() error {
	if root == nil || root.closed || root.fd < 0 {
		return errors.New("evidence root is closed")
	}
	return nil
}

func (root *Root) verifyPathLocked() error {
	if err := root.ensureOpenLocked(); err != nil {
		return err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(root.fd, &opened); err != nil || !isDirectory(&opened) || identityOf(&opened) != root.identity {
		return errors.New("held evidence root identity changed")
	}
	var linked unix.Stat_t
	if err := unix.Lstat(root.path, &linked); err != nil || !isDirectory(&linked) || isSymlink(&linked) || identityOf(&linked) != root.identity {
		return errors.New("evidence root path was replaced")
	}
	return nil
}

func (root *Root) readRootLocked(excluded map[string]struct{}, options Options, state *inventoryState) error {
	before, err := listDirectory(root.fd, options.MaxFiles)
	if err != nil {
		return fmt.Errorf("read evidence root: %w", err)
	}
	for _, name := range before {
		if err := validateRootFilePath(name); err != nil {
			return fmt.Errorf("evidence path %q: %w", name, err)
		}
		var linked unix.Stat_t
		if err := unix.Fstatat(root.fd, name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("inspect evidence path %q: %w", name, err)
		}
		if isSymlink(&linked) {
			return fmt.Errorf("evidence path %q must not be a symlink", name)
		}
		switch {
		case isDirectory(&linked):
			return fmt.Errorf("evidence path %q must not be a directory", name)
		case isRegular(&linked):
			if state.fileCount == options.MaxFiles {
				return fmt.Errorf("evidence root exceeds %d regular files", options.MaxFiles)
			}
			state.fileCount++
			contents, size, err := readRegularAt(root.fd, name, name, options.MaxFileBytes, nil)
			if err != nil {
				return err
			}
			if size > options.MaxTotalBytes-state.totalBytes {
				return fmt.Errorf("evidence root exceeds %d total bytes", options.MaxTotalBytes)
			}
			state.totalBytes += size
			if _, omit := excluded[name]; !omit {
				state.entries = append(state.entries, Entry{Path: name, Bytes: size, SHA256: rawDigest(contents)})
			}
		default:
			return fmt.Errorf("evidence path %q must be a regular file", name)
		}
	}
	after, err := listDirectory(root.fd, options.MaxFiles)
	if err != nil || !equalNames(before, after) {
		return errors.New("evidence root changed while reading")
	}
	return nil
}

func readRegularAt(parentFD int, name, relative string, maximum int64, expected *fileIdentity) ([]byte, int64, error) {
	var linked unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, 0, fmt.Errorf("inspect evidence file %q: %w", relative, err)
	}
	if !isRegular(&linked) || isSymlink(&linked) || linkCount(&linked) != 1 {
		return nil, 0, fmt.Errorf("evidence file %q must be a regular, non-symlink, singly linked file", relative)
	}
	if expected != nil && identityOf(&linked) != *expected {
		return nil, 0, fmt.Errorf("evidence file %q identity changed", relative)
	}
	if linked.Size > maximum {
		return nil, 0, fmt.Errorf("evidence file %q exceeds %d bytes", relative, maximum)
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open evidence file %q: %w", relative, err)
	}
	file := os.NewFile(uintptr(fd), relative)
	if file == nil {
		_ = unix.Close(fd)
		return nil, 0, fmt.Errorf("open evidence file %q", relative)
	}
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !isRegular(&opened) || identityOf(&opened) != identityOf(&linked) || linkCount(&opened) != 1 {
		return nil, 0, fmt.Errorf("evidence file %q was replaced while opening", relative)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read evidence file %q: %w", relative, err)
	}
	if int64(len(contents)) > maximum {
		return nil, 0, fmt.Errorf("evidence file %q exceeds %d bytes", relative, maximum)
	}
	var finalFD unix.Stat_t
	var finalLink unix.Stat_t
	if err := unix.Fstat(fd, &finalFD); err != nil || unix.Fstatat(parentFD, name, &finalLink, unix.AT_SYMLINK_NOFOLLOW) != nil || !isRegular(&finalFD) || !isRegular(&finalLink) || linkCount(&finalFD) != 1 || linkCount(&finalLink) != 1 || !stableFileStat(&opened, &finalFD) || !stableFileStat(&opened, &finalLink) || finalFD.Size != int64(len(contents)) {
		return nil, 0, fmt.Errorf("evidence file %q changed while reading", relative)
	}
	return contents, int64(len(contents)), nil
}

func listDirectory(directoryFD, maximumEntries int) ([]string, error) {
	fd, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "evidence-directory")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open evidence directory stream")
	}
	entries, readErr := file.ReadDir(maximumEntries + 1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > maximumEntries {
		return nil, fmt.Errorf("evidence root exceeds %d regular files or contains unsupported entries", maximumEntries)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func equalNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (root *Root) removeIdentityLocked(relative string, identity fileIdentity) error {
	if identity == (fileIdentity{}) {
		return nil
	}
	var cleanupErrors []error
	if err := root.unlinkEntryIdentityLocked(relative, identity); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	if relative != "receipt.json" {
		if err := root.unlinkEntryIdentityLocked("receipt.json", identity); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

func (root *Root) unlinkEntryIdentityLocked(relative string, identity fileIdentity) error {
	var linked unix.Stat_t
	if err := unix.Fstatat(root.fd, relative, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect evidence file %q during cleanup: %w", relative, err)
	}
	if !isRegular(&linked) || identityOf(&linked) != identity {
		return nil
	}
	if err := unix.Unlinkat(root.fd, relative, 0); err != nil {
		return fmt.Errorf("remove evidence file %q during cleanup: %w", relative, err)
	}
	if err := unix.Fsync(root.fd); err != nil {
		return fmt.Errorf("synchronize evidence root after cleaning %q: %w", relative, err)
	}
	return nil
}

func writeAll(fd int, contents []byte) error {
	for len(contents) > 0 {
		written, err := unix.Write(fd, contents)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}

func identityOf(info *unix.Stat_t) fileIdentity {
	return fileIdentity{device: uint64(info.Dev), inode: uint64(info.Ino)}
}

func fileType(info *unix.Stat_t) uint32 {
	return uint32(info.Mode) & uint32(unix.S_IFMT)
}

func isDirectory(info *unix.Stat_t) bool {
	return fileType(info) == uint32(unix.S_IFDIR)
}

func isRegular(info *unix.Stat_t) bool {
	return fileType(info) == uint32(unix.S_IFREG)
}

func isSymlink(info *unix.Stat_t) bool {
	return fileType(info) == uint32(unix.S_IFLNK)
}

func permissionBits(info *unix.Stat_t) uint32 {
	return uint32(info.Mode) & 0o777
}

func linkCount(info *unix.Stat_t) uint64 {
	return uint64(info.Nlink)
}

func stableFileStat(left, right *unix.Stat_t) bool {
	return identityOf(left) == identityOf(right) &&
		fileType(left) == fileType(right) &&
		permissionBits(left) == permissionBits(right) &&
		linkCount(left) == linkCount(right) &&
		left.Size == right.Size &&
		left.Mtim == right.Mtim &&
		left.Ctim == right.Ctim
}
