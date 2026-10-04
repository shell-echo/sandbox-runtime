//go:build phase6slice6gate

package productphase6gate

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

var errSlice6ExternalTemp = errors.New("Slice 6 private external temporary directory unavailable")

// Keep live Gate build and runtime files adjacent to a Docker-shared checkout,
// but never inside E, R or F. A checkout must stay strictly clean throughout
// the run, including while bind-mounted observer binaries are still live.
func slice6PrivateSourceSibling(t *testing.T, sourceRoot, prefix string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil || !absoluteCleanSlice6Path(root) || !strings.HasPrefix(prefix, ".sr-") ||
		!strings.HasSuffix(prefix, "-") || strings.ContainsAny(prefix, `/\`) {
		t.Fatal(errSlice6ExternalTemp)
	}
	parent := filepath.Dir(root)
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil || canonicalParent != parent {
		t.Fatal(errSlice6ExternalTemp)
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(errSlice6ExternalTemp)
	}
	var parentStat unix.Stat_t
	if unix.Fstat(parentFD, &parentStat) != nil || parentStat.Uid != uint32(os.Getuid()) {
		_ = unix.Close(parentFD)
		t.Fatal(errSlice6ExternalTemp)
	}
	path, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		_ = unix.Close(parentFD)
		t.Fatal(errSlice6ExternalTemp)
	}
	rootFD, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	var rootStat unix.Stat_t
	if err != nil || unix.Fstat(rootFD, &rootStat) != nil || !slice6PrivateDir(rootStat) ||
		!slice6OutsideAllSources(path, root) {
		if rootFD >= 0 {
			_ = unix.Close(rootFD)
		}
		_ = unix.Close(parentFD)
		// Identity was not pinned, so leave any uncertain residue for the
		// operator rather than deleting a possibly replaced path.
		t.Fatal(errSlice6ExternalTemp)
	}
	t.Cleanup(func() {
		if err := slice6RemovePrivateSibling(path, parentFD, rootFD, parentStat, rootStat); err != nil {
			t.Errorf("exact private external temporary cleanup: %v", err)
		}
	})
	return path
}

func slice6OutsideAllSources(path, ownSource string) bool {
	sources := []string{ownSource}
	if local, err := filepath.Abs(".."); err == nil {
		sources = append(sources, local)
	} else {
		return false
	}
	for _, key := range []string{"SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT", slice6GuestFixtureSourceRootEnv} {
		if value := os.Getenv(key); value != "" {
			sources = append(sources, value)
		}
	}
	for _, source := range sources {
		canonical, err := filepath.EvalSymlinks(source)
		if err != nil || !absoluteCleanSlice6Path(canonical) {
			return false
		}
		relative, err := filepath.Rel(canonical, path)
		if err != nil || relative == "." || relative == ".." ||
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return false
		}
	}
	return true
}

// Directory-fd-relative, no-follow and bounded removal of only the inode
// created above. If a name was replaced, leave it in place and fail the Gate.
func slice6RemovePrivateSibling(path string, parentFD, rootFD int,
	parentStat, rootStat unix.Stat_t) error {
	defer unix.Close(rootFD)
	defer unix.Close(parentFD)
	var heldParent, namedParent, heldRoot, namedRoot unix.Stat_t
	if unix.Fstat(parentFD, &heldParent) != nil || unix.Lstat(filepath.Dir(path), &namedParent) != nil ||
		unix.Fstat(rootFD, &heldRoot) != nil ||
		unix.Fstatat(parentFD, filepath.Base(path), &namedRoot, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!slice6SameInode(heldParent, parentStat) || !slice6SameInode(namedParent, parentStat) ||
		!slice6SameInode(heldRoot, rootStat) || !slice6SameInode(namedRoot, rootStat) ||
		!slice6PrivateDir(heldRoot) || !slice6PrivateDir(namedRoot) {
		return errSlice6ExternalTemp
	}
	budget := 4096
	if slice6RemovePrivateContents(rootFD, &budget, 0) != nil || unix.Fsync(rootFD) != nil {
		return errSlice6ExternalTemp
	}
	if unix.Fstatat(parentFD, filepath.Base(path), &namedRoot, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!slice6SameInode(namedRoot, rootStat) ||
		unix.Unlinkat(parentFD, filepath.Base(path), unix.AT_REMOVEDIR) != nil || unix.Fsync(parentFD) != nil {
		return errSlice6ExternalTemp
	}
	return nil
}

func slice6RemovePrivateContents(fd int, budget *int, depth int) error {
	if depth > 16 {
		return errSlice6ExternalTemp
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return errSlice6ExternalTemp
	}
	reader := os.NewFile(uintptr(dup), "private-temp")
	var names []string
	for {
		batch, readErr := reader.Readdirnames(128)
		names = append(names, batch...)
		if len(names) > *budget || readErr != nil {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				_ = reader.Close()
				return errSlice6ExternalTemp
			}
			break
		}
	}
	if reader.Close() != nil || len(names) > *budget {
		return errSlice6ExternalTemp
	}
	for _, name := range names {
		*budget--
		if name == "." || name == ".." || strings.ContainsRune(name, '/') {
			return errSlice6ExternalTemp
		}
		var observed, current unix.Stat_t
		if unix.Fstatat(fd, name, &observed, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return errSlice6ExternalTemp
		}
		if observed.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil || unix.Fstat(child, &current) != nil || !slice6SameInode(current, observed) {
				if child >= 0 {
					_ = unix.Close(child)
				}
				return errSlice6ExternalTemp
			}
			childErr := slice6RemovePrivateContents(child, budget, depth+1)
			closeErr := unix.Close(child)
			if childErr != nil || closeErr != nil {
				return errSlice6ExternalTemp
			}
			if unix.Fstatat(fd, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
				!slice6SameInode(current, observed) || unix.Unlinkat(fd, name, unix.AT_REMOVEDIR) != nil {
				return errSlice6ExternalTemp
			}
			continue
		}
		if unix.Fstatat(fd, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			!slice6SameInode(current, observed) || unix.Unlinkat(fd, name, 0) != nil {
			return errSlice6ExternalTemp
		}
	}
	return nil
}
