// Package restrictedunix owns the shared inode and ownership checks for
// private cross-UID Unix sockets. It does not authorize protocol messages.
package restrictedunix

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Layout struct {
	DirectoryMode os.FileMode
	SocketMode    os.FileMode
	OwnerUID      uint32
	DirectoryGID  uint32
}

func ValidateParent(socketPath string, layout Layout) bool {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || len(socketPath) > 100 ||
		(layout.DirectoryMode != 0o710 && layout.DirectoryMode != 0o700) ||
		(layout.SocketMode != 0o666 && layout.SocketMode != 0o600) ||
		(layout.DirectoryMode == 0o710) != (layout.SocketMode == 0o666) {
		return false
	}
	parent := filepath.Dir(socketPath)
	for directory := parent; directory != "/"; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	info, err := os.Lstat(parent)
	return err == nil && info.IsDir() && info.Mode().Perm() == layout.DirectoryMode && ownedBy(info, layout.OwnerUID, layout.DirectoryGID)
}

func ValidateSocket(socketPath string, layout Layout) bool {
	if !ValidateParent(socketPath, layout) {
		return false
	}
	info, err := os.Lstat(socketPath)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode()&os.ModeSocket != 0 &&
		info.Mode().Perm() == layout.SocketMode && ownedByUID(info, layout.OwnerUID)
}

// Listen refuses a live or substituted socket. Only an exact same-owner
// stale inode, confirmed by ECONNREFUSED, is removed before bind.
func Listen(socketPath string, layout Layout) (*net.UnixListener, os.FileInfo, error) {
	if uint32(os.Getuid()) != layout.OwnerUID || !ValidateParent(socketPath, layout) || !recoverStale(socketPath, layout) {
		return nil, nil, errors.New("invalid restricted Unix socket")
	}
	parent, err := os.Lstat(filepath.Dir(socketPath))
	if err != nil {
		return nil, nil, errors.New("invalid restricted Unix parent")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, nil, errors.New("restricted Unix listen failed")
	}
	listener.SetUnlinkOnClose(false)
	created, createdErr := os.Lstat(socketPath)
	parentAfter, parentErr := os.Lstat(filepath.Dir(socketPath))
	if createdErr != nil || parentErr != nil || !os.SameFile(parent, parentAfter) ||
		os.Chmod(socketPath, layout.SocketMode) != nil || !ValidateSocket(socketPath, layout) {
		_ = listener.Close()
		RemoveIfSame(socketPath, created)
		return nil, nil, errors.New("restricted Unix socket permissions")
	}
	current, err := os.Lstat(socketPath)
	if err != nil || !os.SameFile(created, current) {
		_ = listener.Close()
		RemoveIfSame(socketPath, created)
		return nil, nil, errors.New("restricted Unix socket inode")
	}
	return listener, current, nil
}

func RemoveIfSame(socketPath string, original os.FileInfo) {
	if original == nil {
		return
	}
	if current, err := os.Lstat(socketPath); err == nil && os.SameFile(current, original) {
		_ = os.Remove(socketPath)
	}
}

func recoverStale(socketPath string, layout Layout) bool {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || !ValidateSocket(socketPath, layout) {
		return false
	}
	connection, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
		return false
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return false
	}
	current, err := os.Lstat(socketPath)
	if err != nil || !os.SameFile(info, current) || os.Remove(socketPath) != nil {
		return false
	}
	_, err = os.Lstat(socketPath)
	return errors.Is(err, os.ErrNotExist)
}

func ownedBy(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}

func ownedByUID(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}
