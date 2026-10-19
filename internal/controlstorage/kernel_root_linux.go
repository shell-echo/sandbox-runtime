package controlstorage

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxMountInfoBytes = 1 << 20

// Collect from the actual pinned Store fd, never a caller-supplied statfs or
// mountinfo document. All parser helpers below are pure, not alternate openers.
func readKernelRoot(fd int, path string) (kernelRootSession, int64, error) {
	var st unix.Stat_t
	var fs unix.Statfs_t
	var sx unix.Statx_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_MNT_ID, &sx) != nil ||
		sx.Mask&unix.STATX_MNT_ID == 0 || sx.Mask&unix.STATX_INO == 0 || sx.Mnt_id == 0 || sx.Ino != st.Ino ||
		sx.Dev_major != unix.Major(uint64(st.Dev)) || sx.Dev_minor != unix.Minor(uint64(st.Dev)) {
		return kernelRootSession{}, 0, ErrInvalid
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return kernelRootSession{}, 0, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maxMountInfoBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(data) > maxMountInfoBytes {
		return kernelRootSession{}, 0, ErrInvalid
	}
	// A replacement bind mount can retain dev/inode while selecting a different
	// mount than the pinned fd. Check the live pathname's mount ID as well.
	var pathStat unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_MNT_ID, &pathStat) != nil ||
		!sameKernelMount(sx, pathStat) {
		return kernelRootSession{}, 0, ErrInvalid
	}
	return kernelRootFromFacts(st, fs, sx.Mnt_id, path, data)
}

func sameKernelMount(fd, path unix.Statx_t) bool {
	const mask = unix.STATX_INO | unix.STATX_MNT_ID
	return fd.Mask&mask == mask && path.Mask&mask == mask && fd.Mnt_id != 0 &&
		fd.Mnt_id == path.Mnt_id && fd.Ino == path.Ino && fd.Dev_major == path.Dev_major && fd.Dev_minor == path.Dev_minor
}

func kernelRootFromFacts(st unix.Stat_t, fs unix.Statfs_t, mountID uint64, path string, data []byte) (kernelRootSession, int64, error) {
	fail := func() (kernelRootSession, int64, error) { return kernelRootSession{}, 0, ErrInvalid }
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o700 || st.Uid < 10000 || st.Uid > 60000 || st.Gid < 10000 || st.Gid > 60000 ||
		mountID == 0 || fs.Bsize <= 0 || fs.Frsize <= 0 || fs.Bsize != fs.Frsize || fs.Bsize > 64<<10 || (64<<10)%fs.Bsize != 0 ||
		fs.Blocks == 0 || fs.Blocks > uint64((1<<30)/fs.Frsize) || fs.Bavail > fs.Blocks || fs.Files < 1024 || fs.Ffree > fs.Files || fs.Fsid.Val == ([2]int32{}) {
		return fail()
	}
	total := int64(fs.Blocks) * fs.Frsize
	if total < 512<<20 || uint64(fs.Flags)&uint64(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) != uint64(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) || fs.Flags&unix.ST_RDONLY != 0 {
		return fail()
	}
	filesystem := ""
	switch fs.Type {
	case unix.EXT4_SUPER_MAGIC:
		filesystem = "ext4"
	case unix.XFS_SUPER_MAGIC:
		filesystem = "xfs"
	default:
		return fail()
	}
	source, err := verifyKernelMountInfo(data, mountID, path, fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))), filesystem)
	if err != nil {
		return fail()
	}
	return kernelRootSession{Identity: kernelRootIdentity{Protocol: kernelRootProtocol, Root: id(&st), Filesystem: filesystem, FilesystemID: fs.Fsid.Val,
		SourceDigest: sum([]byte(source)), DataBytes: total, BlockBytes: fs.Frsize, Inodes: fs.Files, MountFlags: uint64(fs.Flags)}, MountID: mountID}, int64(fs.Bavail) * fs.Frsize, nil
}

// Require the filesystem ROOT as a private exact mount, not a bind-mounted
// subdirectory of Docker's shared filesystem. One visible device mount only is
// a local negative check; it cannot prove exclusivity in other namespaces.
func verifyKernelMountInfo(data []byte, mountID uint64, path, device, filesystem string) (string, error) {
	if len(data) == 0 || len(data) > maxMountInfoBytes || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		return "", ErrInvalid
	}
	seen := map[uint64]bool{}
	devices, targets := 0, 0
	source := ""
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > 8192 {
		return "", ErrInvalid
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return "", ErrInvalid
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 || seen[id] {
			return "", ErrInvalid
		}
		seen[id] = true
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(fields) != sep+4 {
			return "", ErrInvalid
		}
		if fields[2] == device {
			devices++
		}
		if fields[4] == path {
			targets++
		}
		if id != mountID {
			continue
		}
		if sep != 6 || fields[2] != device || fields[3] != "/" || fields[4] != path || fields[7] != filesystem ||
			!strings.HasPrefix(fields[8], "/dev/") || strings.Contains(fields[8], "\\") {
			return "", ErrInvalid
		}
		opts := map[string]bool{}
		for _, v := range strings.Split(fields[5], ",") {
			if v == "" || opts[v] {
				return "", ErrInvalid
			}
			opts[v] = true
		}
		if !opts["rw"] || opts["ro"] || !opts["nosuid"] || !opts["nodev"] || !opts["noexec"] {
			return "", ErrInvalid
		}
		source = fields[8]
	}
	if devices != 1 || targets != 1 || source == "" {
		return "", ErrInvalid
	}
	return source, nil
}
