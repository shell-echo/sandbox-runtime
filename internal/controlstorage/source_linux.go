package controlstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/sys/unix"
)

type sourceRecord struct {
	Protocol           string `json:"protocol"`
	Namespace          string `json:"namespace"`
	LoopDevice         string `json:"loop_device"`
	FileDevice         uint64 `json:"file_device"`
	FileInode          uint64 `json:"file_inode"`
	Bytes              int64  `json:"bytes"`
	InitialImageSHA256 string `json:"initial_image_sha256"`
	ControlGID         uint32 `json:"control_gid,omitempty"`
}
type sourceAnchor struct {
	Device, Inode, Mount, Rdev uint64
	Mode                       uint16
	UID, GID, Links            uint32
}
type sourceSession struct {
	identity sourceIdentity
	binding  Binding
	backend  DedicatedBackend
	record   sourceRecord
	original []byte
	fds      []int // directory, lock, image, seal, selected device
	anchors  []sourceAnchor
	closed   bool
}

func openSource(b Binding, backend DedicatedBackend, expected, volumeBinding string) (out *sourceSession, err error) {
	if b.Validate() != nil || backend.Validate() != nil || !hashPattern.MatchString(expected) || !hashPattern.MatchString(volumeBinding) || b.UID < 10000 || b.UID > 60000 || b.GID < 10000 || b.GID > 60000 || uint32(os.Geteuid()) != b.UID || uint32(os.Getegid()) != b.GID {
		return nil, ErrInvalid
	}
	groups, e := os.Getgroups()
	hasSocketGroup := false
	if e != nil {
		return nil, ErrInvalid
	}
	for _, g := range groups {
		if g != 0 && uint32(g) != b.GID {
			return nil, ErrInvalid
		}
		if g == 0 {
			hasSocketGroup = true
		}
	}
	if !hasSocketGroup {
		return nil, ErrInvalid
	}
	s := &sourceSession{binding: b, backend: backend}
	defer func() {
		if out == nil {
			_ = s.close()
		}
	}()
	// No writable or symlink ancestor may redirect the fixed capability mount.
	for p := SourceMountPath; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return nil, ErrInvalid
		}
		if p == "/" {
			break
		}
	}
	for i, name := range []string{SourceMountPath, "ceremony.lock", "receipt.ext4", "backend.json", backend.Device} {
		parent := unix.AT_FDCWD
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i == 0 {
			flags |= unix.O_DIRECTORY
		} else if i < 4 {
			parent = s.fds[0]
		}
		fd, e := unix.Openat(parent, name, flags, 0)
		if e != nil {
			return nil, ErrInvalid
		}
		s.fds = append(s.fds, fd)
		a, e := sourceFDAnchor(fd, parent, name)
		if e != nil {
			return nil, ErrInvalid
		}
		s.anchors = append(s.anchors, a)
	}
	if unix.Flock(s.fds[1], unix.LOCK_SH|unix.LOCK_NB) != nil {
		return nil, ErrInvalid
	}
	raw, e := s.readSeal()
	if e != nil || sum(raw) != expected || json.Unmarshal(raw, &s.record) != nil {
		return nil, ErrInvalid
	}
	canonical, _ := json.Marshal(s.record)
	r := s.record
	if !bytes.Equal(raw, canonical) || r.Protocol != SourceProvisionProtocol || r.Namespace != b.Namespace || r.LoopDevice != backend.Device || r.ControlGID != b.GID || r.Bytes != DedicatedBackendBytes || !hashPattern.MatchString(r.InitialImageSHA256) || r.FileDevice != s.anchors[2].Device || r.FileInode != s.anchors[2].Inode {
		return nil, ErrInvalid
	}
	s.original = raw
	s.identity = sourceIdentity{volumeBinding, SourceProvisionProtocol, sum(raw), identity{s.anchors[0].Device, s.anchors[0].Inode}, identity{r.FileDevice, r.FileInode}, s.anchors[4].Rdev}
	if s.check(s.identity.Device) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}

func (s *sourceSession) readSeal() ([]byte, error) {
	var st unix.Stat_t
	if len(s.fds) != 5 || unix.Fstat(s.fds[3], &st) != nil || st.Size <= 0 || st.Size > 4096 {
		return nil, ErrInvalid
	}
	d := make([]byte, 4097)
	n, e := unix.Pread(s.fds[3], d, 0)
	if e != nil || int64(n) != st.Size || n > 4096 {
		return nil, ErrInvalid
	}
	return d[:n], nil
}
func (s *sourceSession) check(rootDevice uint64) error {
	if s == nil || s.closed || len(s.fds) != 5 || len(s.anchors) != 5 || rootDevice != s.identity.Device || unix.Major(rootDevice) != 7 || s.backend.Device != fmt.Sprintf("/dev/loop%d", unix.Minor(rootDevice)) {
		return ErrInvalid
	}
	before, e := s.census()
	if e != nil {
		return ErrInvalid
	}
	for i, name := range []string{SourceMountPath, "ceremony.lock", "receipt.ext4", "backend.json", s.backend.Device} {
		parent := unix.AT_FDCWD
		if i > 0 && i < 4 {
			parent = s.fds[0]
		}
		a, e := sourceFDAnchor(s.fds[i], parent, name)
		if e != nil || a != s.anchors[i] {
			return ErrInvalid
		}
		if i < 4 {
			mode := uint16(unix.S_IFREG | 0o640)
			if i == 0 {
				mode = unix.S_IFDIR | 0o750
			}
			if a.Mode != mode || a.UID != 0 || a.GID != s.binding.GID {
				return ErrInvalid
			}
			if i > 0 && (a.Links != 1 || a.Device != s.anchors[0].Device || a.Mount != s.anchors[0].Mount) {
				return ErrInvalid
			}
		}
	}
	var root unix.Statfs_t
	var img, lock unix.Stat_t
	if unix.Fstatfs(s.fds[0], &root) != nil || root.Flags&unix.ST_RDONLY == 0 || unix.Fstat(s.fds[2], &img) != nil || img.Size != DedicatedBackendBytes || img.Blocks < DedicatedBackendBytes/512 || unix.Fstat(s.fds[1], &lock) != nil || lock.Size != 0 || s.anchors[4].Mode&unix.S_IFMT != unix.S_IFBLK {
		return ErrInvalid
	}
	raw, e := s.readSeal()
	if e != nil || !bytes.Equal(raw, s.original) {
		return ErrInvalid
	}
	after, e := s.census()
	if e != nil || !reflect.DeepEqual(before, after) {
		return ErrInvalid
	}
	return nil
}

// Every visible loop is explicitly bounded and must be readable. Unrelated
// mappings may exist, but an alias of our actual backing inode is forbidden.
func (s *sourceSession) census() (map[string]*unix.LoopInfo64, error) {
	names, e := filepath.Glob("/sys/class/block/loop*")
	if e != nil || len(names) != 8 {
		return nil, ErrInvalid
	}
	result := map[string]*unix.LoopInfo64{}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("/dev/loop%d", i)
		if names[i] != fmt.Sprintf("/sys/class/block/loop%d", i) {
			return nil, ErrInvalid
		}
		fd := s.fds[4]
		temporary := name != s.backend.Device
		if temporary {
			fd, e = unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				return nil, ErrInvalid
			}
		}
		var st unix.Stat_t
		se := unix.Fstat(fd, &st)
		v, e := unix.IoctlLoopGetStatus64(fd)
		var ce error
		if temporary {
			ce = unix.Close(fd)
		}
		if se != nil || ce != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(st.Rdev)) != 7 || unix.Minor(uint64(st.Rdev)) != uint32(i) {
			return nil, ErrInvalid
		}
		if errors.Is(e, unix.ENXIO) && temporary {
			result[name] = nil
			continue
		}
		if e != nil {
			return nil, ErrInvalid
		}
		if !temporary {
			if v.Device != s.record.FileDevice || v.Inode != s.record.FileInode || v.Number != uint32(i) || v.Offset != 0 || v.Sizelimit != uint64(DedicatedBackendBytes) || v.Flags != 0 || v.Encrypt_type != 0 || v.Encrypt_key_size != 0 {
				return nil, ErrInvalid
			}
			if !sourceGeometry(uint32(i)) {
				return nil, ErrInvalid
			}
		} else if v.Device == s.record.FileDevice && v.Inode == s.record.FileInode {
			return nil, ErrInvalid
		}
		result[name] = v
	}
	after, e := filepath.Glob("/sys/class/block/loop*")
	if e != nil || !reflect.DeepEqual(names, after) {
		return nil, ErrInvalid
	}
	return result, nil
}

func sourceFDAnchor(fd, parent int, name string) (sourceAnchor, error) {
	var a, b unix.Statx_t
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	const mask = unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_NLINK
	if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, mask, &a) != nil || unix.Statx(parent, name, unix.AT_SYMLINK_NOFOLLOW, mask, &b) != nil || a.Mask&mask != mask || b.Mask&mask != mask {
		return sourceAnchor{}, ErrInvalid
	}
	makeAnchor := func(v unix.Statx_t) sourceAnchor {
		return sourceAnchor{unix.Mkdev(v.Dev_major, v.Dev_minor), v.Ino, v.Mnt_id, unix.Mkdev(v.Rdev_major, v.Rdev_minor), v.Mode, v.Uid, v.Gid, v.Nlink}
	}
	x, y := makeAnchor(a), makeAnchor(b)
	if x != y || x.Inode == 0 || x.Mount == 0 {
		return sourceAnchor{}, ErrInvalid
	}
	return x, nil
}
func (s *sourceSession) close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var err error
	for i := len(s.fds) - 1; i >= 0; i-- {
		err = errors.Join(err, unix.Close(s.fds[i]))
	}
	return err
}

func sourceGeometry(minor uint32) bool {
	root := fmt.Sprintf("/sys/dev/block/7:%d", minor)
	var fs unix.Statfs_t
	if unix.Statfs(root, &fs) != nil || fs.Type != unix.SYSFS_MAGIC {
		return false
	}
	for k, want := range map[string]string{"size": "2097152\n", "ro": "0\n"} {
		f, e := os.Open(root + "/" + k)
		if e != nil {
			return false
		}
		d, e := io.ReadAll(io.LimitReader(f, 33))
		ce := f.Close()
		if e != nil || ce != nil || string(d) != want {
			return false
		}
	}
	return true
}
