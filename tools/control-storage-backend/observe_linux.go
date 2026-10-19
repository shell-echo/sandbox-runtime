package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// sourceObservation is operator-local diagnostic data, not a Store token,
// signed receipt, Docker-volume identity, lease or public protocol. Consumers
// must not turn this serialized snapshot into a runtime authorization.
type sourceObservation struct {
	Protocol     string           `json:"protocol"`
	Status       string           `json:"status"`
	Record       record           `json:"record"`
	Root         observedIdentity `json:"backing_root"`
	Image        observedIdentity `json:"backing_file"`
	Loop         observedIdentity `json:"loop_node"`
	RecordDigest string           `json:"record_sha256"`
	CensusDigest string           `json:"census_sha256"`
	Kernel       observedLoop     `json:"kernel"`
}

// Do not serialize LoopInfo64's filename, crypt-name/key or reserved arrays.
type observedLoop struct {
	Device    uint64 `json:"backing_device"`
	Inode     uint64 `json:"backing_inode"`
	Number    uint32 `json:"number"`
	Offset    uint64 `json:"offset"`
	SizeLimit uint64 `json:"size_limit"`
	Flags     uint32 `json:"flags"`
}

type observedIdentity struct {
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	MountID uint64 `json:"mount_id"`
	Rdevice uint64 `json:"rdevice"`
	Mode    uint16 `json:"mode"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Links   uint32 `json:"links"`
}

// Unlike inspect, this action requires a read-only backing mount, never
// creates a missing ceremony lock, opens no writable descriptor and needs no
// capability. The shared lock coordinates with the helper's exclusive device
// ceremony only; it cannot exclude another VM administrator.
func observeSource(ns, device string) (result sourceObservation, resultErr error) {
	if !namespacePattern.MatchString(ns) || !devicePattern.MatchString(device) {
		return result, invalid
	}
	minor, err := strconv.ParseUint(strings.TrimPrefix(device, "/dev/loop"), 10, 32)
	if err != nil {
		return result, invalid
	}
	var owned []int
	defer func() {
		for i := len(owned) - 1; i >= 0; i-- {
			if unix.Close(owned[i]) != nil {
				result, resultErr = sourceObservation{}, invalid
			}
		}
	}()
	open := func(parent int, name string, directory bool) (int, error) {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, name, flags, 0)
		if err == nil {
			owned = append(owned, fd)
		}
		return fd, err
	}
	dir, err := open(unix.AT_FDCWD, "/backing", true)
	if err != nil {
		return result, invalid
	}
	var ds unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(dir, &ds) != nil || ds.Mode != unix.S_IFDIR|0o700 || ds.Uid != 0 || ds.Gid != 0 ||
		unix.Fstatfs(dir, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return result, invalid
	}
	lock, err := open(dir, "ceremony.lock", false)
	if err != nil {
		return result, invalid
	}
	var ls unix.Stat_t
	if unix.Fstat(lock, &ls) != nil || !privateFile(ls) || ls.Size != 0 || ls.Dev != ds.Dev || unix.Flock(lock, unix.LOCK_SH|unix.LOCK_NB) != nil {
		return result, invalid
	}
	image, err := open(dir, "receipt.ext4", false)
	if err != nil {
		return result, invalid
	}
	var st unix.Stat_t
	if unix.Fstat(image, &st) != nil || !privateFile(st) || st.Dev != ds.Dev || st.Size != size || st.Blocks < size/512 {
		return result, invalid
	}
	seal, err := open(dir, "backend.json", false)
	if err != nil {
		return result, invalid
	}
	r, original, err := observedRecord(seal)
	if err != nil || r.Protocol != "sandbox-runtime.control-backend-provision.v1" || r.Namespace != ns || r.LoopDevice != device ||
		r.FileDevice != uint64(st.Dev) || r.FileInode != st.Ino || r.Bytes != size || !validInitialDigest(r.InitialImageSHA256) {
		return result, invalid
	}
	loop, err := open(unix.AT_FDCWD, device, false)
	if err != nil {
		return result, invalid
	}
	var dev unix.Stat_t
	if unix.Fstat(loop, &dev) != nil || dev.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(dev.Rdev)) != 7 || unix.Minor(uint64(dev.Rdev)) != uint32(minor) {
		return result, invalid
	}
	parents := []int{unix.AT_FDCWD, dir, dir, dir, unix.AT_FDCWD}
	names := []string{"/backing", "ceremony.lock", "receipt.ext4", "backend.json", device}
	fds := []int{dir, lock, image, seal, loop}
	anchors := make([]observedIdentity, len(fds))
	for i, fd := range fds {
		anchors[i], err = observeAnchor(fd, parents[i], names[i])
		if err != nil {
			return result, invalid
		}
	}
	for _, anchor := range anchors[1:4] {
		if anchor.Device != anchors[0].Device || anchor.MountID != anchors[0].MountID {
			return result, invalid
		}
	}
	before, err := loopCensus(r, loop)
	if err != nil || before[device] == nil || !sameBacking(r, *before[device], uint32(minor)) {
		return result, invalid
	}
	after, err := loopCensus(r, loop)
	if err != nil || !reflect.DeepEqual(before, after) {
		return result, invalid
	}
	for i, fd := range fds {
		now, err := observeAnchor(fd, parents[i], names[i])
		if err != nil || now != anchors[i] {
			return result, invalid
		}
	}
	retained, data, err := observedRecord(seal)
	if err != nil || retained != r || !bytes.Equal(data, original) ||
		unix.Fstat(image, &st) != nil || !privateFile(st) || st.Size != size || st.Blocks < size/512 ||
		unix.Fstat(lock, &ls) != nil || !privateFile(ls) || ls.Size != 0 ||
		unix.Fstat(dir, &ds) != nil || ds.Mode != unix.S_IFDIR|0o700 || ds.Uid != 0 || ds.Gid != 0 ||
		unix.Fstatfs(dir, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return result, invalid
	}
	last, err := unix.IoctlLoopGetStatus64(loop)
	if err != nil || *last != *after[device] {
		return result, invalid
	}
	census, _ := json.Marshal(after)
	return sourceObservation{"sandbox-runtime.control-backend-source-observation.v1", "current-source-inode-observation-only", r,
		anchors[0], anchors[2], anchors[4], observationDigest(original), observationDigest(census),
		observedLoop{last.Device, last.Inode, last.Number, last.Offset, last.Sizelimit, last.Flags}}, nil
}

// Check the live name against the retained fd, including mount identity. The
// underlying image may receive legitimate mounted filesystem writes, so this
// intentionally does not assert an immutable image content/mtime snapshot.
func observeAnchor(fd, parent int, name string) (observedIdentity, error) {
	var held, live unix.Statx_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	const mask = unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_NLINK
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, mask, &held) != nil ||
		unix.Statx(parent, name, unix.AT_SYMLINK_NOFOLLOW, mask, &live) != nil ||
		!sameObservedAnchor(held, live) {
		return observedIdentity{}, invalid
	}
	return observedIdentity{unix.Mkdev(held.Dev_major, held.Dev_minor), held.Ino, held.Mnt_id, unix.Mkdev(held.Rdev_major, held.Rdev_minor), held.Mode, held.Uid, held.Gid, held.Nlink}, nil
}

func sameObservedAnchor(a, b unix.Statx_t) bool {
	const required = unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_NLINK
	return a.Mask&required == required && b.Mask&required == required && a.Mnt_id != 0 && a.Ino != 0 &&
		a.Dev_major == b.Dev_major && a.Dev_minor == b.Dev_minor && a.Ino == b.Ino && a.Mnt_id == b.Mnt_id &&
		a.Rdev_major == b.Rdev_major && a.Rdev_minor == b.Rdev_minor && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink
}

func observedRecord(fd int) (record, []byte, error) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !privateFile(st) || st.Size <= 0 || st.Size > 4096 {
		return record{}, nil, invalid
	}
	d := make([]byte, 4097)
	n, err := unix.Pread(fd, d, 0)
	if err != nil || int64(n) != st.Size || n > 4096 {
		return record{}, nil, invalid
	}
	d = d[:n]
	var r record
	if json.Unmarshal(d, &r) != nil {
		return record{}, nil, invalid
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(d, canonical) {
		return record{}, nil, invalid
	}
	return r, d, nil
}

func validInitialDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}

func observationDigest(b []byte) string {
	d := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(d[:])
}
