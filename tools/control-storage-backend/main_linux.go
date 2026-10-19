// This operator-only diagnostic helper is not a runtime role or auto-recovery
// service. Every device operation requires an explicitly supplied exact node.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const size = 1 << 30

var invalid = errors.New("backend ceremony refused; retain owned evidence and resources")
var namespacePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var devicePattern = regexp.MustCompile(`^/dev/loop(0|[1-9][0-9]{0,5})$`)

type record struct {
	Protocol           string `json:"protocol"`
	Namespace          string `json:"namespace"`
	LoopDevice         string `json:"loop_device"`
	FileDevice         uint64 `json:"file_device"`
	FileInode          uint64 `json:"file_inode"`
	Bytes              int64  `json:"bytes"`
	InitialImageSHA256 string `json:"initial_image_sha256"`
	ControlGID         uint32 `json:"control_gid,omitempty"`
}

func main() {
	mode := flag.String("mode", "legacy", "legacy or source-v2; fresh namespace only")
	action := flag.String("action", "", "prepare, seal, census, attach, inspect, observe, detach")
	ns := flag.String("namespace", "", "fresh 32-hex diagnostic namespace")
	device := flag.String("device", "", "one explicitly authorized /dev/loopN")
	flag.Parse()
	if flag.NArg() != 0 || !namespacePattern.MatchString(*ns) || !devicePattern.MatchString(*device) || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, invalid)
		os.Exit(1)
	}
	if err := runMode(*action, *ns, *device, *mode); err != nil {
		fmt.Fprintln(os.Stderr, invalid)
		os.Exit(1)
	}
}

// Only /backing in an exclusively owned Docker volume is writable. No device
// discovery, loop-control, mknod, mount, resize, force detach, or shell execution.
func run(action, ns, device string) error { return runMode(action, ns, device, "legacy") }
func runMode(action, ns, device, mode string) error {
	p, err := backendMode(mode)
	if err != nil {
		return err
	}
	if action == "observe" {
		if mode != "legacy" {
			return invalid
		}
		observation, err := observeSource(ns, device)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(observation)
	}
	if !namespacePattern.MatchString(ns) || !devicePattern.MatchString(device) || (action != "prepare" && action != "seal" && action != "census" && action != "attach" && action != "inspect" && action != "detach") {
		return invalid
	}
	dir, err := unix.Open("/backing", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return invalid
	}
	defer unix.Close(dir)
	var ds unix.Stat_t
	if unix.Fstat(dir, &ds) != nil || ds.Uid != 0 || ds.Gid != p.gid || ds.Mode != unix.S_IFDIR|p.dirMode {
		return invalid
	}
	lockFlags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if action == "prepare" {
		lockFlags |= unix.O_CREAT | unix.O_EXCL
	}
	lock, err := unix.Openat(dir, "ceremony.lock", lockFlags, p.fileMode)
	if err != nil {
		return invalid
	}
	defer unix.Close(lock)
	if action == "prepare" && (unix.Fchown(lock, 0, int(p.gid)) != nil || unix.Fchmod(lock, p.fileMode) != nil) {
		return invalid
	}
	var ls unix.Stat_t
	if unix.Fstat(lock, &ls) != nil || !p.privateFile(ls) || unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return invalid
	}
	if action == "prepare" {
		fd, err := unix.Openat(dir, "receipt.ext4", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, p.fileMode)
		if err != nil {
			return invalid
		}
		defer unix.Close(fd)
		if unix.Fchown(fd, 0, int(p.gid)) != nil || unix.Fchmod(fd, p.fileMode) != nil {
			return invalid
		}
		if unix.Fallocate(fd, 0, 0, size) != nil || unix.Fsync(fd) != nil || unix.Fsync(dir) != nil {
			return invalid
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "allocated-unformatted", "bytes": size, "namespace": ns})
	}
	fd, err := unix.Openat(dir, "receipt.ext4", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return invalid
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !p.privateFile(st) || st.Size != size || st.Blocks < size/512 {
		return invalid
	}
	if action == "seal" {
		// mke2fs/debugfs ran before this step. Persist their image writes before
		// publishing a durable hash/identity record for those bytes.
		if unix.Fsync(fd) != nil {
			return invalid
		}
		magic := make([]byte, 2)
		if n, err := unix.Pread(fd, magic, 1024+56); err != nil || n != 2 || !bytes.Equal(magic, []byte{0x53, 0xef}) {
			return invalid
		}
		digest, err := fileDigest(fd)
		if err != nil || unix.Fsync(fd) != nil {
			return invalid
		}
		r := record{p.protocol, ns, device, uint64(st.Dev), st.Ino, size, digest, p.gid}
		d, _ := json.Marshal(r)
		out, err := unix.Openat(dir, "backend.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return invalid
		}
		defer unix.Close(out)
		if unix.Fchown(out, 0, int(p.gid)) != nil || unix.Fchmod(out, p.fileMode) != nil {
			return invalid
		}
		if n, err := unix.Write(out, d); err != nil || n != len(d) || unix.Fsync(out) != nil || unix.Fsync(dir) != nil {
			return invalid
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	r, err := readRecordMode(dir, p)
	if err != nil || r.Protocol != p.protocol || r.ControlGID != p.gid || r.Namespace != ns || r.LoopDevice != device || r.FileDevice != uint64(st.Dev) || r.FileInode != st.Ino || r.Bytes != size {
		return invalid
	}
	if action == "census" {
		facts, err := loopCensus(r, -1)
		if err != nil {
			return invalid
		}
		return json.NewEncoder(os.Stdout).Encode(struct {
			Status string
			Loops  map[string]*unix.LoopInfo64
		}{"current-kernel-loop-census-only", facts})
	}
	minor, err := strconv.ParseUint(strings.TrimPrefix(device, "/dev/loop"), 10, 32)
	if err != nil {
		return invalid
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if action == "attach" || action == "detach" {
		flags = unix.O_RDWR | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	loop, err := unix.Open(device, flags, 0)
	if err != nil {
		return invalid
	}
	defer unix.Close(loop)
	var dev unix.Stat_t
	if unix.Fstat(loop, &dev) != nil || dev.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(dev.Rdev)) != 7 || uint64(unix.Minor(uint64(dev.Rdev))) != minor {
		return invalid
	}
	if _, err := loopCensus(r, loop); err != nil {
		return invalid
	}
	if action == "attach" {
		// No reconnect of used bytes. A restart needs a separately reviewed
		// recovery procedure, never a digest update or implicit fresh mkfs.
		digest, err := fileDigest(fd)
		if err != nil || digest != r.InitialImageSHA256 {
			return invalid
		}
		if _, err := unix.IoctlLoopGetStatus64(loop); !errors.Is(err, unix.ENXIO) {
			return invalid
		}
		config := unix.LoopConfig{Fd: uint32(fd), Info: unix.LoopInfo64{Sizelimit: size}}
		if unix.IoctlLoopConfigure(loop, &config) != nil {
			return invalid
		}
	}
	status, err := unix.IoctlLoopGetStatus64(loop)
	if err != nil || !sameBacking(r, *status, uint32(minor)) {
		return invalid
	}
	if _, err := loopCensus(r, loop); err != nil {
		return invalid
	}
	if action == "detach" {
		// O_EXCL holds a kernel block-device claim: mounted/claimed devices
		// fail EBUSY and a new ordinary mount cannot race this fd.
		// Caller must first remove the exact owned filesystem volume and all
		// consumers. CLR_FD can be lazy: only ENXIO counts as detached. Never
		// delete backing files here, including after an uncertain result.
		if unix.IoctlSetInt(loop, unix.LOOP_CLR_FD, 0) != nil {
			return invalid
		}
		if _, err := unix.IoctlLoopGetStatus64(loop); !errors.Is(err, unix.ENXIO) {
			return invalid
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "detached-exact-device", "namespace": ns, "record": r})
	}
	if action != "attach" && action != "inspect" {
		return invalid
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Status string
		Record record
		Kernel unix.LoopInfo64
	}{"source-inode-matched", r, *status})
}

// Read every currently visible loop device through explicitly granted nodes.
// A missing/inaccessible node or census drift fails closed; no broad device
// rule, discovery allocation or fallback is used. Host administrators remain
// trusted: two snapshots do not fence non-cooperating privileged operations.
func loopCensus(r record, selectedFD int) (map[string]*unix.LoopInfo64, error) {
	names, err := filepath.Glob("/sys/class/block/loop*")
	if err != nil || len(names) == 0 || len(names) > 64 {
		return nil, invalid
	}
	facts := map[string]*unix.LoopInfo64{}
	for _, name := range names {
		device := "/dev/" + filepath.Base(name)
		if !devicePattern.MatchString(device) {
			return nil, invalid
		}
		minor, err := strconv.ParseUint(strings.TrimPrefix(device, "/dev/loop"), 10, 32)
		if err != nil {
			return nil, invalid
		}
		fd := selectedFD
		owned := false
		if device != r.LoopDevice || selectedFD < 0 {
			fd, err = unix.Open(device, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return nil, invalid
			}
			owned = true
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(st.Rdev)) != 7 || uint64(unix.Minor(uint64(st.Rdev))) != minor {
			if owned {
				unix.Close(fd)
			}
			return nil, invalid
		}
		status, statusErr := unix.IoctlLoopGetStatus64(fd)
		if owned {
			if unix.Close(fd) != nil {
				return nil, invalid
			}
		}
		if statusErr != nil && !errors.Is(statusErr, unix.ENXIO) {
			return nil, invalid
		}
		if statusErr == nil && device != r.LoopDevice && status.Device == r.FileDevice && status.Inode == r.FileInode {
			return nil, invalid
		}
		facts[device] = status
	}
	after, err := filepath.Glob("/sys/class/block/loop*")
	if err != nil || strings.Join(after, "\x00") != strings.Join(names, "\x00") {
		return nil, invalid
	}
	if _, ok := facts[r.LoopDevice]; !ok {
		return nil, invalid
	}
	return facts, nil
}

func privateFile(s unix.Stat_t) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&0o7777 == 0o600 && s.Uid == 0 && s.Gid == 0 && s.Nlink == 1
}
func sameBacking(r record, s unix.LoopInfo64, minor uint32) bool {
	return s.Device == r.FileDevice && s.Inode == r.FileInode && s.Offset == 0 && s.Sizelimit == size && s.Number == minor && s.Flags == 0 && s.Encrypt_type == 0 && s.Encrypt_key_size == 0
}
func fileDigest(fd int) (string, error) {
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return "", invalid
	}
	copy, err := unix.Dup(fd)
	if err != nil {
		return "", invalid
	}
	f := os.NewFile(uintptr(copy), "image")
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, size+1))
	if err != nil || n != size {
		return "", invalid
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func readRecord(dir int) (record, error) {
	p, _ := backendMode("legacy")
	return readRecordMode(dir, p)
}
func readRecordMode(dir int, p backendPolicy) (record, error) {
	fd, err := unix.Openat(dir, "backend.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return record{}, invalid
	}
	f := os.NewFile(uintptr(fd), "record")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !p.privateFile(st) || st.Size > 4096 {
		return record{}, invalid
	}
	d, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(d) > 4096 {
		return record{}, invalid
	}
	var r record
	if json.Unmarshal(d, &r) != nil {
		return record{}, invalid
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(d, canonical) {
		return record{}, invalid
	}
	return r, nil
}
