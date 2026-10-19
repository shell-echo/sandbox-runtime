//go:build integration && linux

package controlstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests require the separate, explicitly authorized operator fixture.
// The fixture owns provisioning, exact loop inode checks, Docker identities,
// external evidence and cleanup. Environment values are test inputs, not a
// production attestation. No test opens a block device or changes propagation.
func dedicatedLiveFixture(t *testing.T) (string, Binding, DedicatedBackend) {
	t.Helper()
	if os.Getenv("SANDBOX_RUNTIME_DEDICATED_BACKEND") != "1" {
		t.Skip("explicit dedicated Linux filesystem fixture required")
	}
	b := testBinding()
	b.Namespace = os.Getenv("SANDBOX_RUNTIME_BACKEND_NAMESPACE")
	b.StorageID = "control-execution-" + b.Namespace
	backend := DedicatedBackend{Protocol: DedicatedBackendProtocol, Device: "/dev/loop7", Bytes: DedicatedBackendBytes,
		BackingFile: os.Getenv("SANDBOX_RUNTIME_BACKEND_FILE")}
	if b.Validate() != nil || backend.Validate() != nil || os.Geteuid() != 57010 || os.Getegid() != 57011 {
		t.Fatal("invalid diagnostic binding or owner")
	}
	return "/receipt", b, backend
}

// This is a positive admission test: an unsupported actual mount must FAIL,
// rather than be relabelled as a successful Store gate by the diagnostic.
func TestDedicatedStorageRealAdmission(t *testing.T) {
	root, b, backend := dedicatedLiveFixture(t)
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("positive admission fixture requires an empty filesystem")
	}
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	kernel, _, kernelErr := readKernelRoot(int(f.Fd()), root)
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || f.Close() != nil {
		t.Fatal("root diagnostic unavailable")
	}
	loopErr := readDedicatedLoop(uint64(st.Dev), backend)
	t.Logf("kernel_root=%+v kernel_error=%v exact_backing_error=%v", kernel, kernelErr, loopErr)
	s, err := InitializeDedicated(t.Context(), root, b, backend)
	if err != nil {
		t.Fatalf("dedicated Store admission refused: %v; no raw filesystem result can replace this gate", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// This isolates the real mount invariant from the still-separate source-inode
// composition. It never initializes a Store or substitutes a caller assertion.
func TestDedicatedBackendRealPrivateMount(t *testing.T) {
	root, _, _ := dedicatedLiveFixture(t)
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	kernel, available, kernelErr := readKernelRoot(int(f.Fd()), root)
	closeErr := f.Close()
	if kernelErr != nil || closeErr != nil || kernel.Identity.Filesystem != "ext4" || kernel.Identity.SourceDigest != sum([]byte("/dev/loop7")) || available < 512<<20 {
		t.Fatalf("strict private mount failed: kernel=%v close=%v", kernelErr, closeErr)
	}
	t.Logf("PRIVATE_MOUNT_PASS identity=%+v mount_id=%d available_bytes=%d; not Store admission", kernel.Identity, kernel.MountID, available)
}

type rawBackendRecord struct {
	Namespace string   `json:"namespace"`
	Device    uint64   `json:"device"`
	Inode     uint64   `json:"inode"`
	FSID      [2]int32 `json:"fsid"`
	Blocks    uint64   `json:"blocks"`
	Bytes     int64    `json:"bytes"`
	Digest    string   `json:"digest"`
}

func rawBackendFacts(t *testing.T, root string) (unix.Stat_t, unix.Statfs_t) {
	t.Helper()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Stat(root, &st) != nil || unix.Statfs(root, &fs) != nil || unix.Major(uint64(st.Dev)) != 7 || unix.Minor(uint64(st.Dev)) != 7 ||
		st.Ino != 2 || st.Uid != 57010 || st.Gid != 57011 || st.Mode != unix.S_IFDIR|0o700 ||
		fs.Type != unix.EXT4_SUPER_MAGIC || fs.Bsize != 4096 || fs.Frsize != 4096 || fs.Blocks*4096 > 1<<30 || fs.Blocks*4096 < 512<<20 ||
		fs.Fsid.Val == [2]int32{} || fs.Flags&unix.ST_RDONLY != 0 || fs.Flags&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) != unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC {
		t.Fatal("raw diagnostic filesystem identity/geometry/flags differ")
	}
	t.Logf("raw filesystem dev=%d inode=%d fsid=%v data_bytes=%d available_bytes=%d flags=%d; not Store admission", st.Dev, st.Ino, fs.Fsid.Val, fs.Blocks*4096, fs.Bavail*4096, fs.Flags)
	return st, fs
}

func syncRawRoot(t *testing.T, root string) {
	t.Helper()
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("root sync=%v close=%v", err, closeErr)
	}
}

func writeRawNew(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	n, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if n != len(data) || writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatalf("write=%d/%d %v sync=%v close=%v", n, len(data), writeErr, syncErr, closeErr)
	}
}

// Raw filesystem persistence and ENOSPC are intentionally separate from the
// Store API. Never run these on an initialized namespace or infer a Store quota,
// no-effect receipt, sole consumer or Profile admission from their success.
func TestDedicatedBackendRealFilesystem(t *testing.T) {
	root, b, _ := dedicatedLiveFixture(t)
	st, fs := rawBackendFacts(t, root)
	data := bytes.Repeat([]byte(b.Namespace), 32768)
	const payload = "diagnostic-payload"
	const record = "diagnostic-record.json"
	want := rawBackendRecord{b.Namespace, uint64(st.Dev), st.Ino, fs.Fsid.Val, fs.Blocks, int64(len(data)), sum(data)}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	stage := os.Getenv("SANDBOX_RUNTIME_BACKEND_STAGE")
	if stage == "write" {
		if len(entries) != 0 {
			t.Fatal("raw diagnostic requires a fresh empty filesystem")
		}
		// Use this valid executable, not a script, so EACCES proves noexec.
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(executable)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 4 || info.Size() > 64<<20 {
			t.Fatal("bounded ELF unavailable")
		}
		elf, err := os.ReadFile(executable)
		if err != nil || len(elf) < 4 || string(elf[:4]) != "\x7fELF" || len(elf) > 64<<20 {
			t.Fatal("bounded ELF unavailable")
		}
		probe := filepath.Join(root, "diagnostic-noexec")
		writeRawNew(t, probe, elf, 0o700)
		if err := exec.CommandContext(t.Context(), probe, "-test.run=^$").Run(); !errors.Is(err, unix.EACCES) {
			t.Fatalf("noexec probe: %v", err)
		}
		if err := os.Remove(probe); err != nil {
			t.Fatal(err)
		}
		writeRawNew(t, filepath.Join(root, payload), data, 0o600)
		writeRawNew(t, filepath.Join(root, record), encoded, 0o600)
		syncRawRoot(t, root)
		t.Logf("RAW_WRITE_NOEXEC_PASS record=%s", encoded)
		return
	}
	if stage != "reopen-enospc" && stage != "verify" {
		t.Fatal("unknown raw diagnostic stage")
	}
	if len(entries) != 2 || entries[0].Name() != payload || entries[1].Name() != record {
		t.Fatal("unexplained raw diagnostic objects; preserve filesystem")
	}
	check := func() {
		t.Helper()
		for name, expected := range map[string][]byte{payload: data, record: encoded} {
			got, err := os.ReadFile(filepath.Join(root, name))
			var file unix.Stat_t
			if err != nil || !bytes.Equal(got, expected) || unix.Lstat(filepath.Join(root, name), &file) != nil || file.Dev != st.Dev || file.Mode != unix.S_IFREG|0o600 || file.Uid != st.Uid || file.Gid != st.Gid || file.Nlink != 1 {
				t.Fatal("persistent raw file changed")
			}
		}
	}
	check()
	if stage == "verify" {
		t.Logf("RAW_REOPEN_PASS record=%s", encoded)
		return
	}
	stress := filepath.Join(root, "diagnostic-stress")
	f, err := os.OpenFile(stress, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var original unix.Stat_t
	if unix.Fstat(int(f.Fd()), &original) != nil {
		f.Close()
		t.Fatal("stress identity unavailable")
	}
	var written int64
	var writeErr error
	for written <= DedicatedBackendBytes && writeErr == nil {
		var n int
		n, writeErr = f.Write(data)
		written += int64(n)
		if writeErr == nil {
			writeErr = f.Sync() // Surface filesystem errors before another write.
		}
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if !errors.Is(writeErr, unix.ENOSPC) || (syncErr != nil && !errors.Is(syncErr, unix.ENOSPC)) || closeErr != nil {
		t.Fatalf("unexpected physical exhaustion: bytes=%d write=%v sync=%v close=%v; retain stress evidence", written, writeErr, syncErr, closeErr)
	}
	_, full := rawBackendFacts(t, root)
	if full.Blocks != fs.Blocks || full.Fsid != fs.Fsid || full.Bavail*4096 >= uint64(len(data)) || written < 512<<20 || written > DedicatedBackendBytes {
		t.Fatal("ENOSPC did not match fixed filesystem geometry; retain stress evidence")
	}
	check()
	var current unix.Stat_t
	if unix.Lstat(stress, &current) != nil || current.Dev != original.Dev || current.Ino != original.Ino || current.Nlink != 1 || current.Mode != unix.S_IFREG|0o600 || current.Uid != st.Uid || current.Gid != st.Gid {
		t.Fatal("stress object replaced; preserve it")
	}
	if err := os.Remove(stress); err != nil {
		t.Fatal(err)
	}
	syncRawRoot(t, root)
	_, restored := rawBackendFacts(t, root)
	if restored.Fsid != fs.Fsid || restored.Blocks != fs.Blocks || restored.Bavail*4096 < 512<<20 {
		t.Fatal("capacity did not recover after exact stress deletion")
	}
	check()
	fmt.Printf("RAW_ENOSPC_PASS bytes=%d errno=ENOSPC stress_deleted=true available_after=%d; not Store quota or admission\n", written, restored.Bavail*4096)
}
