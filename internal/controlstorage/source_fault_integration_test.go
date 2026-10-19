//go:build integration && linux

package controlstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const sourceFaultRoot = "/var/lib/sandbox-runtime/control-receipts"
const sourceFaultKey = "22222222222222222222222222222222"

// This binary runs only in a separately inventoried, operator-owned fixture.
// Its inputs describe a previously composed Store, not production admission.
func sourceFaultFixture(t *testing.T) (Binding, DedicatedBackend, string, string) {
	t.Helper()
	if os.Getenv("CONTROL_STORAGE_FAULT_REAL") != "1" {
		t.Skip("explicit source-bound Linux fault fixture required")
	}
	var input struct {
		Storage          Binding
		Backend          DedicatedBackend
		SourceSealDigest string
	}
	volume := os.Getenv("CONTROL_STORAGE_VOLUME_BINDING")
	if json.Unmarshal([]byte(os.Getenv("CONTROL_STORAGE_FAULT_BINDING")), &input) != nil || input.Storage.Validate() != nil || input.Backend.Validate() != nil || input.Storage.UID != 57010 || input.Storage.GID != 57011 || input.Backend.Device != "/dev/loop7" || !hashPattern.MatchString(input.SourceSealDigest) || !hashPattern.MatchString(volume) {
		t.Fatal("invalid private fixture inputs")
	}
	return input.Storage, input.Backend, input.SourceSealDigest, volume
}

type sourceFaultFile struct {
	Digest string
	Inode  uint64
	Size   int64
	Mode   uint32
}

func sourceFaultSnapshot(t *testing.T) map[string]sourceFaultFile {
	t.Helper()
	names, err := os.ReadDir(sourceFaultRoot)
	if err != nil || len(names) > 12 {
		t.Fatal("unexpected fault namespace", err)
	}
	result := map[string]sourceFaultFile{}
	for _, n := range names {
		p := filepath.Join(sourceFaultRoot, n.Name())
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode != unix.S_IFREG|0o600 || st.Uid != 57010 || st.Gid != 57011 || st.Nlink != 1 || st.Size > 2<<20 {
			t.Fatal("unexpected private fixture file")
		}
		d, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		result[n.Name()] = sourceFaultFile{sum(d), st.Ino, st.Size, st.Mode}
	}
	return result
}

func sourceFaultSnapshotLog(t *testing.T, label string) map[string]sourceFaultFile {
	s := sourceFaultSnapshot(t)
	d, _ := json.Marshal(s)
	fmt.Printf("SOURCE_FAULT_FILES %s %s\n", label, d)
	return s
}

func sourceFaultSpace(t *testing.T, fd int) int64 {
	t.Helper()
	var st unix.Statfs_t
	if unix.Fstatfs(fd, &st) != nil || st.Type != unix.EXT4_SUPER_MAGIC || st.Bsize != 4096 || st.Blocks*4096 > 1<<30 || st.Blocks*4096 < 512<<20 {
		t.Fatal("unexpected dedicated filesystem")
	}
	return int64(st.Bavail) * 4096
}

// Fault-only disk pressure: an unlinked file in this exact private ext4. No
// pathname remains for Store to overlook, no other scope gains a reservation,
// and closing this fd releases only these test-owned blocks.
func sourceFaultReserve(t *testing.T) *os.File {
	t.Helper()
	p := filepath.Join(sourceFaultRoot, "fault-pressure")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if os.Remove(p) != nil {
		_ = f.Close()
		t.Fatal("cannot unlink pressure file")
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Nlink != 0 || st.Uid != 57010 || st.Gid != 57011 || unix.Major(uint64(st.Dev)) != 7 || unix.Minor(uint64(st.Dev)) != 7 {
		_ = f.Close()
		t.Fatal("pressure fd is outside exact owned backend")
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func sourceFaultFill(t *testing.T, ctx context.Context, f *os.File, leave int64) {
	t.Helper()
	start := sourceFaultSpace(t, int(f.Fd()))
	var allocated int64
	for count := 0; count < 2048; count++ {
		if ctx.Err() != nil {
			t.Fatal("disk-pressure operation exceeded existing deadline")
		}
		available := sourceFaultSpace(t, int(f.Fd()))
		if available <= leave {
			if start-available < 512<<20 || f.Sync() != nil {
				t.Fatal("inadequate actual pressure")
			}
			fmt.Printf("REAL_PRESSURE initial=%d final=%d allocated=%d unlinked=true\n", start, available, allocated)
			return
		}
		chunk := min(int64(1<<20), available-leave)
		if chunk%4096 != 0 || allocated+chunk > 1<<30 || unix.Fallocate(int(f.Fd()), 0, allocated, chunk) != nil {
			t.Fatal("pressure allocation failed before selected boundary; retain fixture")
		}
		allocated += chunk
	}
	t.Fatal("bounded pressure loop exhausted")
}

func sourceFaultPayload() []byte { return bytes.Repeat([]byte("fault-evidence!\n"), 8192) }

func TestSourceStoreFaultReal(t *testing.T) {
	b, backend, seal, volume := sourceFaultFixture(t)
	if os.Geteuid() != 57010 || os.Getegid() != 57011 {
		t.Fatal("wrong actual owner")
	}
	action := os.Getenv("CONTROL_STORAGE_FAULT_ACTION")
	stage := os.Getenv("CONTROL_STORAGE_FAULT_STAGE")
	before := sourceFaultSnapshotLog(t, "before")
	if action == "check-refuse" || action == "check-consistent" {
		_, objectPending := before[pendingName]
		_, manifestPending := before[pendingManifest]
		_, published := before[string(Closure)+"-"+sourceFaultKey]
		switch stage {
		case "before-object", "before-call":
			if objectPending || manifestPending || published {
				t.Fatal("unexpected pre-effect residue")
			}
		case "enospc", "after-object-sync":
			if !objectPending || manifestPending || published {
				t.Fatal("missing exact pending object")
			}
		case "after-object-rename":
			if objectPending || manifestPending || !published {
				t.Fatal("unexpected object publication residue")
			}
		case "after-manifest-sync":
			if objectPending || !manifestPending || !published {
				t.Fatal("missing staged manifest")
			}
		case "after-manifest-rename":
			if objectPending || manifestPending || !published {
				t.Fatal("unexpected completed publication")
			}
		default:
			t.Fatal("unknown recovery stage")
		}
		if published {
			d, e := os.ReadFile(filepath.Join(sourceFaultRoot, string(Closure)+"-"+sourceFaultKey))
			if e != nil || !bytes.Equal(d, sourceFaultPayload()) {
				t.Fatal("published fault payload differs")
			}
		}
		s, err := OpenSourceBound(sourceFaultRoot, b, backend, seal, volume)
		if action == "check-refuse" {
			if err == nil {
				_ = s.Close()
				t.Fatal("incomplete namespace was repaired")
			}
			// Even explicit initialize cannot discard a marker/residue.
			if s, err = InitializeSourceBound(t.Context(), sourceFaultRoot, b, backend, seal, volume); err == nil {
				_ = s.Close()
				t.Fatal("incomplete namespace was reinitialized")
			}
		} else {
			if err != nil {
				t.Fatal("consistent namespace cannot reopen", err)
			}
			state, e := s.ReadState(t.Context(), strings.Repeat("1", 32))
			if e != nil || !state.Found || !bytes.Equal(state.Data, bytes.Repeat([]byte("source-bound-persistence\n"), 4096)) {
				t.Fatal("original state lost", e)
			}
			_, present := before[string(Closure)+"-"+sourceFaultKey]
			if present != (stage == "after-manifest-rename") || s.Check() != nil || s.Close() != nil {
				t.Fatal("unexpected complete namespace")
			}
		}
		if !reflect.DeepEqual(before, sourceFaultSnapshotLog(t, "after-reopen")) {
			t.Fatal("reopen or failed initialize changed original evidence")
		}
		fmt.Println("SOURCE_FAULT_REOPEN_PASS", action, stage)
		return
	}
	s, err := OpenSourceBound(sourceFaultRoot, b, backend, seal, volume)
	if err != nil {
		t.Fatal("source-bound Store admission", err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	switch action {
	case "preflight":
		reserve := sourceFaultReserve(t)
		sourceFaultFill(t, ctx, reserve, 32<<20)
		attempted := false
		s.fault = func(string) error { attempted = true; return nil }
		if err := s.Put(ctx, Closure, sourceFaultKey, sourceFaultPayload()); !errors.Is(err, ErrCapacity) || attempted || s.poisoned || s.Check() != nil {
			t.Fatal("capacity preflight did not fail without effect", err)
		}
		if !reflect.DeepEqual(before, sourceFaultSnapshot(t)) || reserve.Close() != nil || s.Check() != nil {
			t.Fatal("preflight refusal changed namespace")
		}
		if err := s.Put(ctx, Closure, sourceFaultKey, sourceFaultPayload()); err != nil {
			t.Fatal("owner did not recover after pressure release", err)
		}
		fmt.Println("REAL_CAPACITY_PREFLIGHT_NO_EFFECT_PASS")
	case "enospc":
		reserve := sourceFaultReserve(t)
		var syscallStage string
		s.writeError = func(name, at string, e error) {
			if name == pendingName && errors.Is(e, unix.ENOSPC) {
				syscallStage = at
				fmt.Println("ACTUAL_STORE_SYSCALL_ERROR", name, at, "ENOSPC")
			}
		}
		s.fault = func(at string) error {
			if at == "before-object" {
				fmt.Println("STORE_SPACE_PREFLIGHT_PASSED")
				sourceFaultFill(t, ctx, reserve, 8*4096)
			}
			return nil
		}
		if err := s.Put(ctx, Closure, sourceFaultKey, sourceFaultPayload()); !errors.Is(err, ErrUncertain) {
			t.Fatal("real ENOSPC was not uncertain", err)
		}
		if syscallStage != "write" && syscallStage != "sync" {
			t.Fatal("this run did not prove pending-object write/sync ENOSPC; retain observed branch")
		}
		if reserve.Close() != nil {
			t.Fatal("pressure release failed")
		}
		if _, ok := sourceFaultSnapshot(t)[pendingName]; !ok {
			t.Fatal("this run did not leave expected pending residue")
		}
		if s.Check() == nil || s.Put(t.Context(), Closure, strings.Repeat("3", 32), []byte("retry")) == nil {
			t.Fatal("uncertain owner resumed")
		}
		fmt.Println("REAL_STORE_ENOSPC_UNCERTAIN_PASS")
	case "cancel":
		if stage == "before-call" {
			cancel()
		} else if stage == "after-object-sync" {
			s.fault = func(at string) error {
				if at == stage {
					cancel()
				}
				return nil
			}
		} else {
			t.Fatal("invalid cancellation stage")
		}
		err := s.Put(ctx, Closure, sourceFaultKey, sourceFaultPayload())
		if stage == "before-call" {
			if err == nil || s.Check() != nil || !reflect.DeepEqual(before, sourceFaultSnapshot(t)) {
				t.Fatal("canceled no-effect call changed storage")
			}
		} else if !errors.Is(err, ErrUncertain) || s.Check() == nil {
			t.Fatal("post-write cancellation not uncertain", err)
		}
		fmt.Println("REAL_STORE_CANCEL_PASS", stage)
	case "crash":
		valid := false
		for _, at := range []string{"before-object", "after-object-sync", "after-object-rename", "after-manifest-sync", "after-manifest-rename"} {
			valid = valid || stage == at
		}
		if !valid {
			t.Fatal("invalid crash stage")
		}
		s.fault = func(at string) error {
			if at == stage {
				fmt.Println("REAL_STORE_PROCESS_EXIT", stage)
				os.Exit(73) // No Go defers or application cleanup; not power loss.
			}
			return nil
		}
		_ = s.Put(ctx, Closure, sourceFaultKey, sourceFaultPayload())
		t.Fatal("crash point not reached")
	default:
		t.Fatal("unknown fixture action")
	}
	sourceFaultSnapshotLog(t, "after")
}

func TestSourceStoreWrongPrincipalReal(t *testing.T) {
	b, backend, seal, volume := sourceFaultFixture(t)
	mode := os.Getenv("CONTROL_STORAGE_FAULT_STAGE")
	wantUID, wantGID := 57012, 57012
	sourceReadable, rootReadable := false, false
	switch mode {
	case "wrong-uid":
	case "wrong-gid":
		wantUID, rootReadable = 57010, true
	case "missing-socket-group":
		wantUID, wantGID, sourceReadable, rootReadable = 57010, 57011, true, true
	default:
		t.Fatal("unknown denial principal")
	}
	groups, err := os.Getgroups()
	if err != nil || os.Geteuid() != wantUID || os.Getegid() != wantGID {
		t.Fatal("actual wrong principal differs")
	}
	for _, g := range groups {
		if g != wantGID {
			t.Fatal("unexpected supplementary group", g)
		}
	}
	fmt.Printf("ACTUAL_PRINCIPAL uid=%d gid=%d groups=%v\n", os.Geteuid(), os.Getegid(), groups)
	for _, probe := range []struct {
		path     string
		readable bool
	}{{SourceMountPath + "/backend.json", sourceReadable}, {sourceFaultRoot + "/" + manifestName, rootReadable}} {
		f, e := os.Open(probe.path)
		if e == nil {
			_ = f.Close()
		}
		if probe.readable != (e == nil) || (!probe.readable && !errors.Is(e, unix.EACCES)) {
			t.Fatal("unexpected actual file DAC", e)
		}
	}
	conn, err := net.DialTimeout("unix", "/run/control-storage-docker.sock", time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, unix.EACCES) {
		t.Fatal("wrong principal socket connect was not EACCES", err)
	}
	if s, e := OpenSourceBound(sourceFaultRoot, b, backend, seal, volume); e == nil {
		_ = s.Close()
		t.Fatal("wrong principal obtained source Store")
	}
	fmt.Println("REAL_SOURCE_STORE_SOCKET_PRINCIPAL_REFUSAL_PASS", mode)
}
