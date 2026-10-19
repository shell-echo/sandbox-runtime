//go:build darwin || linux

package controlstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testBinding() Binding {
	return Binding{Layout: NewLayout(), Namespace: strings.Repeat("a", 32), StorageID: "control-execution-" + strings.Repeat("a", 32),
		ProfileDigest: "sha256:" + strings.Repeat("b", 64), TemplateDigest: "sha256:" + strings.Repeat("c", 64),
		ControlPrincipalDigest: "sha256:" + strings.Repeat("d", 64), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
}
func key(n int) string { return fmt.Sprintf("%032x", n) }
func storageRoot(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	p := storageRoot(t)
	s, err := Initialize(t.Context(), p, testBinding(), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, p
}

func TestStorageRestartBindingAndExclusiveOwner(t *testing.T) {
	s, p := newStore(t)
	if other, err := Open(p, testBinding()); err == nil {
		other.Close()
		t.Fatal("second owner admitted")
	}
	if s.Put(t.Context(), Output, key(1), []byte("result")) != nil || s.Put(t.Context(), State, key(2), []byte("Unknown")) != nil {
		t.Fatal("publication failed")
	}
	if s.Put(t.Context(), State, key(2), []byte("Unknown; cancellation intent")) != nil {
		t.Fatal("state replacement failed")
	}
	if s.Put(t.Context(), Output, key(1), []byte("replacement")) == nil || s.Put(t.Context(), State, key(3), []byte("second state")) == nil {
		t.Fatal("immutable history or single-state limit bypassed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Binding){func(b *Binding) { b.Namespace = key(8); b.StorageID = "control-execution-" + b.Namespace }, func(b *Binding) { b.TemplateDigest = b.ProfileDigest }, func(b *Binding) { b.ProfileDigest = b.TemplateDigest }, func(b *Binding) { b.ControlPrincipalDigest = b.TemplateDigest }, func(b *Binding) { b.Layout.OtherScopesUnallocatedBytes-- }} {
		b := testBinding()
		change(&b)
		if other, err := Open(p, b); err == nil {
			other.Close()
			t.Fatal("source drift admitted")
		}
	}
	reopened, err := Open(p, testBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Check() != nil || len(reopened.current.Entries) != 2 || reopened.current.Revision != 4 {
		t.Fatal("restart lost accounting")
	}
	if reopened.Put(t.Context(), Class("browser"), key(1), []byte("x")) == nil {
		t.Fatal("unallocated other scope consumed space")
	}
	if _, err := Initialize(t.Context(), p, testBinding(), func(context.Context) error { return nil }); err == nil {
		t.Fatal("populated namespace reinitialized")
	}
}

func TestStorageInitializationIsPermanentAndRequiresWholeEmptyRoot(t *testing.T) {
	for _, name := range []string{"old-ledger", "failed-physical-check", "missing-state"} {
		t.Run(name, func(t *testing.T) {
			p := storageRoot(t)
			if name == "old-ledger" {
				if err := os.WriteFile(filepath.Join(p, "coding-receipts.json"), []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			callback := func(context.Context) error { return errors.New("not empty") }
			if name == "missing-state" {
				callback = func(context.Context) error { return nil }
			}
			s, err := Initialize(t.Context(), p, testBinding(), callback)
			if name == "missing-state" {
				if err != nil {
					t.Fatal(err)
				}
				s.Close()
				if os.Remove(filepath.Join(p, manifestName)) != nil {
					t.Fatal("remove fixture")
				}
			} else if err == nil {
				s.Close()
				t.Fatal("unsafe initialization")
			}
			if _, err = Initialize(t.Context(), p, testBinding(), func(context.Context) error { return nil }); err == nil {
				t.Fatal("ceremony reset history")
			}
			if _, err = Open(p, testBinding()); err == nil {
				t.Fatal("missing state repaired")
			}
		})
	}
}

func TestStorageOutputExhaustionKeepsClosureAndState(t *testing.T) {
	s, p := newStore(t)
	data := bytes.Repeat([]byte("x"), 8<<20)
	for i := range 24 {
		if err := s.Put(t.Context(), Output, key(i), data); err != nil {
			t.Fatalf("output %d: %v", i, err)
		}
	}
	if err := s.Put(t.Context(), Output, key(24), []byte("one byte")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("exhausted output accepted: %v", err)
	}
	if s.Put(t.Context(), Closure, key(24), []byte("opaque durable close intent, not a no-effect receipt")) != nil || s.Put(t.Context(), State, key(25), []byte("retained Unknown")) != nil {
		t.Fatal("output consumed closure/state allowance")
	}
	s.Close()
	reopened, err := Open(p, testBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Put(t.Context(), Output, key(26), []byte("x")); !errors.Is(err, ErrCapacity) {
		t.Fatal("restart forgot capacity")
	}
}

func TestStorageRoundedChargesAndObjectCounts(t *testing.T) {
	s, _ := newStore(t)
	for i := range 64 {
		if err := s.Put(t.Context(), Closure, key(i), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put(t.Context(), Closure, key(65), []byte("x")); !errors.Is(err, ErrCapacity) {
		t.Fatal("small files bypassed record cap")
	}
	if s.Put(t.Context(), ExecutionEvidence, key(66), []byte("terminal document")) != nil {
		t.Fatal("class isolation failed")
	}
	for _, v := range []struct{ size, blocks, want int64 }{{1, 0, 64 << 10}, {1, 129, 128 << 10}, {65 << 10, 1, 128 << 10}, {0, 0, 0}} {
		st := unix.Stat_t{Size: v.size, Blocks: v.blocks}
		n, err := physicalCharge(&st)
		if err != nil || n != v.want {
			t.Fatalf("charge: %d %v", n, err)
		}
	}
	for _, st := range []unix.Stat_t{{Size: -1}, {Blocks: -1}, {Size: 1 << 62}, {Blocks: 1 << 62}} {
		if _, err := physicalCharge(&st); err == nil {
			t.Fatal("bad kernel facts allowed overflow")
		}
	}
}

func TestStorageStateReplacementAccountsBothCopies(t *testing.T) {
	s, _ := newStore(t)
	d := bytes.Repeat([]byte("s"), 32<<20)
	if s.Put(t.Context(), State, key(1), d) != nil || s.Put(t.Context(), State, key(1), d) != nil {
		t.Fatal("exact double-state peak rejected")
	}
	if err := s.Put(t.Context(), State, key(1), append(d, 'x')); err == nil {
		t.Fatal("single-state cap exceeded")
	}
	if s.Check() != nil {
		t.Fatal("rejected write changed state")
	}
}

func TestStorageRejectsAllUnexplainedOrUnsafeFiles(t *testing.T) {
	for _, name := range []string{"unknown", "directory", "symlink", "hardlink", "mode", "content", "manifest-duplicate", "pending", "lock-replacement"} {
		t.Run(name, func(t *testing.T) {
			s, p := newStore(t)
			if s.Put(t.Context(), Output, key(1), []byte("abc")) != nil {
				t.Fatal("fixture")
			}
			target := filepath.Join(p, string(Output)+"-"+key(1))
			var err error
			switch name {
			case "unknown":
				err = os.WriteFile(filepath.Join(p, "unknown"), []byte("x"), 0o600)
			case "directory":
				err = os.Mkdir(filepath.Join(p, "subdir"), 0o700)
			case "symlink":
				err = os.Symlink(target, filepath.Join(p, "alias"))
			case "hardlink":
				err = os.Link(target, filepath.Join(p, "alias"))
			case "mode":
				err = os.Chmod(target, 0o640)
			case "content":
				err = os.WriteFile(target, []byte("xyz"), 0o600)
			case "manifest-duplicate":
				b, e := os.ReadFile(filepath.Join(p, manifestName))
				if e != nil {
					t.Fatal(e)
				}
				b = append(b[:len(b)-1], []byte(`,"revision":2}`)...)
				err = os.WriteFile(filepath.Join(p, manifestName), b, 0o600)
			case "pending":
				err = os.WriteFile(filepath.Join(p, pendingName), []byte("x"), 0o600)
			case "lock-replacement":
				err = os.Rename(filepath.Join(p, lockName), filepath.Join(p, "held-lock"))
				if err == nil {
					err = os.WriteFile(filepath.Join(p, lockName), nil, 0o600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Check() == nil || s.Put(t.Context(), Closure, key(2), []byte("x")) == nil {
				t.Fatal("unexplained mutation allowed")
			}
			s.Close()
			if other, err := Open(p, testBinding()); err == nil {
				other.Close()
				t.Fatal("reopen ignored unsafe file")
			}
		})
	}
}

func TestStorageRootReplacementCannotRedirectWrites(t *testing.T) {
	s, p := newStore(t)
	moved := p + "-moved"
	if os.Rename(p, moved) != nil {
		t.Fatal("move")
	}
	t.Cleanup(func() { os.RemoveAll(moved) })
	if os.Mkdir(p, 0o700) != nil {
		t.Fatal("replace")
	}
	if s.Put(t.Context(), Closure, key(1), []byte("x")) == nil {
		t.Fatal("replaced root accepted")
	}
	names, err := os.ReadDir(p)
	if err != nil || len(names) != 0 {
		t.Fatal("write escaped pinned root")
	}
}

func TestStorageUncertainWritesPoisonOwnerAndPreserveResidue(t *testing.T) {
	for _, stage := range []string{"before-object", "after-object-sync", "after-object-rename", "after-manifest-sync", "after-manifest-rename"} {
		t.Run(stage, func(t *testing.T) {
			s, p := newStore(t)
			s.fault = func(at string) error {
				if at == stage {
					return errors.New("injected")
				}
				return nil
			}
			if err := s.Put(t.Context(), Closure, key(1), []byte("durable attempt")); !errors.Is(err, ErrUncertain) {
				t.Fatal("fault hidden")
			}
			if s.Check() == nil || s.Put(t.Context(), Closure, key(2), []byte("retry")) == nil {
				t.Fatal("uncertain owner still writes")
			}
			s.Close()
			other, err := Open(p, testBinding())
			// Before any effect or after a completely readable manifest rename,
			// reopening may verify consistent bytes. It still grants no permit.
			if stage == "before-object" || stage == "after-manifest-rename" {
				if err != nil {
					t.Fatal(err)
				}
				other.Close()
			} else if err == nil {
				other.Close()
				t.Fatal("incomplete state repaired")
			}
		})
	}
}

func TestStorageConcurrentImmutablePublication(t *testing.T) {
	s, _ := newStore(t)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { results <- s.Put(t.Context(), Closure, key(1), []byte("one closure")) })
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 || len(s.current.Entries) != 1 || s.Check() != nil {
		t.Fatal("publication not serialized")
	}
}

func TestStorageUnexpectedEntrantIsNeverOverwritten(t *testing.T) {
	s, p := newStore(t)
	target := filepath.Join(p, string(Closure)+"-"+key(1))
	s.fault = func(stage string) error {
		if stage == "after-object-sync" {
			return os.WriteFile(target, []byte("unexpected entrant"), 0o600)
		}
		return nil
	}
	if err := s.Put(t.Context(), Closure, key(1), []byte("candidate")); !errors.Is(err, ErrUncertain) {
		t.Fatal("entrant not held")
	}
	d, err := os.ReadFile(target)
	if err != nil || string(d) != "unexpected entrant" {
		t.Fatal("unexplained file overwritten")
	}
}

func TestStorageProcessLockAndCrash(t *testing.T) {
	s, p := newStore(t)
	run := func(mode string) int {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStorageChild$")
		cmd.Env = append(os.Environ(), "CONTROL_STORAGE_TEST_CHILD="+mode, "CONTROL_STORAGE_TEST_ROOT="+p)
		err := cmd.Run()
		if err == nil {
			return 0
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		t.Fatal(err)
		return -1
	}
	if run("locked") != 0 {
		t.Fatal("separate process acquired held owner")
	}
	s.Close()
	if run("crash") != 42 {
		t.Fatal("child did not reach crash point")
	}
	if other, err := Open(p, testBinding()); err == nil {
		other.Close()
		t.Fatal("process death reset incomplete write")
	}
	if _, err := os.Stat(filepath.Join(p, string(Closure)+"-"+key(1))); err != nil {
		t.Fatal("uncommitted evidence erased")
	}
}

func TestStorageChild(t *testing.T) {
	mode := os.Getenv("CONTROL_STORAGE_TEST_CHILD")
	if mode == "" {
		return
	}
	s, err := Open(os.Getenv("CONTROL_STORAGE_TEST_ROOT"), testBinding())
	if mode == "locked" {
		if err == nil {
			s.Close()
			os.Exit(2)
		}
		return
	}
	if err != nil {
		os.Exit(3)
	}
	s.fault = func(stage string) error {
		if stage == "after-object-rename" {
			os.Exit(42)
		}
		return nil
	}
	_ = s.Put(context.Background(), Closure, key(1), []byte("child crash evidence"))
	os.Exit(4)
}

func TestStorageManifestDoesNotAcceptCopiedRootOrNoncanonicalBinding(t *testing.T) {
	s, p := newStore(t)
	s.Close()
	b := testBinding()
	d, err := os.ReadFile(filepath.Join(p, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	other := storageRoot(t)
	for _, name := range []string{manifestName, lockName} {
		data, e := os.ReadFile(filepath.Join(p, name))
		if e != nil {
			t.Fatal(e)
		}
		if os.WriteFile(filepath.Join(other, name), data, 0o600) != nil {
			t.Fatal("copy fixture")
		}
	}
	if opened, err := Open(other, b); err == nil {
		opened.Close()
		t.Fatal("copied root inherited binding")
	}
	var doc map[string]any
	if json.Unmarshal(d, &doc) != nil {
		t.Fatal("manifest")
	}
	doc["extra"] = true
	d, _ = json.Marshal(doc)
	if os.WriteFile(filepath.Join(p, manifestName), d, 0o600) != nil {
		t.Fatal("tamper fixture")
	}
	if opened, err := Open(p, b); err == nil {
		opened.Close()
		t.Fatal("unknown manifest field accepted")
	}
}
