//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
	"golang.org/x/sys/unix"
)

func filesystemFixture(t *testing.T) *PreparedConfiguration {
	return filesystemFixtureContext(t, context.Background())
}

func filesystemFixtureContext(t *testing.T, ctx context.Context) *PreparedConfiguration {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range []string{"profile", "work", "evidence", "caller"} {
		if err := os.Mkdir(filepath.Join(root, leaf), 0700); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(filepath.Join("../..", qualificationprofile.ProfilePath))
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "profile", "profile.json")
	if err := os.WriteFile(profile, body, 0400); err != nil {
		t.Fatal(err)
	}
	config := locationFixture()
	config.ProfilePath = profile
	config.WorkingDirectory = filepath.Join(root, "work")
	config.EvidenceRoot = filepath.Join(root, "evidence")
	config.CallerStateRoot = filepath.Join(root, "caller", "state")
	prepared, err := PrepareConfiguration(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestLocationFilesCreatesPrivateStateAndRetainsIt(t *testing.T) {
	p := filesystemFixture(t)
	f, err := OpenLocationFiles(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	info, err := os.Stat(p.locations.CallerStateRoot)
	if err != nil || !admissibleDirectory(info, true) {
		t.Fatalf("private state: %v", err)
	}
	// This enumeration is test-only; production never enumerates caller state.
	entries, err := os.ReadDir(p.locations.CallerStateRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("initial state not empty: %v", err)
	}
	for _, held := range []*os.File{f.profile, f.profileParent.file, f.work.file, f.evidence.file, f.stateParent.file, f.state.file} {
		flags, err := unix.FcntlInt(held.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("descriptor not close-on-exec", err)
		}
		flags, err = unix.FcntlInt(held.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("descriptor not read-only", err)
		}
	}
	// Unreadable caller data and a FIFO must not prevent a metadata-only recheck.
	marker := filepath.Join(p.locations.CallerStateRoot, "private")
	if err := os.WriteFile(marker, []byte("caller-owned"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(p.locations.CallerStateRoot, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.Recheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.Recheck(context.Background()), ErrLocationFiles) {
		t.Fatal("closed preflight accepted")
	}
	if err := os.Chmod(marker, 0600); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(marker)
	if err != nil || string(body) != "caller-owned" {
		t.Fatal("caller data changed", err)
	}
}

func TestLocationFilesRejectsBeforeStateCreation(t *testing.T) {
	for _, kind := range []string{"profile-missing", "profile-symlink", "profile-parent-symlink", "profile-fifo", "profile-directory", "profile-hardlink", "profile-writable", "profile-empty", "profile-oversize", "profile-invalid", "work-symlink", "evidence-symlink", "state-parent-symlink", "work-writable", "evidence-missing", "state-parent-writable", "nil-context", "canceled-context", "unprepared"} {
		t.Run(kind, func(t *testing.T) {
			p := filesystemFixture(t)
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			moveAndSymlink := func(path string) { must(os.Rename(path, path+"-original")); must(os.Symlink(path+"-original", path)) }
			switch kind {
			case "profile-missing":
				must(os.Rename(p.locations.ProfilePath, p.locations.ProfilePath+"-original"))
			case "profile-symlink":
				moveAndSymlink(p.locations.ProfilePath)
			case "profile-parent-symlink":
				moveAndSymlink(filepath.Dir(p.locations.ProfilePath))
			case "profile-fifo", "profile-directory":
				must(os.Rename(p.locations.ProfilePath, p.locations.ProfilePath+"-original"))
				if kind == "profile-fifo" {
					must(unix.Mkfifo(p.locations.ProfilePath, 0600))
				} else {
					must(os.Mkdir(p.locations.ProfilePath, 0700))
				}
			case "profile-hardlink":
				must(os.Link(p.locations.ProfilePath, p.locations.ProfilePath+"-link"))
			case "profile-writable":
				must(os.Chmod(p.locations.ProfilePath, 0600))
			case "profile-empty", "profile-oversize", "profile-invalid":
				must(os.Chmod(p.locations.ProfilePath, 0600))
				if kind == "profile-empty" {
					must(os.Truncate(p.locations.ProfilePath, 0))
				}
				if kind == "profile-oversize" {
					must(os.Truncate(p.locations.ProfilePath, maxLocationProfileBytes+1))
				}
				if kind == "profile-invalid" {
					must(os.WriteFile(p.locations.ProfilePath, []byte(`{"secret":"must not appear in error"}`), 0600))
				}
				must(os.Chmod(p.locations.ProfilePath, 0400))
			case "work-symlink":
				moveAndSymlink(p.locations.WorkingDirectory)
			case "evidence-symlink":
				moveAndSymlink(p.locations.EvidenceRoot)
			case "state-parent-symlink":
				moveAndSymlink(filepath.Dir(p.locations.CallerStateRoot))
			case "work-writable":
				must(os.Chmod(p.locations.WorkingDirectory, 0770))
			case "evidence-missing":
				must(os.Rename(p.locations.EvidenceRoot, p.locations.EvidenceRoot+"-original"))
			case "state-parent-writable":
				must(os.Chmod(filepath.Dir(p.locations.CallerStateRoot), 0770))
			case "nil-context":
				ctx = nil
			case "canceled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			input := p
			if kind == "unprepared" {
				input = &PreparedConfiguration{}
			}
			got, err := OpenLocationFiles(ctx, input)
			if got != nil {
				_ = got.Close()
				t.Fatal("invalid input accepted")
			}
			if kind == "canceled-context" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if err != ErrLocationFiles {
				t.Fatalf("expected sanitized error, got %v", err)
			}
			if _, err := os.Lstat(p.locations.CallerStateRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("state created on failed preflight", err)
			}
		})
	}
}

func TestLocationFilesNeverReusesExistingState(t *testing.T) {
	for _, kind := range []string{"empty", "populated", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			p := filesystemFixture(t)
			state := p.locations.CallerStateRoot
			switch kind {
			case "empty", "populated":
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "populated" {
					if err := os.WriteFile(filepath.Join(state, "marker"), []byte("retain"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "file":
				if err := os.WriteFile(state, []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(p.locations.WorkingDirectory, state); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(state)
			if err != nil {
				t.Fatal(err)
			}
			f, err := OpenLocationFiles(context.Background(), p)
			if f != nil {
				_ = f.Close()
				t.Fatal("existing state accepted")
			}
			if err != ErrLocationFiles || errors.Is(err, ErrStateDirectoryRetained) {
				t.Fatal("existing state reported as created", err)
			}
			after, err := os.Lstat(state)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("existing state replaced", err)
			}
		})
	}
}

func TestLocationFilesRecheckRejectsReplacementAndMutation(t *testing.T) {
	for _, kind := range []string{"profile-content", "profile-replaced", "profile-hardlink", "profile-writable", "work-replaced", "evidence-replaced", "state-replaced", "state-symlink", "state-public", "state-parent-replaced"} {
		t.Run(kind, func(t *testing.T) {
			p := filesystemFixture(t)
			f, err := OpenLocationFiles(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			replaceDir := func(path string) { must(os.Rename(path, path+"-original")); must(os.Mkdir(path, 0700)) }
			switch kind {
			case "profile-content":
				info, err := os.Stat(p.locations.ProfilePath)
				must(err)
				body, err := os.ReadFile(p.locations.ProfilePath)
				must(err)
				body[0] = ' '
				must(os.Chmod(p.locations.ProfilePath, 0600))
				must(os.WriteFile(p.locations.ProfilePath, body, 0600))
				must(os.Chmod(p.locations.ProfilePath, 0400))
				must(os.Chtimes(p.locations.ProfilePath, info.ModTime(), info.ModTime()))
			case "profile-replaced":
				body, err := os.ReadFile(p.locations.ProfilePath)
				must(err)
				must(os.Rename(p.locations.ProfilePath, p.locations.ProfilePath+"-original"))
				must(os.WriteFile(p.locations.ProfilePath, body, 0400))
			case "profile-hardlink":
				must(os.Link(p.locations.ProfilePath, p.locations.ProfilePath+"-link"))
			case "profile-writable":
				must(os.Chmod(p.locations.ProfilePath, 0600))
			case "work-replaced":
				replaceDir(p.locations.WorkingDirectory)
			case "evidence-replaced":
				replaceDir(p.locations.EvidenceRoot)
			case "state-replaced":
				replaceDir(p.locations.CallerStateRoot)
			case "state-symlink":
				must(os.Rename(p.locations.CallerStateRoot, p.locations.CallerStateRoot+"-original"))
				must(os.Symlink(p.locations.CallerStateRoot+"-original", p.locations.CallerStateRoot))
			case "state-public":
				must(os.Chmod(p.locations.CallerStateRoot, 0755))
			case "state-parent-replaced":
				replaceDir(filepath.Dir(p.locations.CallerStateRoot))
				must(os.Mkdir(p.locations.CallerStateRoot, 0700))
			}
			if !errors.Is(f.Recheck(context.Background()), ErrLocationFiles) {
				t.Fatal("mutation accepted")
			}
		})
	}
}

// Deterministically deliver cancellation immediately after state creation.
// This test context observes metadata only and never changes production hooks.
type cancelOnStateContext struct {
	context.Context
	state  string
	cancel context.CancelFunc
}

func (c cancelOnStateContext) Err() error {
	if _, err := os.Lstat(c.state); err == nil {
		c.cancel()
	}
	return c.Context.Err()
}

func TestLocationFilesCancellationAfterMkdirRetainsState(t *testing.T) {
	p := filesystemFixture(t)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := cancelOnStateContext{base, p.locations.CallerStateRoot, cancel}
	f, err := OpenLocationFiles(ctx, p)
	if f != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, ErrStateDirectoryRetained) {
		t.Fatalf("missing retained-state cancellation: %v", err)
	}
	if _, err := os.Stat(p.locations.CallerStateRoot); err != nil {
		t.Fatal("created state removed", err)
	}
}

func TestLocationFilesCanceledRecheckDoesNotConsumeCustody(t *testing.T) {
	p := filesystemFixture(t)
	f, err := OpenLocationFiles(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(f.Recheck(ctx), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if f.Recheck(nil) != ErrLocationFiles {
		t.Fatal("nil context accepted")
	}
	if err := f.Recheck(context.Background()); err != nil {
		t.Fatal("custody lost", err)
	}
}
