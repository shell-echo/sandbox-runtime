//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func launchFixture(t *testing.T) (*FrozenPreflight, *PhaseAdmission) {
	t.Helper()
	c := freezeFixture(t)
	a, err := c.AdmitPhase(context.Background(), "initial")
	if err != nil {
		t.Fatal(err)
	}
	return c, a
}

func TestLaunchPreparationTopologyNoInputAndClose(t *testing.T) {
	t.Setenv("SANDBOX_TEST_SECRET", "must-not-be-inherited")
	c, a := launchFixture(t)
	l, err := PrepareLaunch(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.core.path != c.core.executable.path || l.core.directory != a.Locations().WorkingDirectory ||
		len(l.core.argv) != 1 || l.core.argv[0] != "qualification-adapter" || l.core.environment == nil || len(l.core.environment) != 0 {
		t.Fatal("launch parameters not fixed/frozen")
	}
	seen := map[int]bool{}
	for i := range l.core.child {
		childRead := i == 0 || i >= 3
		for j, file := range []*os.File{l.core.child[i], l.core.parent[i]} {
			fd := int(file.Fd())
			if seen[fd] {
				t.Fatal("aliased endpoint")
			}
			seen[fd] = true
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatal("endpoint not close-on-exec", err)
			}
			read := childRead
			if j == 1 {
				read = !read
			}
			want := unix.O_WRONLY
			if read {
				want = unix.O_RDONLY
			}
			flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil || flags&unix.O_ACCMODE != want {
				t.Fatal("wrong pipe direction", err)
			}
			if read {
				if err := unix.SetNonblock(fd, true); err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				n, err := unix.Read(fd, b[:])
				if n > 0 || !errors.Is(err, unix.EAGAIN) {
					t.Fatal("pipe has bytes or premature EOF", err)
				}
				if err := unix.SetNonblock(fd, false); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if len(seen) != 22 {
		t.Fatal("wrong endpoint inventory")
	}
	if err := l.Recheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	copyLaunch := *l
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !copyLaunch.core.closed || l.Close() != nil || l.Recheck(context.Background()) != ErrLaunch {
		t.Fatal("shared close did not revoke topology")
	}
	for fd := range seen {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatal("endpoint leaked", err)
		}
	}
}

func TestLaunchRejectsUnsafeWorkingDirectoryAndAdmission(t *testing.T) {
	for _, kind := range []string{"nonempty", "symlink", "public", "duplicate", "copied-admission", "nil-context", "canceled", "closed", "failed-machine"} {
		t.Run(kind, func(t *testing.T) {
			c, a := launchFixture(t)
			ctx := context.Background()
			work := a.Locations().WorkingDirectory
			switch kind {
			case "nonempty":
				if err := os.WriteFile(filepath.Join(work, "marker"), []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(work, work+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(work+"-original", work); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(work, 0755); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				l, err := PrepareLaunch(ctx, a)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
			case "copied-admission":
				copy := *a
				a = &copy
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				_ = c.Close()
			case "failed-machine":
				_ = a.Machine().AuthorizeInvocationInput()
			}
			l, err := PrepareLaunch(ctx, a)
			if l != nil {
				_ = l.Close()
				t.Fatal("unsafe launch prepared")
			}
			if kind == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if err != ErrLaunch {
				t.Fatal("unsanitized failure", err)
			}
			if kind == "nonempty" {
				body, err := os.ReadFile(filepath.Join(work, "marker"))
				if err != nil || string(body) != "retain" {
					t.Fatal("work data changed", err)
				}
			}
		})
	}
}

func TestLaunchPipeAllocationFailureClosesEveryEndpoint(t *testing.T) {
	for failAt := 0; failAt < 11; failAt++ {
		c, a := launchFixture(t)
		var allocated []*os.File
		calls := 0
		factory := func() (*os.File, *os.File, error) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			allocated = append(allocated, r, w)
			index := calls
			calls++
			if index == failAt {
				return r, w, errors.New("private diagnostic must be sanitized")
			}
			return r, w, nil
		}
		l, err := prepareLaunch(context.Background(), a, factory)
		if l != nil || err != ErrLaunch || calls != failAt+1 {
			t.Fatal("allocation failure not closed", err)
		}
		for _, file := range allocated {
			if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("partial allocation leaked", err)
			}
		}
		if _, err := PrepareLaunch(context.Background(), a); err == nil {
			t.Fatal("failed preparation retried")
		}
		_ = c.Close()
	}
}

func TestLaunchCancellationDuringAllocationAndDirtyRecheck(t *testing.T) {
	c, a := launchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var r, w *os.File
	_, err := prepareLaunch(ctx, a, func() (*os.File, *os.File, error) {
		var err error
		r, w, err = os.Pipe()
		cancel()
		return r, w, err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, file := range []*os.File{r, w} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("canceled allocation leaked", err)
		}
	}
	_ = c.Close()
	c, a = launchFixture(t)
	l, err := PrepareLaunch(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	marker := filepath.Join(a.Locations().WorkingDirectory, "changed")
	if err := os.WriteFile(marker, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if l.Recheck(context.Background()) != ErrLaunch {
		t.Fatal("dirty work directory accepted")
	}
	if a.Recheck(context.Background()) == nil {
		t.Fatal("failed launch left live admission")
	}
}
