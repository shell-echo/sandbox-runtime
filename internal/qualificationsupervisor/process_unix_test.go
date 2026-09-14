//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func buildSpawnProbe(t *testing.T, mode string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "probe")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-ldflags=-X main.mode="+mode, "-o", path, "./testdata/spawnprobe")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build local probe: %v\n%s", err, output)
	}
	// Do not inherit a platform/user-specific umask into the executable
	// admission fixture. Production intentionally rejects group-writable files.
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func preparedProbe(t *testing.T, path string) (*FrozenPreflight, *PreparedLaunch) {
	return preparedProbeContext(t, path, context.Background())
}

func preparedProbeContext(t *testing.T, path string, runContext context.Context) (*FrozenPreflight, *PreparedLaunch) {
	t.Helper()
	p := filesystemFixtureContext(t, runContext)
	files, err := OpenLocationFiles(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	e, err := OpenExecutable(context.Background(), p, path, "sha256:"+hex.EncodeToString(sum[:]), MaxExecutableBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	frozen, err := FinalizePreflight(context.Background(), p, files, e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frozen.Close() })
	a, err := frozen.AdmitPhase(context.Background(), "initial")
	if err != nil {
		t.Fatal(err)
	}
	launch, err := PrepareLaunch(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return frozen, launch
}

type spawnProbeReport struct {
	Args, Env                                    []string
	Cwd                                          string
	Entries                                      int
	NewGroup, Directions, NoInput, WitnessClosed bool
}

func readSpawnProbe(t *testing.T, p *StartedProcess) spawnProbeReport {
	t.Helper()
	var report spawnProbeReport
	if err := json.NewDecoder(io.LimitReader(processOutput{p.core.parent[1]}, 4096)).Decode(&report); err != nil {
		t.Fatal("probe output", err)
	}
	return report
}

func TestProcessRealHandoffAndConcurrentCleanup(t *testing.T) {
	path := buildSpawnProbe(t, "hang")
	t.Setenv("SANDBOX_PROCESS_TEST_SECRET", "must-not-inherit")
	frozen, launch := preparedProbe(t, path)
	work := launch.core.directory
	childEnds := launch.core.child
	// A parent-only descriptor at a fixed high number must not cross exec.
	witness, err := unix.FcntlInt(frozen.core.files.profile.Fd(), unix.F_DUPFD_CLOEXEC, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(witness)
	if witness != 64 {
		t.Fatal("test witness fd unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := StartProcess(ctx, launch)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := StartProcess(ctx, launch); err != ErrProcessStart {
		t.Fatal("launch reused", err)
	}
	if err := launch.Close(); err != nil {
		t.Fatal("transferred launch close", err)
	}
	for _, file := range childEnds {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("child endpoint retained", err)
		}
	}
	report := readSpawnProbe(t, p)
	if len(report.Args) != 1 || report.Args[0] != launchArgv0 || len(report.Env) != 0 || report.Cwd != work || report.Entries != 0 ||
		!report.NewGroup || !report.Directions || !report.NoInput || !report.WitnessClosed {
		t.Fatalf("unexpected local probe: %+v", report)
	}
	copyProcess := *p
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for _, close := range []func() error{p.Close, copyProcess.Close, frozen.Close} {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- close() }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("cleanup", err)
		}
	}
	if !p.core.isStopping() || p.core.cleanlyReaped() {
		t.Fatal("forced cleanup reported clean exit")
	}
	if count, err, done := p.core.stderrResult(); !done || err != nil || count != int64(len("probe-stderr\n")) {
		t.Fatal("stderr was not privately bounded and drained", count, err, done)
	}
	for _, file := range p.core.parent {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("parent endpoint leaked", err)
		}
	}
	if err := unix.Kill(p.core.pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatal("child not reaped", err)
	}
}

func TestProcessContextCancellationAndNormalExit(t *testing.T) {
	for _, mode := range []string{"hang", "exit"} {
		t.Run(mode, func(t *testing.T) {
			path := buildSpawnProbe(t, mode)
			runContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			frozen, launch := preparedProbeContext(t, path, runContext)
			p, err := StartProcess(context.Background(), launch)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			_ = readSpawnProbe(t, p)
			if mode == "hang" {
				cancel()
				select {
				case <-p.core.done:
				case <-time.After(7 * time.Second):
					t.Fatal("cancellation did not reclaim child")
				}
				if p.Close() != nil || p.core.cleanlyReaped() {
					t.Fatal("canceled process result")
				}
				if _, err := frozen.AdmitPhase(context.Background(), "reconstruction"); err == nil {
					t.Fatal("canceled child allowed reconstruction")
				}
			} else {
				if _, err := io.Copy(io.Discard, processOutput{p.core.parent[1]}); err != nil {
					t.Fatal(err)
				}
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
				if p.core.cleanlyReaped() {
					t.Fatal("exit without protocol completion was accepted")
				}
			}
		})
	}
}

func TestProcessPreStartFailuresCloseTopology(t *testing.T) {
	for _, kind := range []string{"invalid-executable", "nil-context", "canceled", "dirty-cwd"} {
		t.Run(kind, func(t *testing.T) {
			// Valid preflight digest but deliberately not a loadable executable.
			_, path, _ := executableFixture(t)
			frozen, launch := preparedProbe(t, path)
			childEnds, parentEnds := launch.core.child, launch.core.parent
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			switch kind {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "dirty-cwd":
				if err := os.WriteFile(filepath.Join(launch.core.directory, "marker"), []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			p, err := StartProcess(ctx, launch)
			if p != nil || err == nil {
				t.Fatal("invalid start accepted")
			}
			if kind == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if err != ErrProcessStart {
				t.Fatal("unsanitized start error", err)
			}
			for i := range childEnds {
				for _, file := range []*os.File{childEnds[i], parentEnds[i]} {
					if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
						t.Fatal("failed start leaked endpoint", err)
					}
				}
			}
			if frozen.core.process != nil {
				t.Fatal("failed start left a process owner")
			}
		})
	}
}

// Deliver cancellation at the first post-spawn context check, without changing
// production hooks or guessing a timing window.
type cancelAfterSpawnContext struct {
	context.Context
	owner  *frozenCore
	cancel context.CancelFunc
}

func (c cancelAfterSpawnContext) Err() error {
	if c.owner.process != nil {
		c.cancel()
	}
	return c.Context.Err()
}

func TestProcessPostSpawnCancellationKeepsRecoveryOwner(t *testing.T) {
	path := buildSpawnProbe(t, "hang")
	frozen, launch := preparedProbe(t, path)
	base, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx := cancelAfterSpawnContext{base, frozen.core, cancel}
	p, err := StartProcess(ctx, launch)
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("post-spawn cancellation not reported", err)
	}
	owned := frozen.core.process
	if owned == nil {
		t.Fatal("lost recovery owner")
	}
	select {
	case <-owned.done:
	default:
		t.Fatal("post-spawn child not reclaimed")
	}
	if owned.cleanupErr != nil {
		t.Fatal(owned.cleanupErr)
	}
	for _, file := range owned.parent {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("post-spawn endpoint leaked", err)
		}
	}
	if err := frozen.Close(); err != nil {
		t.Fatal(err)
	}
	if err := frozen.Close(); err != nil {
		t.Fatal(err)
	}
}
