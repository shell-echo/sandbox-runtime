package logger

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGlobalAPI drives the package-level facade (Init, the level wrappers, With
// and Sync) through a real file sink and asserts every call reaches the file.
// It also re-initialises to exercise Init's old-logger swap-and-sync path.
func TestGlobalAPI(t *testing.T) {
	silenceStderr(t)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	if err := Init(Options{Level: DebugLevel, File: File{Name: logPath, MaxSize: 1}}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	Debug("gd")
	Info("gi")
	Warn("gw")
	Error("ge")
	Debugf("gdf %d", 1)
	Infof("gif %d", 2)
	Warnf("gwf %d", 3)
	Errorf("gef %d", 4)
	With(String("rid", "abc")).Info("gwith")

	if err := Sync(); err != nil {
		t.Errorf("Sync: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`"msg":"gd"`, `"msg":"gi"`, `"msg":"gw"`, `"msg":"ge"`,
		`"gdf 1"`, `"gif 2"`, `"gwf 3"`, `"gef 4"`, `"rid":"abc"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("global log missing %q\n%s", want, out)
		}
	}

	// Re-init to cover Init's "old logger != nil -> sync it" branch.
	if err := Init(Options{Level: InfoLevel, File: File{Name: logPath, MaxSize: 1}}); err != nil {
		t.Fatalf("re-Init: %v", err)
	}
}

// TestGlobalNilLoggerFallsBackToNop verifies that before Init (or if the global
// logger is nil) Get returns a NopLogger and every wrapper is a safe no-op.
func TestGlobalNilLoggerFallsBackToNop(t *testing.T) {
	silenceStderr(t)

	// Force the uninitialised state and restore it afterwards.
	mu.Lock()
	prev := logger
	logger = nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		logger = prev
		mu.Unlock()
	})

	if Get() == nil {
		t.Error("Get returned nil, want a NopLogger")
	}
	if err := Sync(); err != nil {
		t.Errorf("Sync with nil logger should be nil, got %v", err)
	}

	Debug("x")
	Info("x")
	Warn("x")
	Error("x")
	Debugf("x %d", 1)
	Infof("x %d", 1)
	Warnf("x %d", 1)
	Errorf("x %d", 1)
	_ = With(String("k", "v"))
}

// TestFatalBehaviour re-executes the test binary in a child process so the
// os.Exit(1) performed by the global Fatal/Fatalf can be observed: the child
// must exit with code 1 after emitting a FATAL-level record containing the
// message. Coverage of the exit path is not counted (separate process), but the
// behaviour is verified end to end.
func TestFatalBehaviour(t *testing.T) {
	switch os.Getenv("LOGGER_FATAL_MODE") {
	case "fatal":
		_ = Init(Options{Level: InfoLevel})
		Fatal("fatal-msg", String("k", "v"))
		return
	case "fatalf":
		_ = Init(Options{Level: InfoLevel})
		Fatalf("fatalf-%d", 7)
		return
	}

	cases := []struct {
		mode string
		want string
	}{
		{"fatal", "fatal-msg"},
		{"fatalf", "fatalf-7"},
	}

	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestFatalBehaviour", "-test.v")
			cmd.Env = append(os.Environ(), "LOGGER_FATAL_MODE="+tc.mode)
			out, err := cmd.CombinedOutput()

			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("expected process to exit non-zero, got err=%v\noutput:\n%s", err, out)
			}
			if ee.ExitCode() != 1 {
				t.Errorf("exit code = %d, want 1", ee.ExitCode())
			}
			if !strings.Contains(string(out), tc.want) {
				t.Errorf("output missing %q\n%s", tc.want, out)
			}
			if !strings.Contains(string(out), "FATAL") {
				t.Errorf("output missing FATAL level\n%s", out)
			}
		})
	}
}
