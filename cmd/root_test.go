package cmd

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestExecuteHelpSuccess drives the success path of Execute: with no arguments
// the root command is not runnable, so cobra prints help (without running
// PersistentPreRunE) and Execute returns normally. The help text must name the
// command, and no log file should be created.
func TestExecuteHelpSuccess(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{})

	Execute()

	if !strings.Contains(out.String(), "sandbox-runtime") {
		t.Errorf("help output missing command name:\n%s", out.String())
	}
}

// TestConfigFlagRegistered confirms the persistent --config flag is wired up by
// the package init.
func TestConfigFlagRegistered(t *testing.T) {
	if rootCmd.PersistentFlags().Lookup("config") == nil {
		t.Error("--config persistent flag not registered")
	}
}

// TestExecuteErrorExits runs the binary in a child process with an unknown flag
// so the error path in Execute (print to stderr, os.Exit(1)) can be observed
// without terminating the test run. The child must exit with code 1.
func TestExecuteErrorExits(t *testing.T) {
	if os.Getenv("CMD_EXEC_ERR") == "1" {
		os.Args = []string{"sandbox-runtime", "--definitely-not-a-flag"}
		Execute()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestExecuteErrorExits")
	cmd.Env = append(os.Environ(), "CMD_EXEC_ERR=1")
	out, err := cmd.CombinedOutput()

	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected non-zero exit, got %v\n%s", err, out)
	}
	if ee.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", ee.ExitCode())
	}
}
