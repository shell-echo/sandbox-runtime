// Package staging provides a private file stager and injected content-check
// adapters. It does not publish artifacts or expose its storage paths.
package staging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

// CommandChecker invokes an operator-supplied argv directly and streams the
// bounded content through stdin. Exit 0 passes, exit 1 rejects, and every other
// failure remains unavailable rather than becoming false rejection evidence.
type CommandChecker struct {
	executable string
	arguments  []string
}

func NewCommandChecker(argv []string) (*CommandChecker, error) {
	if len(argv) == 0 {
		return nil, artifact.ErrUnsupportedChecks
	}
	executable, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, errors.Join(artifact.ErrUnsupportedChecks, err)
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, artifact.ErrUnsupportedChecks
	}
	return &CommandChecker{executable: executable, arguments: append([]string(nil), argv[1:]...)}, nil
}

func (c *CommandChecker) CheckContent(ctx context.Context, _ artifact.Request, content []byte) (artifact.CheckStatus, error) {
	if ctx == nil {
		return artifact.CheckNotRun, context.Canceled
	}
	if c == nil || c.executable == "" {
		return artifact.CheckNotRun, artifact.ErrUnsupportedChecks
	}
	command := exec.CommandContext(ctx, c.executable, c.arguments...)
	command.Stdin = bytes.NewReader(content)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Env = []string{}
	err := command.Run()
	if err == nil {
		return artifact.CheckPassed, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return artifact.CheckNotRun, ctxErr
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return artifact.CheckFailed, nil
	}
	return artifact.CheckNotRun, err
}

func (c *CommandChecker) CheckSupport(ctx context.Context, _ artifact.Request) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || c.executable == "" {
		return artifact.ErrUnsupportedChecks
	}
	info, err := os.Stat(c.executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return artifact.ErrUnsupportedChecks
	}
	return nil
}

var _ artifact.ContentChecker = (*CommandChecker)(nil)
var _ artifact.SupportChecker = (*CommandChecker)(nil)
