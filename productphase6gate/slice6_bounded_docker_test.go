//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
)

var errSlice6OutputLimit = errors.New("bounded Docker output limit exceeded")

type slice6BoundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *slice6BoundedOutput) Write(value []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.overflow || output.buffer.Len()+len(value) > output.limit {
		output.overflow = true
		return 0, errSlice6OutputLimit
	}
	return output.buffer.Write(value)
}

// The diagnostic never holds or prints unbounded Docker/CLI output. Both
// streams share one synchronized cap; callers must clear the returned bytes.
func slice6DockerBounded(ctx context.Context, limit int, stdin []byte, arguments ...string) ([]byte, error, bool) {
	if ctx == nil || limit < 1 || limit > 64<<10 || len(arguments) == 0 {
		return nil, errors.New("bounded Docker diagnostic input invalid"), false
	}
	return slice6CaptureBounded(exec.CommandContext(ctx, "docker", arguments...), limit, stdin)
}

func slice6CaptureBounded(command *exec.Cmd, limit int, stdin []byte) ([]byte, error, bool) {
	if command == nil || limit < 1 || limit > 64<<10 {
		return nil, errors.New("bounded diagnostic command is invalid"), false
	}
	output := &slice6BoundedOutput{limit: limit}
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	output.mu.Lock()
	document := bytes.Clone(output.buffer.Bytes())
	clear(output.buffer.Bytes())
	overflow := output.overflow
	output.mu.Unlock()
	if overflow {
		return document, errSlice6OutputLimit, true
	}
	return document, err, false
}
