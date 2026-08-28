package docker

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

// OpenOutput returns only a regular file confined beneath the stable private
// output mount after rechecking exact Provider ownership, running state, and
// sandbox generation. It never returns a backend identifier or host path.
func (d *Driver) OpenOutput(ctx context.Context, sandboxID string, expectedGeneration int64, sourcePath string) (artifact.Output, error) {
	if err := contextError(ctx); err != nil {
		return artifact.Output{}, err
	}
	if d == nil || d.engine == nil || expectedGeneration < 1 {
		return artifact.Output{}, ErrInvalidDriver
	}
	if sourcePath != "/outputs" && !strings.HasPrefix(sourcePath, "/outputs/") {
		return artifact.Output{}, artifact.ErrInvalidRequest
	}
	relative := strings.TrimPrefix(sourcePath, "/outputs/")
	if sourcePath == "/outputs" {
		relative = "."
	}
	if path.Clean(relative) != relative || strings.HasPrefix(relative, "/") {
		return artifact.Output{}, artifact.ErrInvalidRequest
	}

	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	container, found, err := d.inspectOwnedID(operationCtx, sandboxID)
	if err != nil {
		return artifact.Output{}, err
	}
	if !found || !container.running || container.status != "running" || container.paused || container.restarting || container.dead {
		return artifact.Output{}, artifact.ErrSourceMissing
	}
	generation, err := strconv.ParseInt(container.labels[generationLabel], 10, 64)
	if err != nil || generation != expectedGeneration {
		return artifact.Output{}, artifact.ErrGenerationConflict
	}
	paths, err := d.mountPaths(sandboxID)
	if err != nil {
		return artifact.Output{}, err
	}
	root, err := os.OpenRoot(paths.outputs)
	if err != nil {
		return artifact.Output{}, artifact.ErrSourceMissing
	}
	defer root.Close()
	if err := rejectOutputLinks(root, relative); err != nil {
		return artifact.Output{}, artifact.ErrSourceMissing
	}
	file, err := root.Open(relative)
	if errors.Is(err, os.ErrNotExist) {
		return artifact.Output{}, artifact.ErrSourceMissing
	}
	if err != nil {
		return artifact.Output{}, artifact.ErrSourceMissing
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
		_ = file.Close()
		return artifact.Output{}, artifact.ErrSourceMissing
	}
	if err := contextError(operationCtx); err != nil {
		_ = file.Close()
		return artifact.Output{}, err
	}
	return artifact.Output{Content: file, SizeBytes: info.Size()}, nil
}

func rejectOutputLinks(root *os.Root, relative string) error {
	current := ""
	for _, component := range strings.Split(relative, "/") {
		if component == "" || component == "." || component == ".." {
			return artifact.ErrSourceMissing
		}
		if current == "" {
			current = component
		} else {
			current += "/" + component
		}
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return artifact.ErrSourceMissing
		}
	}
	return nil
}

var _ artifact.OutputReader = (*Driver)(nil)
