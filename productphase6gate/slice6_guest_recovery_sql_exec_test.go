//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// This E-only path creates an individually inspectable Docker exec. A
// successful stream EOF or Docker CLI exit alone is not a psql exit receipt.
type slice6GuestOperatorExec struct {
	ID          string
	ContainerID string
	Output      []byte
	StartedUTC  string
	FinishedUTC string
	ExitReceipt []byte
}

// Whitelist only the inspected process identity, terminal state and local
// observation time. No Docker diagnostics, environment or SQL text escapes.
func slice6GuestOperatorExecExitReceipt(id, containerID, finishedUTC string) []byte {
	return []byte(id + "|" + containerID + "|false|0|" + finishedUTC + "\n")
}

func slice6CheckGuestOperatorExecExitReceipt(exec slice6GuestOperatorExec) error {
	if len(exec.ID) != 64 || !lowerHexSlice6(exec.ID) ||
		len(exec.ContainerID) != 64 || !lowerHexSlice6(exec.ContainerID) ||
		len(exec.ExitReceipt) < 140 || len(exec.ExitReceipt) > 256 ||
		!bytes.Equal(exec.ExitReceipt,
			slice6GuestOperatorExecExitReceipt(exec.ID, exec.ContainerID, exec.FinishedUTC)) {
		return errors.New("Guest operator SQL exit receipt identity drift")
	}
	started, startErr := time.Parse(time.RFC3339Nano, exec.StartedUTC)
	finished, finishErr := time.Parse(time.RFC3339Nano, exec.FinishedUTC)
	if startErr != nil || finishErr != nil || !finished.After(started) ||
		strings.ContainsAny(exec.FinishedUTC, "|\n\r") {
		return errors.New("Guest operator SQL exit receipt time drift")
	}
	return nil
}

func slice6RunGuestOperatorSQL(ctx context.Context, containerID, applicationName string,
	query []byte, command []string, outputLimit int) (slice6GuestOperatorExec, error) {
	if ctx == nil || ctx.Err() != nil || len(containerID) != 64 || !lowerHexSlice6(containerID) ||
		len(applicationName) < 1 || len(applicationName) > 63 || len(query) == 0 ||
		len(query) > 2048 || len(command) < 2 || command[0] != "psql" ||
		outputLimit < 1 || outputLimit > 4096 {
		return slice6GuestOperatorExec{}, errors.New("Guest operator SQL exec input invalid")
	}
	engine, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return slice6GuestOperatorExec{}, errors.New("Guest operator Docker engine unavailable")
	}
	defer engine.Close()
	created, err := engine.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		User: "70:70", AttachStdin: true, AttachStdout: true, AttachStderr: true,
		Env: []string{"PGAPPNAME=" + applicationName}, Cmd: command,
	})
	if err != nil || len(created.ID) != 64 || !lowerHexSlice6(created.ID) {
		return slice6GuestOperatorExec{}, errors.New("Guest operator SQL exec creation unavailable")
	}
	observedExec := slice6GuestOperatorExec{ID: created.ID, ContainerID: containerID}
	started := time.Now().UTC()
	attached, err := engine.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return observedExec, errors.New("Guest operator SQL exec attach unavailable")
	}
	defer attached.Close()
	stopClose := context.AfterFunc(ctx, attached.Close)
	defer stopClose()
	if written, err := io.Copy(attached.Conn, bytes.NewReader(query)); err != nil || written != int64(len(query)) {
		return observedExec, errors.New("Guest operator SQL stdin unavailable")
	}
	if err := attached.CloseWrite(); err != nil {
		return observedExec, errors.New("Guest operator SQL stdin close unavailable")
	}
	stdout := &slice6BoundedOutput{limit: outputLimit}
	stderr := &slice6BoundedOutput{limit: 64}
	_, copyErr := stdcopy.StdCopy(stdout, stderr, attached.Reader)
	stdout.mu.Lock()
	output := bytes.Clone(stdout.buffer.Bytes())
	clear(stdout.buffer.Bytes())
	stdoutOverflow := stdout.overflow
	stdout.mu.Unlock()
	stderr.mu.Lock()
	stderrLen, stderrOverflow := stderr.buffer.Len(), stderr.overflow
	clear(stderr.buffer.Bytes())
	stderr.mu.Unlock()
	if copyErr != nil || stdoutOverflow || stderrOverflow || stderrLen != 0 || ctx.Err() != nil {
		clear(output)
		return observedExec, errors.New("Guest operator SQL stream or exit uncertain")
	}
	for ctx.Err() == nil {
		observed, err := engine.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
		if err != nil || observed.ID != created.ID || observed.ContainerID != containerID {
			clear(output)
			return observedExec, errors.New("Guest operator SQL exec identity drift")
		}
		if !observed.Running {
			if observed.ExitCode != 0 {
				clear(output)
				return observedExec, errors.New("Guest operator SQL exec failed")
			}
			finishedUTC := time.Now().UTC().Format(time.RFC3339Nano)
			return slice6GuestOperatorExec{ID: created.ID, ContainerID: containerID,
				Output: output, StartedUTC: started.Format(time.RFC3339Nano),
				FinishedUTC: finishedUTC,
				ExitReceipt: slice6GuestOperatorExecExitReceipt(observed.ID, observed.ContainerID, finishedUTC)}, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	clear(output)
	return observedExec, errors.New("Guest operator SQL exec exit timed out")
}
