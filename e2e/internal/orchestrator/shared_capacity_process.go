package orchestrator

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
)

const maxSharedCapacityRecordBytes = 64 << 10

type sharedCallerProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *json.Decoder
	log     *os.File
	done    chan struct{}

	requestMu sync.Mutex
	stateMu   sync.Mutex
	sequence  uint64
	err       error
}

func startSharedCaller(binary, configPath, logPath string) (*sharedCallerProcess, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	command := exec.Command(binary, "-config", configPath)
	input, err := command.StdinPipe()
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		_ = logFile.Close()
		return nil, err
	}
	command.Stderr = logFile
	process := &sharedCallerProcess{
		command: command, input: input, output: json.NewDecoder(io.LimitReader(output, 16<<20)),
		log: logFile, done: make(chan struct{}),
	}
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = logFile.Close()
		return nil, err
	}
	go func() {
		err := command.Wait()
		process.stateMu.Lock()
		process.err = err
		process.stateMu.Unlock()
		_ = logFile.Close()
		close(process.done)
	}()
	return process, nil
}

func (p *sharedCallerProcess) request(ctx context.Context, command wire.Command) (wire.Response, error) {
	if p == nil || p.command == nil || p.input == nil || p.output == nil {
		return wire.Response{}, errors.New("shared-capacity caller is unavailable")
	}
	if ctx == nil {
		return wire.Response{}, context.Canceled
	}
	p.requestMu.Lock()
	defer p.requestMu.Unlock()
	select {
	case <-p.done:
		return wire.Response{}, errors.New("shared-capacity caller exited")
	default:
	}
	p.sequence++
	command.Version = wire.ProtocolVersion
	command.Sequence = p.sequence
	encoded, err := json.Marshal(command)
	if err != nil {
		return wire.Response{}, err
	}
	if len(encoded) > maxSharedCapacityRecordBytes {
		return wire.Response{}, errors.New("shared-capacity command exceeds its bound")
	}
	encoded = append(encoded, '\n')

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := p.input.Write(encoded)
		writeDone <- writeErr
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			p.terminate()
			return wire.Response{}, errors.New("write shared-capacity caller command")
		}
	case <-ctx.Done():
		p.terminate()
		return wire.Response{}, ctx.Err()
	case <-p.done:
		return wire.Response{}, errors.New("shared-capacity caller exited")
	}

	responseDone := make(chan struct {
		response wire.Response
		err      error
	}, 1)
	go func() {
		var response wire.Response
		err := p.output.Decode(&response)
		responseDone <- struct {
			response wire.Response
			err      error
		}{response: response, err: err}
	}()
	select {
	case result := <-responseDone:
		if result.err != nil {
			p.terminate()
			return wire.Response{}, errors.New("read shared-capacity caller response")
		}
		if result.response.Version != wire.ProtocolVersion || result.response.Sequence != command.Sequence {
			p.terminate()
			return wire.Response{}, errors.New("shared-capacity caller response correlation failed")
		}
		return result.response, nil
	case <-ctx.Done():
		p.terminate()
		return wire.Response{}, ctx.Err()
	case <-p.done:
		return wire.Response{}, errors.New("shared-capacity caller exited")
	}
}

func (p *sharedCallerProcess) shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return p.result()
	default:
	}
	response, requestErr := p.request(ctx, wire.Command{Action: wire.ActionShutdown})
	if requestErr == nil && (!response.OK || response.Outcome != wire.OutcomeTerminated) {
		requestErr = errors.New("shared-capacity caller rejected shutdown")
	}
	_ = p.input.Close()
	select {
	case <-p.done:
		return errors.Join(requestErr, p.result())
	case <-ctx.Done():
		killErr := p.command.Process.Kill()
		select {
		case <-p.done:
			return errors.Join(requestErr, ctx.Err(), killErr, p.result())
		case <-time.After(2 * time.Second):
			return errors.Join(requestErr, ctx.Err(), killErr, errors.New("shared-capacity caller did not exit after kill"))
		}
	}
}

func (p *sharedCallerProcess) result() error {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.err
}

// A timed-out pipe request cannot be resynchronized safely because its pending
// decoder may consume a later response. Terminate the fixture process so every
// subsequent operation fails closed instead of reusing an ambiguous stream.
func (p *sharedCallerProcess) terminate() {
	if p == nil || p.command == nil || p.command.Process == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
		_ = p.command.Process.Kill()
	}
}

func signalSharedGateway(child *childProcess, signal syscall.Signal) error {
	if child == nil || child.command == nil || child.command.Process == nil {
		return errors.New("shared-capacity Gateway process is unavailable")
	}
	select {
	case <-child.done:
		return errors.New("shared-capacity Gateway already exited")
	default:
	}
	return child.command.Process.Signal(signal)
}

func waitForSharedGatewayStopped(ctx context.Context, child *childProcess, timeout time.Duration) error {
	if child == nil || child.command == nil || child.command.Process == nil || ctx == nil {
		return errors.New("shared-capacity Gateway process is unavailable")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-child.done:
			return errors.New("shared-capacity Gateway exited while awaiting stopped state")
		default:
		}
		probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		output, err := exec.CommandContext(probeCtx, "ps", "-o", "stat=", "-p", fmt.Sprint(child.command.Process.Pid)).Output()
		cancel()
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(output)), "T") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("shared-capacity Gateway did not enter stopped state")
		case <-ticker.C:
		}
	}
}

func killSharedGateway(child *childProcess) error {
	if child == nil || child.command == nil || child.command.Process == nil {
		return errors.New("shared-capacity Gateway process is unavailable")
	}
	select {
	case <-child.done:
		return errors.New("shared-capacity Gateway already exited")
	default:
	}
	if err := child.command.Process.Kill(); err != nil {
		return err
	}
	select {
	case <-child.done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("shared-capacity Gateway did not exit after SIGKILL")
	}
}

func countSanitizedRecords(path, kind string) (int, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxSharedCapacityRecordBytes)
	count := 0
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return 0, fmt.Errorf("decode sanitized record: %w", err)
		}
		value, _ := record["type"].(string)
		if value == "" {
			value, _ = record["kind"].(string)
		}
		if value == kind {
			count++
		}
	}
	return count, scanner.Err()
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256<<20)); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func assertEvidenceExcludes(root string, forbidden []string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range forbidden {
			if value != "" && strings.Contains(string(content), value) {
				return fmt.Errorf("evidence file %s contains forbidden runtime material", filepath.Base(path))
			}
		}
		return nil
	})
}
