package orchestrator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
)

const maxDurableRevocationRecordBytes = 64 << 10

// durableControlProcess owns one independent caller or revoker JSONL process.
// A timed-out request terminates and reaps the process because its stream can
// no longer be correlated safely with later commands.
type durableControlProcess struct {
	name    string
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
	log     *os.File
	done    chan struct{}

	requestMu sync.Mutex
	stateMu   sync.Mutex
	sequence  uint64
	err       error
}

func startDurableControl(name, binary, configPath, logPath string) (*durableControlProcess, error) {
	if name == "" {
		return nil, errors.New("durable-revocation process name is required")
	}
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
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		_ = logFile.Close()
		return nil, err
	}
	command.Stderr = logFile
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), maxDurableRevocationRecordBytes)
	process := &durableControlProcess{
		name: name, command: command, input: input, output: scanner,
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

func (p *durableControlProcess) request(ctx context.Context, command wire.Command) (wire.Response, error) {
	if p == nil || p.command == nil || p.input == nil || p.output == nil {
		return wire.Response{}, errors.New("durable-revocation control process is unavailable")
	}
	if ctx == nil {
		return wire.Response{}, context.Canceled
	}
	p.requestMu.Lock()
	defer p.requestMu.Unlock()
	select {
	case <-p.done:
		return wire.Response{}, fmt.Errorf("%s process exited", p.name)
	default:
	}

	p.sequence++
	command.Version = wire.ProtocolVersion
	command.Sequence = p.sequence
	encoded, err := json.Marshal(command)
	if err != nil {
		return wire.Response{}, err
	}
	if len(encoded) > maxDurableRevocationRecordBytes {
		return wire.Response{}, errors.New("durable-revocation command exceeds its bound")
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
			return wire.Response{}, fmt.Errorf("write %s command", p.name)
		}
	case <-ctx.Done():
		p.terminate()
		return wire.Response{}, ctx.Err()
	case <-p.done:
		return wire.Response{}, fmt.Errorf("%s process exited", p.name)
	}

	type scanResult struct {
		line []byte
		ok   bool
		err  error
	}
	responseDone := make(chan scanResult, 1)
	go func() {
		ok := p.output.Scan()
		responseDone <- scanResult{line: append([]byte(nil), p.output.Bytes()...), ok: ok, err: p.output.Err()}
	}()
	select {
	case result := <-responseDone:
		if !result.ok || result.err != nil {
			p.terminate()
			return wire.Response{}, fmt.Errorf("read %s response", p.name)
		}
		response, err := decodeDurableResponse(result.line)
		if err != nil || response.Version != wire.ProtocolVersion || response.Sequence != command.Sequence {
			p.terminate()
			return wire.Response{}, fmt.Errorf("%s response correlation failed", p.name)
		}
		return response, nil
	case <-ctx.Done():
		p.terminate()
		return wire.Response{}, ctx.Err()
	case <-p.done:
		return wire.Response{}, fmt.Errorf("%s process exited", p.name)
	}
}

func decodeDurableResponse(content []byte) (wire.Response, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var response wire.Response
	if err := decoder.Decode(&response); err != nil {
		return wire.Response{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return wire.Response{}, errors.New("durable-revocation response has trailing content")
	}
	return response, nil
}

func (p *durableControlProcess) shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return p.result()
	default:
	}
	response, requestErr := p.request(ctx, wire.Command{Action: wire.ActionShutdown})
	if requestErr == nil && (!response.OK || response.Outcome != wire.OutcomeTerminated || response.ErrorCode != "") {
		requestErr = fmt.Errorf("%s process rejected shutdown", p.name)
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
			return errors.Join(requestErr, ctx.Err(), killErr, fmt.Errorf("%s process did not exit after kill", p.name))
		}
	}
}

func (p *durableControlProcess) result() error {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.err
}

func (p *durableControlProcess) terminate() {
	if p == nil || p.command == nil || p.command.Process == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
		_ = p.command.Process.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
	}
}
