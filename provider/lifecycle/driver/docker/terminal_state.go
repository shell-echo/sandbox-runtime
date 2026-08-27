package docker

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	providerterminal "github.com/shell-echo/sandbox-runtime/provider/terminal"
)

const (
	terminalStateVersion  = 1
	maxTerminalStateBytes = 64 << 10
)

type terminalState struct {
	Version             int
	Request             providerterminal.AllocationRequest
	Receipt             providerterminal.Receipt
	BackendContainerID  string
	BackendBrokerExecID string
	BrokerSocketPath    string
	Ready               bool
}

func newTerminalState(allocation providerterminal.Allocation, containerID string) terminalState {
	token := terminalToken(allocation.Request.SandboxID, allocation.Request.RuntimeSessionID)
	return terminalState{
		Version: terminalStateVersion, Request: allocation.Request.Clone(),
		Receipt: providerterminal.Receipt{
			Reference: providerterminal.Reference("ref:terminal/" + token),
			SandboxID: allocation.Request.SandboxID, RuntimeSessionID: allocation.Request.RuntimeSessionID,
			OperationID: allocation.Request.OperationID, AttemptID: allocation.Request.AttemptID,
			FencingToken: allocation.Request.FencingToken, ExpectedGeneration: allocation.Request.ExpectedGeneration,
			ConnectionGeneration: terminalConnectionGen, AllocatedAt: allocation.AllocatedAt.UTC(), ExpiresAt: allocation.Request.ExpiresAt.UTC(),
		},
		BackendContainerID: containerID, BrokerSocketPath: terminalSocketPath(token),
	}
}

func (s terminalState) validate() error {
	if s.Version != terminalStateVersion || s.BackendContainerID == "" || s.BrokerSocketPath == "" ||
		s.BrokerSocketPath != terminalSocketPath(terminalToken(s.Request.SandboxID, s.Request.RuntimeSessionID)) ||
		(s.Ready && s.BackendBrokerExecID == "") || s.Request.Validate(s.Receipt.AllocatedAt) != nil ||
		s.Receipt.Validate() != nil || !s.Receipt.Matches(s.Request) ||
		s.Receipt.Reference != providerterminal.Reference("ref:terminal/"+terminalToken(s.Request.SandboxID, s.Request.RuntimeSessionID)) {
		return ErrInvalidRuntime
	}
	return nil
}

func (s terminalState) matchesAllocation(allocation providerterminal.Allocation) bool {
	return sameTerminalRequest(s.Request, allocation.Request) && s.Receipt.AllocatedAt.Equal(allocation.AllocatedAt)
}

func (s terminalState) matchesReceipt(receipt providerterminal.Receipt) bool {
	return s.Receipt == receipt
}

func sameTerminalRequest(left, right providerterminal.AllocationRequest) bool {
	return left.SandboxID == right.SandboxID && left.RuntimeSessionID == right.RuntimeSessionID &&
		left.OperationID == right.OperationID && left.AttemptID == right.AttemptID &&
		left.FencingToken == right.FencingToken && left.ExpectedGeneration == right.ExpectedGeneration &&
		left.RequestDigest == right.RequestDigest && left.WorkingDirectory == right.WorkingDirectory && left.ExpiresAt.Equal(right.ExpiresAt)
}

func loadTerminalState(path string) (terminalState, error) {
	file, err := os.Open(path)
	if err != nil {
		return terminalState{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxTerminalStateBytes {
		return terminalState{}, ErrInvalidRuntime
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxTerminalStateBytes+1))
	decoder.DisallowUnknownFields()
	var state terminalState
	if err := decoder.Decode(&state); err != nil {
		return terminalState{}, ErrInvalidRuntime
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return terminalState{}, ErrInvalidRuntime
	}
	if err := state.validate(); err != nil {
		return terminalState{}, err
	}
	return state, nil
}

func persistTerminalState(path string, state terminalState) error {
	if err := state.validate(); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".terminal-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(state); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := errors.Join(temporary.Sync(), temporary.Close()); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func countTerminalStates(directory string) (int, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if _, err := loadTerminalState(filepath.Join(directory, entry.Name())); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func countControllerTerminalStates(dataRoot string) (int, error) {
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		directory := filepath.Join(dataRoot, entry.Name(), "terminal")
		count, err := countTerminalStates(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}
