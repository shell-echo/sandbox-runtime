package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
)

const (
	desktopStateVersion  = 2
	maxDesktopStateBytes = 64 << 10
	connectionGeneration = 1
)

var backendIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type desktopState struct {
	Version            int
	Request            providerdesktop.AllocationRequest
	Receipt            providerdesktop.AllocationReceipt
	BackendContainerID string
	Network            NetworkAttachment
	SpecDigest         string
	Ready              bool
}

func newDesktopState(allocation providerdesktop.Allocation, network NetworkAttachment, specDigest string) desktopState {
	token := allocationToken(allocation.Request.SandboxID, allocation.Request.DesktopSessionID)
	return desktopState{
		Version: desktopStateVersion, Request: allocation.Request,
		Receipt: providerdesktop.AllocationReceipt{
			Reference: "ref:desktop/" + token,
			SandboxID: allocation.Request.SandboxID, DesktopSessionID: allocation.Request.DesktopSessionID,
			OperationID: allocation.Request.OperationID, AttemptID: allocation.Request.AttemptID,
			FencingToken: allocation.Request.FencingToken, ExpectedGeneration: allocation.Request.ExpectedGeneration,
			ConnectionGeneration: connectionGeneration, AllocatedAt: allocation.AllocatedAt.UTC(),
			ExpiresAt: allocation.Request.ExpiresAt.UTC(),
		},
		Network: network, SpecDigest: specDigest,
	}
}

func (s desktopState) validate(networkPolicy string) error {
	token := allocationToken(s.Request.SandboxID, s.Request.DesktopSessionID)
	if s.Version != desktopStateVersion || s.Request.Validate(s.Receipt.AllocatedAt) != nil ||
		s.Receipt.Validate() != nil || !s.Receipt.Matches(s.Request) ||
		s.Receipt.Reference != "ref:desktop/"+token || s.Receipt.ConnectionGeneration != connectionGeneration ||
		s.Network.validate(networkPolicy) != nil || !digestPattern.MatchString(s.SpecDigest) ||
		(s.BackendContainerID != "" && !backendIDPattern.MatchString(s.BackendContainerID)) ||
		(s.Ready && s.BackendContainerID == "") {
		return ErrInvalidRuntime
	}
	return nil
}

func (s desktopState) matchesAllocation(allocation providerdesktop.Allocation) bool {
	return sameAllocationRequest(s.Request, allocation.Request) && s.Receipt.AllocatedAt.Equal(allocation.AllocatedAt)
}

func (s desktopState) matchesReceipt(receipt providerdesktop.AllocationReceipt) bool {
	return sameReceipt(s.Receipt, receipt)
}

func sameAllocationRequest(left, right providerdesktop.AllocationRequest) bool {
	return left.SandboxID == right.SandboxID && left.DesktopSessionID == right.DesktopSessionID &&
		left.OperationID == right.OperationID && left.AttemptID == right.AttemptID &&
		left.FencingToken == right.FencingToken && left.ExpectedGeneration == right.ExpectedGeneration &&
		left.RequestDigest == right.RequestDigest && left.NetworkPolicyReference == right.NetworkPolicyReference &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

func sameReceipt(left, right providerdesktop.AllocationReceipt) bool {
	return left.Reference == right.Reference && left.SandboxID == right.SandboxID &&
		left.DesktopSessionID == right.DesktopSessionID && left.OperationID == right.OperationID &&
		left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken &&
		left.ExpectedGeneration == right.ExpectedGeneration && left.ConnectionGeneration == right.ConnectionGeneration &&
		left.AllocatedAt.Equal(right.AllocatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func loadDesktopState(path, networkPolicy string) (desktopState, error) {
	file, err := os.Open(path)
	if err != nil {
		return desktopState{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxDesktopStateBytes {
		return desktopState{}, ErrInvalidRuntime
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxDesktopStateBytes+1))
	decoder.DisallowUnknownFields()
	var state desktopState
	if err := decoder.Decode(&state); err != nil {
		return desktopState{}, ErrInvalidRuntime
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return desktopState{}, ErrInvalidRuntime
	}
	if err := state.validate(networkPolicy); err != nil {
		return desktopState{}, err
	}
	return state, nil
}

func persistDesktopState(path string, state desktopState, networkPolicy string) error {
	if err := state.validate(networkPolicy); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".desktop-state-*.tmp")
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

func prepareDataRoot(configured string) (string, error) {
	absolute, err := filepath.Abs(configured)
	if err != nil {
		return "", ErrInvalidOptions
	}
	clean := filepath.Clean(absolute)
	if clean == string(filepath.Separator) {
		return "", ErrInvalidOptions
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return "", err
	}
	if err := ensureDirectory(clean, 0o700); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func ensureDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidRuntime
	}
	return os.Chmod(path, mode)
}

func countDesktopStates(dataRoot, networkPolicy string) (int, error) {
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, sandbox := range entries {
		if !sandbox.IsDir() {
			continue
		}
		directory := filepath.Join(dataRoot, sandbox.Name(), "desktop")
		sessions, err := os.ReadDir(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		for _, session := range sessions {
			if session.IsDir() || filepath.Ext(session.Name()) != ".json" {
				continue
			}
			if _, err := loadDesktopState(filepath.Join(directory, session.Name()), networkPolicy); err != nil {
				return 0, err
			}
			total++
		}
	}
	return total, nil
}

func allocationToken(sandboxID, desktopSessionID string) string {
	digest := sha256.Sum256([]byte(sandboxID + "\x00" + desktopSessionID))
	return hex.EncodeToString(digest[:16])
}

func sandboxToken(sandboxID string) string {
	digest := sha256.Sum256([]byte(sandboxID))
	return hex.EncodeToString(digest[:16])
}

func containerName(sandboxID, desktopSessionID string) string {
	return "sandbox-runtime-desktop-" + allocationToken(sandboxID, desktopSessionID)
}
