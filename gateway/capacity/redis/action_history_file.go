package rediscapacity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	actionHistoryFileVersion = 1
	maxActionHistoryFileSize = 4096
)

type actionHistoryFileState struct {
	Version           int    `json:"version"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	Sequence          int64  `json:"sequence"`
	Token             string `json:"token"`
}

// FileActionHistoryWitness stores one monotonic checkpoint outside the
// Redis-compatible snapshot domain. One process owns the file for its lifetime.
type FileActionHistoryWitness struct {
	mu    sync.Mutex
	path  string
	state *actionHistoryFileState
	lock  *os.File
}

func OpenFileActionHistoryWitness(path string) (*FileActionHistoryWitness, error) {
	if strings.TrimSpace(path) == "" {
		return nil, ErrActionHistoryUnavailable
	}
	cleanPath := filepath.Clean(path)
	lock, err := acquireActionHistoryFileLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("%w: acquire witness lock", ErrActionHistoryUnavailable)
	}
	witness := &FileActionHistoryWitness{path: cleanPath, lock: lock}
	if err := witness.load(); err != nil {
		_ = releaseActionHistoryFileLock(lock)
		return nil, err
	}
	return witness, nil
}

func (w *FileActionHistoryWitness) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lock == nil {
		return nil
	}
	err := releaseActionHistoryFileLock(w.lock)
	w.lock = nil
	return err
}

func (w *FileActionHistoryWitness) Load(ctx context.Context, policyFingerprint string) (ActionHistoryCheckpoint, error) {
	if err := validateActionHistoryCall(ctx, policyFingerprint); err != nil {
		return ActionHistoryCheckpoint{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lock == nil {
		return ActionHistoryCheckpoint{}, ErrActionHistoryUnavailable
	}
	if w.state == nil {
		return ActionHistoryCheckpoint{}, ErrActionHistoryNotProvisioned
	}
	if w.state.PolicyFingerprint != policyFingerprint {
		return ActionHistoryCheckpoint{}, ErrActionHistoryUnavailable
	}
	return NewActionHistoryCheckpoint(w.state.Sequence, w.state.Token)
}

func (w *FileActionHistoryWitness) Provision(
	ctx context.Context,
	policyFingerprint string,
	initial ActionHistoryCheckpoint,
) error {
	if err := validateActionHistoryCall(ctx, policyFingerprint); err != nil {
		return err
	}
	if initial.validate() != nil || initial.sequence != 0 {
		return ErrActionHistoryUnavailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lock == nil {
		return ErrActionHistoryUnavailable
	}
	if w.state != nil {
		if w.state.PolicyFingerprint == policyFingerprint && w.state.Sequence == initial.sequence && w.state.Token == initial.token {
			return nil
		}
		return ErrActionHistoryConflict
	}
	next := actionHistoryFileState{
		Version: actionHistoryFileVersion, PolicyFingerprint: policyFingerprint,
		Sequence: initial.sequence, Token: initial.token,
	}
	committed, err := w.persist(ctx, next)
	if committed {
		w.state = &next
	}
	return err
}

func (w *FileActionHistoryWitness) CompareAndSwap(
	ctx context.Context,
	policyFingerprint string,
	previous ActionHistoryCheckpoint,
	replacement ActionHistoryCheckpoint,
) error {
	if err := validateActionHistoryCall(ctx, policyFingerprint); err != nil {
		return err
	}
	if previous.validate() != nil || replacement.validate() != nil ||
		replacement.sequence != previous.sequence+1 || replacement.token == previous.token {
		return ErrActionHistoryUnavailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lock == nil || w.state == nil || w.state.PolicyFingerprint != policyFingerprint {
		return ErrActionHistoryUnavailable
	}
	if w.state.Sequence != previous.sequence || w.state.Token != previous.token {
		return ErrActionHistoryConflict
	}
	next := actionHistoryFileState{
		Version: actionHistoryFileVersion, PolicyFingerprint: policyFingerprint,
		Sequence: replacement.sequence, Token: replacement.token,
	}
	committed, err := w.persist(ctx, next)
	if committed {
		w.state = &next
	}
	return err
}

func (w *FileActionHistoryWitness) load() error {
	pathInfo, err := os.Lstat(w.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: invalid witness file", ErrActionHistoryUnavailable)
	}
	file, err := os.Open(w.path)
	if err != nil {
		return fmt.Errorf("%w: open witness", ErrActionHistoryUnavailable)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: invalid witness file", ErrActionHistoryUnavailable)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxActionHistoryFileSize+1))
	if err != nil || len(data) > maxActionHistoryFileSize {
		return fmt.Errorf("%w: read witness", ErrActionHistoryUnavailable)
	}
	if err := rejectDuplicateActionHistoryJSONKeys(data); err != nil {
		return fmt.Errorf("%w: invalid witness JSON", ErrActionHistoryUnavailable)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(data, &shape); err != nil || len(shape) != 4 || shape["version"] == nil ||
		shape["policy_fingerprint"] == nil || shape["sequence"] == nil || shape["token"] == nil {
		return fmt.Errorf("%w: invalid witness shape", ErrActionHistoryUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state actionHistoryFileState
	if err := decoder.Decode(&state); err != nil || ensureActionHistoryJSONEOF(decoder) != nil ||
		state.Version != actionHistoryFileVersion || !validActionPolicyFingerprint(state.PolicyFingerprint) {
		return fmt.Errorf("%w: invalid witness state", ErrActionHistoryUnavailable)
	}
	checkpoint, err := NewActionHistoryCheckpoint(state.Sequence, state.Token)
	if err != nil || checkpoint.sequence != state.Sequence {
		return fmt.Errorf("%w: invalid witness checkpoint", ErrActionHistoryUnavailable)
	}
	w.state = &state
	return nil
}

func (w *FileActionHistoryWitness) persist(ctx context.Context, state actionHistoryFileState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrActionHistoryUnavailable, err)
	}
	directory := filepath.Dir(w.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("%w: create witness directory", ErrActionHistoryUnavailable)
	}
	file, err := os.CreateTemp(directory, ".action-history-witness-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create witness temporary file", ErrActionHistoryUnavailable)
	}
	temporaryPath := file.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("%w: secure witness temporary file", ErrActionHistoryUnavailable)
	}
	if err := json.NewEncoder(file).Encode(state); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("%w: encode witness", ErrActionHistoryUnavailable)
	}
	info, err := file.Stat()
	if err != nil || info.Size() > maxActionHistoryFileSize {
		_ = file.Close()
		return false, fmt.Errorf("%w: bound witness", ErrActionHistoryUnavailable)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("%w: sync witness", ErrActionHistoryUnavailable)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("%w: close witness", ErrActionHistoryUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrActionHistoryUnavailable, err)
	}
	if err := os.Rename(temporaryPath, w.path); err != nil {
		return false, fmt.Errorf("%w: replace witness", ErrActionHistoryUnavailable)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("%w: open witness directory", ErrActionHistoryUnavailable)
	}
	err = errors.Join(directoryFile.Sync(), directoryFile.Close())
	if err != nil {
		return true, fmt.Errorf("%w: sync witness directory", ErrActionHistoryUnavailable)
	}
	return true, nil
}

func validateActionHistoryCall(ctx context.Context, policyFingerprint string) error {
	if ctx == nil {
		return errors.Join(ErrActionHistoryUnavailable, context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrActionHistoryUnavailable, err)
	}
	if !validActionPolicyFingerprint(policyFingerprint) {
		return ErrActionHistoryUnavailable
	}
	return nil
}

func validActionPolicyFingerprint(value string) bool {
	return actionHistoryTokenPattern.MatchString(value)
}

func ensureActionHistoryJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("witness contains multiple JSON values")
	}
	return nil
}

func rejectDuplicateActionHistoryJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanActionHistoryJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("witness contains multiple JSON values")
	}
	return nil
}

func scanActionHistoryJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("witness object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("witness contains a duplicate JSON key")
			}
			seen[key] = struct{}{}
			if err := scanActionHistoryJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("witness object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanActionHistoryJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("witness array is not closed")
		}
	default:
		return errors.New("witness contains an unexpected JSON delimiter")
	}
	return nil
}

var _ ActionHistoryWitness = (*FileActionHistoryWitness)(nil)
