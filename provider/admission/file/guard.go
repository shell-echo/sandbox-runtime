// Package file provides a durable single-controller Provider admission guard.
package file

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

const (
	formatVersion      = 1
	maxStateFileBytes  = 4 << 20
	maxGuardEntries    = 4096
	maxScopeInputBytes = 16 << 10
	maxTokenLifetime   = 5 * time.Minute
)

type replayEntry struct {
	JTIFingerprint string    `json:"jti_fingerprint"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type fenceEntry struct {
	ScopeFingerprint string    `json:"scope_fingerprint"`
	FencingToken     int64     `json:"fencing_token"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type snapshot struct {
	Version int           `json:"version"`
	Replays []replayEntry `json:"replays"`
	Fences  []fenceEntry  `json:"fences"`
}

// Guard atomically persists JTI fingerprints and scoped fencing high-water
// marks. It is safe for concurrent goroutines and holds an advisory lock for
// its lifetime so another local process cannot use the same state file.
type Guard struct {
	mu      sync.Mutex
	path    string
	clock   admission.Clock
	replays map[string]time.Time
	fences  map[string]fenceRecord
	lock    *os.File
}

type fenceRecord struct {
	token     int64
	expiresAt time.Time
}

// NewGuard opens a durable guard. A non-empty state path and a determinate
// injected clock are mandatory because a missing guard must fail closed.
func NewGuard(path string, clock admission.Clock) (*Guard, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("provider admission guard path is required")
	}
	if clock == nil || clock.Now().IsZero() {
		return nil, errors.New("provider admission guard requires a determinate clock")
	}

	cleanPath := filepath.Clean(path)
	lock, err := acquireFileLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock provider admission guard: %w", err)
	}
	guard := &Guard{
		path:    cleanPath,
		clock:   clock,
		replays: make(map[string]time.Time),
		fences:  make(map[string]fenceRecord),
		lock:    lock,
	}
	if err := guard.load(); err != nil {
		_ = releaseFileLock(lock)
		return nil, err
	}
	if guard.pruneExpired(clock.Now()) {
		if _, err := guard.persist(context.Background(), guard.replays, guard.fences); err != nil {
			_ = releaseFileLock(lock)
			return nil, err
		}
	}
	return guard, nil
}

// Close releases the exclusive local-process lock. A closed guard cannot
// reserve another mutation and must be replaced through composition.
func (g *Guard) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lock == nil {
		return nil
	}
	err := releaseFileLock(g.lock)
	g.lock = nil
	return err
}

// Reserve atomically consumes a mutation JTI fingerprint and advances its
// operation-scoped fencing high-water mark. It never persists raw bearer
// material, a raw JTI, request documents, or Provider lifecycle state.
func (g *Guard) Reserve(ctx context.Context, request admission.MutationGuardRequest) (admission.MutationGuardDecision, error) {
	if ctx == nil {
		return admission.MutationGuardAccepted, errors.New("provider admission guard context is required")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.lock == nil {
		return admission.MutationGuardAccepted, errors.New("provider admission guard is closed")
	}
	if err := ctx.Err(); err != nil {
		return admission.MutationGuardAccepted, err
	}
	now := g.clock.Now()
	if err := validateRequest(request, now); err != nil {
		return admission.MutationGuardAccepted, err
	}

	replays := cloneReplays(g.replays)
	fences := cloneFences(g.fences)
	changed := pruneExpired(replays, fences, now)

	jti := hex.EncodeToString(request.JTIFingerprint[:])
	if _, exists := replays[jti]; exists {
		return g.persistRejected(ctx, replays, fences, changed, admission.MutationGuardReplayed)
	}

	scope := scopeFingerprint(request)
	if previous, exists := fences[scope]; exists && request.FencingToken < previous.token {
		return g.persistRejected(ctx, replays, fences, changed, admission.MutationGuardStaleFencing)
	}
	if len(replays) >= maxGuardEntries {
		return g.persistUnavailable(ctx, replays, fences, changed, "provider admission guard replay capacity is exhausted")
	}
	if _, exists := fences[scope]; !exists && len(fences) >= maxGuardEntries {
		return g.persistUnavailable(ctx, replays, fences, changed, "provider admission guard fencing capacity is exhausted")
	}

	replays[jti] = request.ExpiresAt.UTC()
	previous, exists := fences[scope]
	if !exists || request.FencingToken > previous.token {
		previous.token = request.FencingToken
	}
	if request.ExpiresAt.After(previous.expiresAt) {
		previous.expiresAt = request.ExpiresAt.UTC()
	}
	fences[scope] = previous

	committed, err := g.persist(ctx, replays, fences)
	if committed {
		g.replays = replays
		g.fences = fences
	}
	if err != nil {
		return admission.MutationGuardAccepted, err
	}
	return admission.MutationGuardAccepted, nil
}

func (g *Guard) persistRejected(ctx context.Context, replays map[string]time.Time, fences map[string]fenceRecord, changed bool, decision admission.MutationGuardDecision) (admission.MutationGuardDecision, error) {
	if !changed {
		return decision, nil
	}
	committed, err := g.persist(ctx, replays, fences)
	if committed {
		g.replays = replays
		g.fences = fences
	}
	if err != nil {
		return admission.MutationGuardAccepted, err
	}
	return decision, nil
}

func (g *Guard) persistUnavailable(ctx context.Context, replays map[string]time.Time, fences map[string]fenceRecord, changed bool, message string) (admission.MutationGuardDecision, error) {
	if changed {
		committed, err := g.persist(ctx, replays, fences)
		if committed {
			g.replays = replays
			g.fences = fences
		}
		if err != nil {
			return admission.MutationGuardAccepted, err
		}
	}
	return admission.MutationGuardAccepted, errors.New(message)
}

func (g *Guard) load() error {
	file, err := os.Open(g.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open provider admission guard: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat provider admission guard: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("provider admission guard state file must be a regular 0600 file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateFileBytes+1))
	if err != nil {
		return fmt.Errorf("read provider admission guard: %w", err)
	}
	if len(data) > maxStateFileBytes {
		return fmt.Errorf("provider admission guard exceeds %d bytes", maxStateFileBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return fmt.Errorf("decode provider admission guard: %w", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode provider admission guard shape: %w", err)
	}
	if len(fields) != 3 || fields["version"] == nil || fields["replays"] == nil || fields["fences"] == nil {
		return errors.New("provider admission guard state has an invalid shape")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var stored snapshot
	if err := decoder.Decode(&stored); err != nil {
		return fmt.Errorf("decode provider admission guard: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode provider admission guard: %w", err)
	}
	if stored.Version != formatVersion || stored.Replays == nil || stored.Fences == nil {
		return errors.New("provider admission guard state has an unsupported version or collection")
	}
	if len(stored.Replays) > maxGuardEntries || len(stored.Fences) > maxGuardEntries {
		return errors.New("provider admission guard state exceeds entry capacity")
	}

	now := g.clock.Now()
	if now.IsZero() {
		return errors.New("provider admission guard clock is indeterminate")
	}
	for _, entry := range stored.Replays {
		if !validFingerprint(entry.JTIFingerprint) || !validStoredExpiry(entry.ExpiresAt, now) {
			return errors.New("provider admission guard has an invalid replay entry")
		}
		if _, exists := g.replays[entry.JTIFingerprint]; exists {
			return errors.New("provider admission guard has a duplicate replay entry")
		}
		g.replays[entry.JTIFingerprint] = entry.ExpiresAt.UTC()
	}
	for _, entry := range stored.Fences {
		if !validFingerprint(entry.ScopeFingerprint) || entry.FencingToken < 1 || !validStoredExpiry(entry.ExpiresAt, now) {
			return errors.New("provider admission guard has an invalid fencing entry")
		}
		if _, exists := g.fences[entry.ScopeFingerprint]; exists {
			return errors.New("provider admission guard has a duplicate fencing entry")
		}
		g.fences[entry.ScopeFingerprint] = fenceRecord{token: entry.FencingToken, expiresAt: entry.ExpiresAt.UTC()}
	}
	return nil
}

func (g *Guard) pruneExpired(now time.Time) bool {
	return pruneExpired(g.replays, g.fences, now)
}

func pruneExpired(replays map[string]time.Time, fences map[string]fenceRecord, now time.Time) bool {
	changed := false
	for fingerprint, expiresAt := range replays {
		if !expiresAt.After(now) {
			delete(replays, fingerprint)
			changed = true
		}
	}
	for scope, record := range fences {
		if !record.expiresAt.After(now) {
			delete(fences, scope)
			changed = true
		}
	}
	return changed
}

// persist reports committed once rename makes the new state visible. A caller
// must retain the new in-memory state after that point even if directory sync
// reports a durability error, then fail closed on the returned error.
func (g *Guard) persist(ctx context.Context, replays map[string]time.Time, fences map[string]fenceRecord) (committed bool, result error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	directory := filepath.Dir(g.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("create provider admission guard directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".provider-admission-guard-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create provider admission guard temporary file: %w", err)
	}
	temporaryPath := file.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("secure provider admission guard temporary file: %w", err)
	}
	if err := json.NewEncoder(file).Encode(makeSnapshot(replays, fences)); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("encode provider admission guard: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return false, fmt.Errorf("stat provider admission guard temporary file: %w", err)
	}
	if info.Size() > maxStateFileBytes {
		_ = file.Close()
		return false, fmt.Errorf("provider admission guard exceeds %d bytes", maxStateFileBytes)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("sync provider admission guard: %w", err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("close provider admission guard: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, g.path); err != nil {
		return false, fmt.Errorf("replace provider admission guard: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("open provider admission guard directory: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return true, fmt.Errorf("sync provider admission guard directory: %w", errors.Join(syncErr, closeErr))
	}
	return true, nil
}

func makeSnapshot(replays map[string]time.Time, fences map[string]fenceRecord) snapshot {
	stored := snapshot{
		Version: formatVersion,
		Replays: make([]replayEntry, 0, len(replays)),
		Fences:  make([]fenceEntry, 0, len(fences)),
	}
	for fingerprint, expiresAt := range replays {
		stored.Replays = append(stored.Replays, replayEntry{JTIFingerprint: fingerprint, ExpiresAt: expiresAt.UTC()})
	}
	slices.SortFunc(stored.Replays, func(a, b replayEntry) int { return strings.Compare(a.JTIFingerprint, b.JTIFingerprint) })
	for scope, record := range fences {
		stored.Fences = append(stored.Fences, fenceEntry{ScopeFingerprint: scope, FencingToken: record.token, ExpiresAt: record.expiresAt.UTC()})
	}
	slices.SortFunc(stored.Fences, func(a, b fenceEntry) int { return strings.Compare(a.ScopeFingerprint, b.ScopeFingerprint) })
	return stored
}

func validateRequest(request admission.MutationGuardRequest, now time.Time) error {
	if now.IsZero() || request.FencingToken < 1 || fingerprintIsZero(request.JTIFingerprint) {
		return errors.New("provider admission guard request is invalid")
	}
	if request.ExpiresAt.IsZero() || !request.ExpiresAt.After(now) || request.ExpiresAt.Sub(now) > maxTokenLifetime {
		return errors.New("provider admission guard request expiry is invalid")
	}
	totalBytes := 0
	for _, value := range []string{request.ProviderRevisionID, request.SandboxID, request.OperationID, request.AttemptID} {
		if !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
			return errors.New("provider admission guard request scope is invalid")
		}
		totalBytes += len(value)
		if totalBytes > maxScopeInputBytes {
			return errors.New("provider admission guard request scope exceeds its bound")
		}
	}
	return nil
}

func validStoredExpiry(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && !expiresAt.After(now.Add(maxTokenLifetime))
}

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func fingerprintIsZero(fingerprint [sha256.Size]byte) bool {
	return fingerprint == [sha256.Size]byte{}
}

func scopeFingerprint(request admission.MutationGuardRequest) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("sandbox-runtime/provider-admission-guard-scope/v1"))
	for _, value := range []string{request.ProviderRevisionID, request.SandboxID, request.OperationID} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func cloneReplays(source map[string]time.Time) map[string]time.Time {
	copy := make(map[string]time.Time, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func cloneFences(source map[string]fenceRecord) map[string]fenceRecord {
	copy := make(map[string]fenceRecord, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
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
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values")
}

var _ admission.MutationGuard = (*Guard)(nil)
