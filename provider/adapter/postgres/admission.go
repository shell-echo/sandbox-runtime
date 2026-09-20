package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

const (
	maxGuardEntries    = 4096
	maxScopeInputBytes = 16 << 10
	maxTokenLifetime   = 5 * time.Minute
)

type replayEntry struct {
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type fenceEntry struct {
	Scope        string    `json:"scope"`
	FencingToken int64     `json:"fencing_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}
type guardSnapshot struct {
	Version int           `json:"version"`
	Replays []replayEntry `json:"replays"`
	Fences  []fenceEntry  `json:"fences"`
}
type fenceRecord struct {
	token     int64
	expiresAt time.Time
}
type guardState struct {
	replays map[string]time.Time
	fences  map[string]fenceRecord
}

func newGuardState() guardState {
	return guardState{replays: make(map[string]time.Time), fences: make(map[string]fenceRecord)}
}
func importGuardState(state *guardState, document json.RawMessage) error {
	var snapshot guardSnapshot
	if err := decodePersisted(&snapshot, document); err != nil || snapshot.Version != 1 || snapshot.Replays == nil || snapshot.Fences == nil || len(snapshot.Replays) > maxGuardEntries || len(snapshot.Fences) > maxGuardEntries {
		return ErrCorrupt
	}
	for _, entry := range snapshot.Replays {
		if !validFingerprint(entry.Fingerprint) || entry.ExpiresAt.IsZero() {
			return ErrCorrupt
		}
		if _, exists := state.replays[entry.Fingerprint]; exists {
			return ErrCorrupt
		}
		state.replays[entry.Fingerprint] = entry.ExpiresAt.UTC()
	}
	for _, entry := range snapshot.Fences {
		if !validFingerprint(entry.Scope) || entry.FencingToken < 1 || entry.ExpiresAt.IsZero() {
			return ErrCorrupt
		}
		if _, exists := state.fences[entry.Scope]; exists {
			return ErrCorrupt
		}
		state.fences[entry.Scope] = fenceRecord{token: entry.FencingToken, expiresAt: entry.ExpiresAt.UTC()}
	}
	return nil
}
func exportGuardState(state guardState) any {
	snapshot := guardSnapshot{Version: 1, Replays: make([]replayEntry, 0, len(state.replays)), Fences: make([]fenceEntry, 0, len(state.fences))}
	for fingerprint, expiresAt := range state.replays {
		snapshot.Replays = append(snapshot.Replays, replayEntry{Fingerprint: fingerprint, ExpiresAt: expiresAt.UTC()})
	}
	for scope, record := range state.fences {
		snapshot.Fences = append(snapshot.Fences, fenceEntry{Scope: scope, FencingToken: record.token, ExpiresAt: record.expiresAt.UTC()})
	}
	sort.Slice(snapshot.Replays, func(i, j int) bool { return snapshot.Replays[i].Fingerprint < snapshot.Replays[j].Fingerprint })
	sort.Slice(snapshot.Fences, func(i, j int) bool { return snapshot.Fences[i].Scope < snapshot.Fences[j].Scope })
	return snapshot
}

type AdmissionGuard struct {
	store *Store
	clock admission.Clock
}

func NewAdmissionGuard(store *Store, clock admission.Clock) (*AdmissionGuard, error) {
	if store == nil || clock == nil || clock.Now().IsZero() {
		return nil, ErrUnavailable
	}
	return &AdmissionGuard{store: store, clock: clock}, nil
}
func (g *AdmissionGuard) Reserve(ctx context.Context, request admission.MutationGuardRequest) (admission.MutationGuardDecision, error) {
	decision := admission.MutationGuardAccepted
	err := mutateState(ctx, g.store, "admission", newGuardState, importGuardState, exportGuardState, func(state *guardState) error {
		now := g.clock.Now().UTC()
		if err := validateGuardRequest(request, now); err != nil {
			return err
		}
		for key, expiresAt := range state.replays {
			if !expiresAt.After(now) {
				delete(state.replays, key)
			}
		}
		for key, record := range state.fences {
			if !record.expiresAt.After(now) {
				delete(state.fences, key)
			}
		}
		jti := hex.EncodeToString(request.JTIFingerprint[:])
		if _, exists := state.replays[jti]; exists {
			decision = admission.MutationGuardReplayed
			return nil
		}
		scope := guardScope(request)
		previous, exists := state.fences[scope]
		if exists && request.FencingToken < previous.token {
			decision = admission.MutationGuardStaleFencing
			return nil
		}
		if len(state.replays) >= maxGuardEntries || (!exists && len(state.fences) >= maxGuardEntries) {
			return ErrUnavailable
		}
		state.replays[jti] = request.ExpiresAt.UTC()
		if !exists || request.FencingToken > previous.token {
			previous.token = request.FencingToken
		}
		if request.ExpiresAt.After(previous.expiresAt) {
			previous.expiresAt = request.ExpiresAt.UTC()
		}
		state.fences[scope] = previous
		return nil
	})
	return decision, err
}
func (g *AdmissionGuard) Close() error { return nil }

func validateGuardRequest(request admission.MutationGuardRequest, now time.Time) error {
	if now.IsZero() || request.FencingToken < 1 || request.JTIFingerprint == [sha256.Size]byte{} || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(now) || request.ExpiresAt.Sub(now) > maxTokenLifetime {
		return errors.New("Provider admission guard request is invalid")
	}
	total := 0
	for _, value := range []string{request.ProviderRevisionID, request.SandboxID, request.OperationID, request.AttemptID} {
		if !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
			return errors.New("Provider admission guard request scope is invalid")
		}
		total += len(value)
		if total > maxScopeInputBytes {
			return errors.New("Provider admission guard request scope exceeds its bound")
		}
	}
	return nil
}
func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func guardScope(request admission.MutationGuardRequest) string {
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

var _ admission.MutationGuard = (*AdmissionGuard)(nil)
