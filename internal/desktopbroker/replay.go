package desktopbroker

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
)

const (
	bridgeReplayLedgerVersion = 1
	bridgeReplayMaxClaims     = 4096
	bridgeReplayMaxBytes      = 1 << 20
)

var bridgeReplayKeyPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type bridgeReplayClaim struct {
	Key       string `json:"key"`
	ExpiresAt string `json:"expires_at"`
}

type bridgeReplayDocument struct {
	Version int                 `json:"version"`
	Claims  []bridgeReplayClaim `json:"claims"`
}

type bridgeReplayLedger struct {
	mu      sync.Mutex
	path    string
	claimed map[string]time.Time
}

func newBridgeReplayLedger(path string, now time.Time) (*bridgeReplayLedger, error) {
	if path == "" || !now.Equal(now.UTC()) || now.IsZero() {
		return nil, ErrInvalidArguments
	}
	if err := validateReplayDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	ledger := &bridgeReplayLedger{path: path, claimed: make(map[string]time.Time)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ledger, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) || info.Size() < 1 || info.Size() > bridgeReplayMaxBytes {
		return nil, ErrInvalidRequest
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	var stored bridgeReplayDocument
	if decodeReplayDocument(document, &stored) != nil || stored.Version != bridgeReplayLedgerVersion || len(stored.Claims) > bridgeReplayMaxClaims {
		return nil, ErrInvalidRequest
	}
	for _, claim := range stored.Claims {
		expires, parseErr := time.Parse(time.RFC3339Nano, claim.ExpiresAt)
		if parseErr != nil || !expires.Equal(expires.UTC()) || !bridgeReplayKeyPattern.MatchString(claim.Key) {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := ledger.claimed[claim.Key]; duplicate {
			return nil, ErrInvalidRequest
		}
		if expires.After(now) {
			ledger.claimed[claim.Key] = expires
		}
	}
	return ledger, nil
}

func (r *bridgeReplayLedger) claim(envelope *desktopbridge.Envelope) bool {
	if r == nil || envelope == nil {
		return false
	}
	now := time.Now().UTC()
	expires, err := time.Parse(time.RFC3339Nano, envelope.Statement.HandoffExpiresAt)
	if err != nil || !expires.Equal(expires.UTC()) || !expires.After(now) {
		return false
	}
	identity := envelope.Statement.Digest() + "\x00" + envelope.Statement.Nonce + "\x00" + envelope.Statement.ExecutorIdentity + "\x00" + envelope.Statement.ConnectionEpoch
	digest := sha256.Sum256([]byte(identity))
	key := fmt.Sprintf("sha256:%x", digest[:])

	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]time.Time, len(r.claimed)+1)
	for claimed, until := range r.claimed {
		if until.After(now) {
			next[claimed] = until
		}
	}
	if _, exists := next[key]; exists || len(next) >= bridgeReplayMaxClaims {
		return false
	}
	next[key] = expires
	if r.persist(next) != nil {
		return false
	}
	r.claimed = next
	return true
}

func (r *bridgeReplayLedger) persist(claimed map[string]time.Time) error {
	if r == nil || r.path == "" {
		return ErrInvalidRequest
	}
	keys := make([]string, 0, len(claimed))
	for key := range claimed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	document := bridgeReplayDocument{Version: bridgeReplayLedgerVersion, Claims: make([]bridgeReplayClaim, 0, len(keys))}
	for _, key := range keys {
		document.Claims = append(document.Claims, bridgeReplayClaim{Key: key, ExpiresAt: claimed[key].UTC().Format(time.RFC3339Nano)})
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > bridgeReplayMaxBytes {
		return ErrInvalidRequest
	}
	directory := filepath.Dir(r.path)
	if err := validateReplayDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".desktop-bridge-replay-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = directoryFile.Sync()
	closeErr := directoryFile.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func decodeReplayDocument(document []byte, target *bridgeReplayDocument) error {
	if len(document) == 0 || len(document) > bridgeReplayMaxBytes || target == nil {
		return ErrInvalidRequest
	}
	duplicateDecoder := json.NewDecoder(bytes.NewReader(document))
	if err := scanUniqueJSON(duplicateDecoder); err != nil {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrInvalidRequest
	}
	return nil
}

func validateReplayDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return ErrInvalidRequest
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(stat.Uid) == uint32(os.Getuid())
}
