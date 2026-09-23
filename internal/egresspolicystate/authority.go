package egresspolicystate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const ledgerSchema = "sandbox-runtime.egress-policy-state-ledger.v1"

type AuthorityConfig struct {
	Binding         Binding
	LedgerPath      string
	SnapshotPath    string
	PrivateKey      ed25519.PrivateKey
	Now             func() time.Time
	AllowInitialize bool
}

type Ledger struct {
	Schema            string `json:"schema"`
	EnvironmentDigest string `json:"environment_digest"`
	ProfileDigest     string `json:"profile_digest"`
	PolicyID          string `json:"policy_id"`
	PolicyRevision    string `json:"policy_revision"`
	PolicyDigest      string `json:"policy_digest"`
	PrincipalDigest   string `json:"principal_digest"`
	BrokerDigest      string `json:"broker_digest"`
	Generation        uint64 `json:"generation"`
	Status            string `json:"status"`
	SnapshotDigest    string `json:"snapshot_digest"`
	CommittedAt       string `json:"committed_at"`
	PreviousDigest    string `json:"previous_digest"`
	LedgerDigest      string `json:"ledger_digest"`
}

type Authority struct {
	mu           sync.Mutex
	binding      Binding
	ledgerPath   string
	snapshotPath string
	privateKey   ed25519.PrivateKey
	now          func() time.Time
	lockFile     *os.File
	current      Ledger
	replays      map[string]time.Time
	closed       bool
}

func OpenAuthority(config AuthorityConfig) (*Authority, error) {
	if !validPrivatePath(config.LedgerPath) || !validPrivatePath(config.SnapshotPath) ||
		config.LedgerPath == config.SnapshotPath || config.Now == nil || config.Now().IsZero() ||
		len(config.PrivateKey) != ed25519.PrivateKeySize ||
		!config.PrivateKey.Public().(ed25519.PublicKey).Equal(config.Binding.operatorPublicKey) {
		return nil, ErrInvalid
	}
	lockFile, err := openAuthorityLock(config.LedgerPath + ".lock")
	if err != nil {
		return nil, ErrInvalid
	}
	authority := &Authority{binding: config.Binding, ledgerPath: config.LedgerPath, snapshotPath: config.SnapshotPath,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...), now: config.Now, lockFile: lockFile,
		replays: make(map[string]time.Time)}
	ledger, err := loadAuthorityLedger(config.LedgerPath, config.Binding)
	if err != nil {
		if !config.AllowInitialize || !errors.Is(err, os.ErrNotExist) {
			_ = authority.Close()
			return nil, ErrInvalid
		}
	} else {
		authority.current = ledger
	}
	return authority, nil
}

func (a *Authority) Commit(expectedGeneration uint64, status string, lifetime time.Duration) (Snapshot, error) {
	if a == nil {
		return Snapshot{}, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || expectedGeneration != a.current.Generation || a.current.Status == "revoked" ||
		(status != "active" && status != "revoked") || lifetime < time.Second || lifetime > MaxStateLifetime ||
		a.current.Generation == ^uint64(0) || a.checkDiskLocked() != nil {
		return Snapshot{}, ErrInvalid
	}
	now := a.now().UTC()
	if !a.current.CommittedAtIsZero() {
		previous, _ := canonicalTime(a.current.CommittedAt)
		if now.Before(previous) {
			return Snapshot{}, ErrInvalid
		}
	}
	snapshot, err := NewSigned(a.binding, a.current.Generation+1, now, now.Add(lifetime), status, a.privateKey)
	if err != nil {
		return Snapshot{}, ErrInvalid
	}
	ledger := Ledger{Schema: ledgerSchema, EnvironmentDigest: a.binding.environmentDigest,
		ProfileDigest: a.binding.profileDigest, PolicyID: a.binding.policyID,
		PolicyRevision: a.binding.policyRevision, PolicyDigest: a.binding.policyDigest,
		PrincipalDigest: a.binding.principalDigest, BrokerDigest: a.binding.brokerDigest,
		Generation: snapshot.Generation, Status: status, SnapshotDigest: snapshot.SnapshotDigest,
		CommittedAt: now.Format(time.RFC3339Nano), PreviousDigest: a.current.LedgerDigest}
	ledger.LedgerDigest = ledger.digest()
	ledgerDocument, err := json.Marshal(ledger)
	if err != nil || atomicWritePrivate(a.ledgerPath, ledgerDocument) != nil {
		return Snapshot{}, ErrInvalid
	}
	a.current = ledger // committed state wins even when snapshot publication fails
	snapshotDocument, err := json.Marshal(snapshot)
	if err != nil || atomicWritePrivate(a.snapshotPath, snapshotDocument) != nil {
		return Snapshot{}, ErrInvalid
	}
	return snapshot, nil
}

func (a *Authority) Current(request CurrentRequest, now time.Time) (CurrentResponse, error) {
	if a == nil {
		return CurrentResponse{}, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || request.Verify(a.binding, now) != nil || a.current.Generation < 1 || a.checkDiskLocked() != nil {
		return CurrentResponse{}, ErrInvalid
	}
	for nonce, expiry := range a.replays {
		if !expiry.After(now) {
			delete(a.replays, nonce)
		}
	}
	if _, duplicate := a.replays[request.Challenge]; duplicate || len(a.replays) >= 4096 {
		return CurrentResponse{}, ErrInvalid
	}
	deadline, _ := canonicalTime(request.Deadline)
	a.replays[request.Challenge] = deadline
	return SignCurrent(a.binding, request, CurrentRecord{Generation: a.current.Generation,
		Status: a.current.Status, SnapshotDigest: a.current.SnapshotDigest}, now, a.privateKey)
}

// Committed returns only the locally locked, still-on-disk high-water record.
// A caller must not infer live policy state from an unverified snapshot file.
func (a *Authority) Committed() (Ledger, error) {
	if a == nil {
		return Ledger{}, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.current.Generation < 1 || a.checkDiskLocked() != nil {
		return Ledger{}, ErrInvalid
	}
	return a.current, nil
}

func (a *Authority) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	clear(a.privateKey)
	if a.lockFile == nil {
		return nil
	}
	_ = syscall.Flock(int(a.lockFile.Fd()), syscall.LOCK_UN)
	return a.lockFile.Close()
}

func (a *Authority) checkDiskLocked() error {
	ledger, err := loadAuthorityLedger(a.ledgerPath, a.binding)
	if a.current.Generation == 0 && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || ledger.LedgerDigest != a.current.LedgerDigest || ledger.Generation != a.current.Generation {
		return ErrInvalid
	}
	return nil
}

func (l Ledger) CommittedAtIsZero() bool { return l.CommittedAt == "" }

func (l Ledger) digest() string {
	l.LedgerDigest = ""
	document, _ := json.Marshal(l)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/egress-policy-state-ledger/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (l Ledger) validate(binding Binding) error {
	committed, err := canonicalTime(l.CommittedAt)
	if l.Schema != ledgerSchema || l.EnvironmentDigest != binding.environmentDigest ||
		l.ProfileDigest != binding.profileDigest || l.PolicyID != binding.policyID ||
		l.PolicyRevision != binding.policyRevision || l.PolicyDigest != binding.policyDigest ||
		l.PrincipalDigest != binding.principalDigest || l.BrokerDigest != binding.brokerDigest ||
		l.Generation < 1 || (l.Status != "active" && l.Status != "revoked") ||
		!digestRegex.MatchString(l.SnapshotDigest) || err != nil || committed.IsZero() ||
		(l.Generation == 1 && l.PreviousDigest != "") ||
		(l.Generation > 1 && !digestRegex.MatchString(l.PreviousDigest)) || l.LedgerDigest != l.digest() {
		return ErrInvalid
	}
	return nil
}

func loadAuthorityLedger(path string, binding Binding) (Ledger, error) {
	document, err := secretfile.Read(path, MaxSnapshotBytes)
	if err != nil {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			return Ledger{}, os.ErrNotExist
		}
		return Ledger{}, ErrInvalid
	}
	defer clear(document)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var ledger Ledger
	if decoder.Decode(&ledger) != nil {
		return Ledger{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Ledger{}, ErrInvalid
	}
	canonical, err := json.Marshal(ledger)
	if err != nil || !bytes.Equal(canonical, document) || ledger.validate(binding) != nil {
		return Ledger{}, ErrInvalid
	}
	return ledger, nil
}

func validPrivatePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	parentPath := filepath.Dir(path)
	if !safeAncestorDirectories(parentPath) {
		return false
	}
	parent, err := os.Lstat(parentPath)
	stat, ok := parentSyscallStat(parent)
	return err == nil && ok && parent.IsDir() && parent.Mode()&os.ModeSymlink == 0 &&
		parent.Mode().Perm()&0o022 == 0 && stat.Uid == uint32(os.Getuid())
}

func parentSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func openAuthorityLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	stat, ok := parentSyscallStat(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		!ok || stat.Uid != uint32(os.Getuid()) ||
		syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func atomicWritePrivate(path string, document []byte) error {
	if !validPrivatePath(path) || len(document) < 1 || len(document) > MaxSnapshotBytes {
		return ErrInvalid
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".egress-policy-state-*")
	if err != nil {
		return ErrInvalid
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil || writeExact(temporary, document) != nil ||
		temporary.Sync() != nil || temporary.Close() != nil || os.Rename(temporaryPath, path) != nil {
		_ = temporary.Close()
		return ErrInvalid
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return ErrInvalid
	}
	defer directoryFile.Close()
	if directoryFile.Sync() != nil {
		return ErrInvalid
	}
	return nil
}

func writeExact(writer io.Writer, document []byte) error {
	for len(document) > 0 {
		count, err := writer.Write(document)
		if err != nil || count < 1 {
			return ErrInvalid
		}
		document = document[count:]
	}
	return nil
}
