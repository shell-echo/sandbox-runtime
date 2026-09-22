package workloadcredential

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	leaseActive  = "active"
	leaseRevoked = "revoked"
	leaseExpired = "expired"
)

type Ledger struct {
	Schema   string         `json:"schema"`
	Revision int64          `json:"revision"`
	Leases   []LeaseRecord  `json:"leases"`
	Replays  []ReplayRecord `json:"replays"`
}

type LeaseRecord struct {
	LeaseID                string            `json:"lease_id"`
	AgentID                string            `json:"agent_id"`
	Role                   secretref.Role    `json:"role"`
	Purpose                secretref.Purpose `json:"purpose"`
	PolicyID               string            `json:"policy_id"`
	BindingDigest          string            `json:"binding_digest"`
	BackendID              string            `json:"backend_id"`
	BackendLeaseID         string            `json:"backend_lease_id"`
	PreviousBackendLeaseID string            `json:"previous_backend_lease_id"`
	CredentialDigest       string            `json:"credential_digest"`
	IssuedAt               time.Time         `json:"issued_at"`
	ExpiresAt              time.Time         `json:"expires_at"`
	PreviousRevokeAt       time.Time         `json:"previous_revoke_at"`
	RevokedAt              time.Time         `json:"revoked_at"`
	Revision               int64             `json:"revision"`
	Renewable              bool              `json:"renewable"`
	Migration              bool              `json:"migration"`
	State                  string            `json:"state"`
}

type ReplayRecord struct {
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

func loadLedger(path string) (Ledger, error) {
	if !validLedgerPath(path) {
		return Ledger{}, ErrUnavailable
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Ledger{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) || info.Size() < 1 || info.Size() > 4<<20 {
		return Ledger{}, ErrUnavailable
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return Ledger{}, ErrUnavailable
	}
	defer clear(document)
	var ledger Ledger
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ledger) != nil {
		return Ledger{}, ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Ledger{}, ErrUnavailable
	}
	canonical, err := json.Marshal(ledger)
	if err != nil || !bytes.Equal(document, canonical) {
		return Ledger{}, ErrUnavailable
	}
	clear(canonical)
	return ledger, nil
}

func saveLedger(path string, ledger Ledger) error {
	if !validLedgerPath(path) || ledger.Schema != LedgerSchema || ledger.Revision < 1 || len(ledger.Leases) > maxLedgerItems || len(ledger.Replays) > maxLedgerItems {
		return ErrUnavailable
	}
	document, err := json.Marshal(ledger)
	if err != nil || len(document) > 4<<20 {
		return ErrUnavailable
	}
	defer clear(document)
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".workload-credential-ledger-*")
	if err != nil {
		return ErrUnavailable
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil || writeAll(temporary, document) != nil || temporary.Sync() != nil || temporary.Close() != nil || os.Rename(temporaryPath, path) != nil {
		_ = temporary.Close()
		return ErrUnavailable
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return ErrUnavailable
	}
	defer directoryHandle.Close()
	if directoryHandle.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func validLedgerPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 && ownedByCurrentUser(info)
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid()) && stat.Gid == uint32(os.Getgid())
}

func writeAll(file *os.File, document []byte) error {
	for len(document) > 0 {
		count, err := file.Write(document)
		if err != nil {
			return err
		}
		document = document[count:]
	}
	return nil
}

func (c *Controller) validateLedger() error {
	if c.ledger.Schema != LedgerSchema || c.ledger.Revision < 1 || len(c.ledger.Leases) > maxLedgerItems || len(c.ledger.Replays) > maxLedgerItems {
		return ErrUnavailable
	}
	leaseIDs := make(map[string]struct{}, len(c.ledger.Leases))
	for _, lease := range c.ledger.Leases {
		policy, ok := c.policies[lease.PolicyID]
		if !ok || !leasePattern.MatchString(lease.LeaseID) || !leaseMatchesPolicy(lease, policy) || !backendLeasePattern.MatchString(lease.BackendLeaseID) ||
			!validDigest(lease.CredentialDigest) || lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() || lease.ExpiresAt.Before(lease.IssuedAt) ||
			lease.Revision < 1 || (lease.State != leaseActive && lease.State != leaseRevoked && lease.State != leaseExpired) {
			return ErrUnavailable
		}
		if _, duplicate := leaseIDs[lease.LeaseID]; duplicate {
			return ErrUnavailable
		}
		leaseIDs[lease.LeaseID] = struct{}{}
	}
	for _, replay := range c.ledger.Replays {
		if !validJTI(replay.JTI) || replay.ExpiresAt.IsZero() {
			return ErrUnavailable
		}
	}
	return nil
}
