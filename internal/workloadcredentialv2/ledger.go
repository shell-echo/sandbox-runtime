package workloadcredentialv2

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
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

type Ledger struct {
	Schema   string         `json:"schema"`
	Revision int64          `json:"revision"`
	Leases   []LeaseRecord  `json:"leases"`
	Replays  []ReplayRecord `json:"replays"`
}

type LeaseRecord struct {
	LeaseID                string                      `json:"lease_id"`
	Principal              securityprincipal.Principal `json:"principal"`
	PrincipalDigest        string                      `json:"principal_digest"`
	Purpose                secretref.Purpose           `json:"purpose"`
	PolicyID               string                      `json:"policy_id"`
	PolicyDigest           string                      `json:"policy_digest"`
	BackendID              string                      `json:"backend_id"`
	BackendPolicy          string                      `json:"backend_policy"`
	BindingDigest          string                      `json:"binding_digest"`
	BackendLeaseID         string                      `json:"backend_lease_id"`
	PreviousBackendLeaseID string                      `json:"previous_backend_lease_id"`
	CredentialDigest       string                      `json:"credential_digest"`
	IssuedAt               time.Time                   `json:"issued_at"`
	ExpiresAt              time.Time                   `json:"expires_at"`
	PreviousRevokeAt       time.Time                   `json:"previous_revoke_at"`
	RevokedAt              time.Time                   `json:"revoked_at"`
	Revision               int64                       `json:"revision"`
	Renewable              bool                        `json:"renewable"`
	State                  string                      `json:"state"`
}

type ReplayRecord struct {
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

func loadLedger(path string) (Ledger, error) {
	if !closedLedgerDirectory(path) {
		return Ledger{}, ErrUnavailable
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Ledger{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!ownedByCurrentUser(info) || info.Size() < 1 || info.Size() > 8<<20 {
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
	if err != nil || !bytes.Equal(canonical, document) {
		return Ledger{}, ErrUnavailable
	}
	return ledger, nil
}

func saveLedger(path string, ledger Ledger) error {
	if !closedLedgerDirectory(path) || ledger.Schema != LedgerSchema || ledger.Revision < 1 || len(ledger.Leases) > maxLedgerItems || len(ledger.Replays) > maxLedgerItems {
		return ErrUnavailable
	}
	document, err := json.Marshal(ledger)
	if err != nil || len(document) > 8<<20 {
		return ErrUnavailable
	}
	defer clear(document)
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".workload-credential-v2-ledger-*")
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
	return directoryHandle.Sync()
}

func (c *Controller) validateLedger() error {
	if c.ledger.Schema != LedgerSchema || c.ledger.Revision < 1 || len(c.ledger.Leases) > maxLedgerItems || len(c.ledger.Replays) > maxLedgerItems {
		return ErrUnavailable
	}
	leaseIDs, backendIDs := map[string]struct{}{}, map[string]struct{}{}
	for _, lease := range c.ledger.Leases {
		policy, ok := c.policies[lease.PolicyID]
		if !ok || !leasePattern.MatchString(lease.LeaseID) || policy.Registry.Validate(lease.Principal) != nil ||
			lease.PrincipalDigest != lease.Principal.Digest() || !leaseMatchesPolicy(lease, policy) || len(lease.BackendLeaseID) < 8 ||
			!validDigest(lease.CredentialDigest) || lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() || !lease.ExpiresAt.After(lease.IssuedAt) ||
			lease.Revision < 1 || (lease.State != leaseActive && lease.State != leaseRevoked && lease.State != leaseExpired) {
			return ErrUnavailable
		}
		if _, duplicate := leaseIDs[lease.LeaseID]; duplicate {
			return ErrUnavailable
		}
		if _, duplicate := backendIDs[lease.BackendLeaseID]; duplicate {
			return ErrUnavailable
		}
		leaseIDs[lease.LeaseID], backendIDs[lease.BackendLeaseID] = struct{}{}, struct{}{}
	}
	for _, replay := range c.ledger.Replays {
		if !validJTI(replay.JTI) || replay.ExpiresAt.IsZero() {
			return ErrUnavailable
		}
	}
	return nil
}

func validLedgerPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(filepath.Dir(path))
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 && ownedByCurrentUser(info)
}

// A crashed atomic replacement can leave its temporary inode behind. Never
// silently accumulate or remove that inode: recovery requires an operator to
// inspect the exact run-owned volume before this controller can resume.
func closedLedgerDirectory(path string) bool {
	if !validLedgerPath(path) {
		return false
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) > 1 {
		return false
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(path) {
			return false
		}
		info, err := os.Lstat(filepath.Join(filepath.Dir(path), entry.Name()))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
			!ownedByCurrentUser(info) || info.Size() < 1 || info.Size() > 8<<20 {
			return false
		}
	}
	return true
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
