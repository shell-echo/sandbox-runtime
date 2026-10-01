package workloadpki

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Ledger struct {
	Schema       string              `json:"schema"`
	Revision     int64               `json:"revision"`
	QuiescedAt   *time.Time          `json:"quiesced_at,omitempty"`
	Certificates []CertificateRecord `json:"certificates"`
	Replays      []ReplayRecord      `json:"replays"`
}

type CertificateRecord struct {
	Serial            string    `json:"serial"`
	AgentID           string    `json:"agent_id"`
	RequesterDigest   string    `json:"requester_digest"`
	PolicyID          string    `json:"policy_id"`
	Principal         string    `json:"principal"`
	SubjectDigest     string    `json:"subject_digest"`
	IssuerRevision    string    `json:"issuer_revision"`
	CertificateDigest string    `json:"certificate_digest"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	IssuedAt          time.Time `json:"issued_at"`
	RevokedAt         time.Time `json:"revoked_at"`
	State             string    `json:"state"`
}

type ReplayRecord struct {
	Nonce      string    `json:"nonce"`
	ExpiresAt  time.Time `json:"expires_at"`
	AcceptedAt time.Time `json:"accepted_at"`
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
		clear(canonical)
		return Ledger{}, ErrUnavailable
	}
	clear(canonical)
	return ledger, nil
}

func saveLedger(path string, ledger Ledger) error {
	if !closedLedgerDirectory(path) || ledger.Schema != LedgerSchema || ledger.Revision < 1 || len(ledger.Certificates) > maxLedgerRecords || len(ledger.Replays) > maxLedgerRecords {
		return ErrUnavailable
	}
	document, err := json.Marshal(ledger)
	if err != nil || len(document) < 1 || len(document) > 8<<20 {
		return ErrUnavailable
	}
	defer clear(document)
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".workload-certificate-ledger-*")
	if err != nil {
		return ErrUnavailable
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil || writeLedger(temporary, document) != nil || temporary.Sync() != nil || temporary.Close() != nil || os.Rename(temporaryPath, path) != nil {
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

func (c *Controller) persist() error {
	previous := c.ledger.Revision
	c.ledger.Revision++
	if err := saveLedger(c.ledgerPath, c.ledger); err != nil {
		c.ledger.Revision = previous
		return err
	}
	return nil
}

func (c *Controller) validateLedger() error {
	if c.ledger.Schema != LedgerSchema || c.ledger.Revision < 1 || len(c.ledger.Certificates) > maxLedgerRecords || len(c.ledger.Replays) > maxLedgerRecords ||
		(c.ledger.QuiescedAt != nil && (c.ledger.QuiescedAt.IsZero() || c.ledger.QuiescedAt.After(c.now().UTC()))) {
		return ErrUnavailable
	}
	serials := make(map[string]struct{}, len(c.ledger.Certificates))
	for _, record := range c.ledger.Certificates {
		policy, ok := c.policies[record.PolicyID]
		if !ok || record.AgentID != policy.Requester.Name || record.RequesterDigest != policy.Requester.Digest() ||
			record.Principal != policy.Subject.Name || record.SubjectDigest != policy.Subject.Digest() || !serialPattern.MatchString(record.Serial) ||
			!revisionPattern.MatchString(record.IssuerRevision) || !digestPattern.MatchString(record.CertificateDigest) || record.NotBefore.IsZero() ||
			record.NotAfter.IsZero() || !record.NotAfter.After(record.NotBefore) || record.IssuedAt.IsZero() ||
			(record.State != certificateActive && record.State != certificateRevoked && record.State != certificateExpired) ||
			(record.State == certificateRevoked) != !record.RevokedAt.IsZero() {
			return ErrUnavailable
		}
		if _, duplicate := serials[record.Serial]; duplicate {
			return ErrUnavailable
		}
		serials[record.Serial] = struct{}{}
	}
	nonces := make(map[string]struct{}, len(c.ledger.Replays))
	for _, replay := range c.ledger.Replays {
		if !validNonce(replay.Nonce) || replay.ExpiresAt.IsZero() || replay.AcceptedAt.IsZero() || replay.ExpiresAt.Before(replay.AcceptedAt) {
			return ErrUnavailable
		}
		if _, duplicate := nonces[replay.Nonce]; duplicate {
			return ErrUnavailable
		}
		nonces[replay.Nonce] = struct{}{}
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

func writeLedger(file *os.File, document []byte) error {
	for len(document) > 0 {
		count, err := file.Write(document)
		if err != nil {
			return err
		}
		document = document[count:]
	}
	return nil
}

func certificateDigest(document []byte) string {
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
}
