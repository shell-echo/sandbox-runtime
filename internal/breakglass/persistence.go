package breakglass

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func loadLedger(path string) (Ledger, error) {
	if !validPrivatePath(path) {
		return Ledger{}, ErrUnavailable
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Ledger{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) || info.Size() < 1 || info.Size() > 8<<20 {
		return Ledger{}, ErrUnavailable
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return Ledger{}, ErrUnavailable
	}
	defer clear(document)
	var ledger Ledger
	if decodeCanonical(document, &ledger) != nil {
		return Ledger{}, ErrUnavailable
	}
	return ledger, nil
}

func saveLedger(path string, ledger Ledger) error {
	if !validPrivatePath(path) || ledger.Schema != LedgerSchema || ledger.Revision < 1 || len(ledger.Requests) > maxRecords || len(ledger.Replays) > maxRecords {
		return ErrUnavailable
	}
	document, err := json.Marshal(ledger)
	if err != nil || len(document) > 8<<20 {
		return ErrUnavailable
	}
	defer clear(document)
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".break-glass-ledger-*")
	if err != nil {
		return ErrUnavailable
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil || writeAll(temporary, document) != nil || temporary.Sync() != nil || temporary.Close() != nil || os.Rename(temporaryPath, path) != nil {
		_ = temporary.Close()
		return ErrUnavailable
	}
	return syncDirectory(directory)
}

func initializeAudit(path string) error {
	if !validPrivatePath(path) {
		return ErrUnavailable
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrUnavailable
	}
	if file.Sync() != nil || file.Close() != nil {
		_ = file.Close()
		return ErrUnavailable
	}
	return syncDirectory(filepath.Dir(path))
}

func appendAudit(path string, entry AuditEntry) error {
	if !validAuditFile(path) || entry.Schema != AuditSchema || entry.Sequence < 1 || entry.EntryHash != auditDigest(entry) ||
		(entry.Sequence == 1 && entry.PreviousHash != "") || (entry.Sequence > 1 && !validDigest(entry.PreviousHash)) {
		return ErrUnavailable
	}
	document, err := json.Marshal(entry)
	if err != nil || len(document) > 32<<10 {
		return ErrUnavailable
	}
	defer clear(document)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	if writeAll(file, append(document, '\n')) != nil || file.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func verifyAudit(path string, wantCount int64, wantHead string) error {
	if !validAuditFile(path) {
		return ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4<<10), 32<<10)
	var count int64
	head := ""
	for scanner.Scan() {
		document := append([]byte(nil), scanner.Bytes()...)
		var entry AuditEntry
		if decodeCanonical(document, &entry) != nil || entry.Schema != AuditSchema || entry.Sequence != count+1 || entry.PreviousHash != head || entry.EntryHash != auditDigest(entry) {
			clear(document)
			return ErrUnavailable
		}
		clear(document)
		count, head = entry.Sequence, entry.EntryHash
	}
	if scanner.Err() != nil || count != wantCount || head != wantHead {
		return ErrUnavailable
	}
	return nil
}

func validPrivatePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(filepath.Dir(path))
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 && ownedByCurrentUser(info)
}

func validAuditFile(path string) bool {
	if !validPrivatePath(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 && ownedByCurrentUser(info) && info.Size() <= 64<<20
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid()) && stat.Gid == uint32(os.Getgid())
}

func decodeCanonical(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrDenied
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrDenied
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(document, canonical) {
		return ErrDenied
	}
	return nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		value = value[count:]
	}
	return nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return ErrUnavailable
	}
	defer handle.Close()
	if handle.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}
