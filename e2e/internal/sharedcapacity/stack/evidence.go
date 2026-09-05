package stack

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

type evidenceWriter struct {
	mu       sync.Mutex
	file     *os.File
	buffer   *bufio.Writer
	sequence uint64
	closed   bool
}

func newEvidenceWriter(path string) (*evidenceWriter, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("evidence output must be a regular file")
	}
	sequence, err := readEvidenceSequence(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &evidenceWriter{file: file, buffer: bufio.NewWriter(file), sequence: sequence}, nil
}

func readEvidenceSequence(file *os.File) (uint64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var last uint64
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			return 0, errors.New("evidence output contains an empty record")
		}
		var record struct {
			Sequence uint64 `json:"sequence"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.Sequence != last+1 {
			return 0, errors.New("evidence output sequence is invalid")
		}
		last = record.Sequence
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return last, nil
}

func (w *evidenceWriter) append(build func(uint64) any) error {
	if w == nil || build == nil {
		return errors.New("evidence writer is unavailable")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("evidence writer is closed")
	}
	w.sequence++
	encoded, err := json.Marshal(build(w.sequence))
	if err != nil {
		return err
	}
	if _, err := w.buffer.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return w.buffer.Flush()
}

func (w *evidenceWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return errors.Join(w.buffer.Flush(), w.file.Close())
}

type auditRecord struct {
	Sequence   uint64                 `json:"sequence"`
	Type       gateway.AuditEventType `json:"type"`
	Timestamp  string                 `json:"timestamp"`
	Attempt    int                    `json:"attempt"`
	Frames     uint64                 `json:"frames"`
	Bytes      uint64                 `json:"bytes"`
	ReasonCode string                 `json:"reason_code"`
}

type auditRecorder struct{ writer *evidenceWriter }

func (r *auditRecorder) Record(ctx context.Context, event gateway.AuditEvent) error {
	if r == nil || r.writer == nil || ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	at := event.At.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	reasonCode, ok := auditReasonCode(event.Type)
	if !ok {
		return errors.New("unsupported Gateway audit event")
	}
	return r.writer.append(func(sequence uint64) any {
		return auditRecord{
			Sequence: sequence, Type: event.Type, Timestamp: at.Format(time.RFC3339Nano),
			Attempt: event.Attempt, Frames: event.Frames, Bytes: event.Bytes,
			ReasonCode: reasonCode,
		}
	})
}

func auditReasonCode(eventType gateway.AuditEventType) (string, bool) {
	switch eventType {
	case gateway.AuditAuthorized:
		return "authorized", true
	case gateway.AuditDenied:
		return "denied", true
	case gateway.AuditConnected:
		return "connected", true
	case gateway.AuditReconnected:
		return "reconnected", true
	case gateway.AuditBackendClosed:
		return "backend_closed", true
	case gateway.AuditRevoked:
		return "revoked", true
	case gateway.AuditExpired:
		return "expired", true
	case gateway.AuditClientClosed:
		return "client_closed", true
	case gateway.AuditReconnectFailed:
		return "reconnect_failed", true
	case gateway.AuditCapacityRejected:
		return "capacity_rejected", true
	case gateway.AuditCapacityUnavailable:
		return "capacity_unavailable", true
	case gateway.AuditCapacityLost:
		return "capacity_lost", true
	case gateway.AuditCapacityReleaseFailed:
		return "capacity_release_failed", true
	default:
		return "", false
	}
}

type observationRecord struct {
	Sequence uint64 `json:"sequence"`
	Kind     string `json:"kind"`
}

type observationRecorder struct{ writer *evidenceWriter }

func (r *observationRecorder) record(kind string) error {
	if r == nil || r.writer == nil || (kind != "resolve" && kind != "dial") {
		return errors.New("unsupported Gateway observation")
	}
	return r.writer.append(func(sequence uint64) any {
		return observationRecord{Sequence: sequence, Kind: kind}
	})
}
