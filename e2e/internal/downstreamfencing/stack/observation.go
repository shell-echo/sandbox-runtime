package stack

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
)

const (
	maxObservationRecordBytes = 512
	maxObservationFileBytes   = 16 << 20
)

type observationRecord struct {
	Sequence    uint64                           `json:"sequence"`
	Type        transport.ObservationType        `json:"type"`
	Timestamp   string                           `json:"timestamp"`
	Result      transport.ObservationResult      `json:"result"`
	MessageType transport.ObservationMessageType `json:"message_type"`
	Bytes       uint64                           `json:"bytes"`
}

type observationOutput interface {
	Write([]byte) (int, error)
	Sync() error
	Stat() (os.FileInfo, error)
	Close() error
}

type observationWriter struct {
	mu       sync.Mutex
	file     observationOutput
	sequence uint64
	failed   error
	closed   bool
}

func newObservationWriter(path string) (*observationWriter, error) {
	file, err := openPrivateAppendFile(path)
	if err != nil {
		return nil, err
	}
	sequence, err := readObservationSequence(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &observationWriter{file: file, sequence: sequence}, nil
}

func readObservationSequence(file *os.File) (uint64, error) {
	if file == nil {
		return 0, errors.New("private ingress observation file is unavailable")
	}
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() < 0 || info.Size() > maxObservationFileBytes {
		return 0, errors.New("private ingress observation file exceeds its byte limit")
	}
	if info.Size() > 0 {
		last := []byte{0}
		if _, err := file.ReadAt(last, info.Size()-1); err != nil || last[0] != '\n' {
			return 0, errors.New("private ingress observation file has a partial record")
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, maxObservationRecordBytes), maxObservationRecordBytes)
	var last uint64
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) == 0 || len(line) > maxObservationRecordBytes {
			return 0, errors.New("private ingress observation record is invalid")
		}
		record, err := decodeObservationRecord(line)
		if err != nil || record.Sequence != last+1 {
			return 0, errors.New("private ingress observation sequence is invalid")
		}
		last = record.Sequence
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return last, nil
}

func decodeObservationRecord(line []byte) (observationRecord, error) {
	if err := validateUniqueJSONFields(line); err != nil {
		return observationRecord{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var record observationRecord
	if err := decoder.Decode(&record); err != nil {
		return observationRecord{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return observationRecord{}, errors.New("private ingress observation has trailing input")
	}
	at, err := time.Parse(time.RFC3339Nano, record.Timestamp)
	if err != nil || at.IsZero() || record.Timestamp != at.UTC().Format(time.RFC3339Nano) {
		return observationRecord{}, errors.New("private ingress observation timestamp is invalid")
	}
	if err := transport.ValidateObservation(transport.Observation{
		Type: record.Type, Result: record.Result, MessageType: record.MessageType, Bytes: record.Bytes,
	}); err != nil {
		return observationRecord{}, err
	}
	return record, nil
}

func (w *observationWriter) Observe(value transport.Observation) error {
	if w == nil {
		return errors.New("private ingress observation writer is unavailable")
	}
	if err := transport.ValidateObservation(value); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("private ingress observation writer is closed")
	}
	if w.failed != nil {
		return w.failed
	}
	info, err := w.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		w.failed = errors.New("private ingress observation output is no longer a 0600 regular file")
		return w.failed
	}
	record := observationRecord{
		Sequence: w.sequence + 1, Type: value.Type, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Result: value.Result, MessageType: value.MessageType, Bytes: value.Bytes,
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded)+1 > maxObservationRecordBytes {
		w.failed = errors.New("encode bounded private ingress observation")
		return w.failed
	}
	encoded = append(encoded, '\n')
	if info.Size() > maxObservationFileBytes-int64(len(encoded)) {
		w.failed = errors.New("private ingress observation file exceeds its byte limit")
		return w.failed
	}
	written, err := w.file.Write(encoded)
	if err != nil || written != len(encoded) {
		w.failed = errors.New("write private ingress observation")
		return w.failed
	}
	if err := w.file.Sync(); err != nil {
		w.failed = errors.New("sync private ingress observation")
		return w.failed
	}
	w.sequence = record.Sequence
	return nil
}

func (w *observationWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return errors.Join(w.failed, w.file.Close())
}

var _ transport.Observer = (*observationWriter)(nil)
