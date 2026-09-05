package revoker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const maxControlRecordBytes = 16 << 10

type controlRecord struct {
	Sequence       uint64 `json:"sequence"`
	Type           string `json:"type"`
	Timestamp      string `json:"timestamp"`
	DurationMillis int64  `json:"duration_millis"`
}

type controlLog struct {
	mu       sync.Mutex
	file     *os.File
	buffer   *bufio.Writer
	sequence uint64
	closed   bool
}

func openControlLog(path string) (*controlLog, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("control log unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("control log unavailable")
	}
	sequence, err := readControlSequence(file)
	if err != nil {
		_ = file.Close()
		return nil, errors.New("control log unavailable")
	}
	return &controlLog{file: file, buffer: bufio.NewWriter(file), sequence: sequence}, nil
}

func readControlSequence(file *os.File) (uint64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxControlRecordBytes)
	var last uint64
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if !uniqueJSONFields(line) {
			return 0, errors.New("invalid control log")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(line, &fields); err != nil || len(fields) != 4 {
			return 0, errors.New("invalid control log")
		}
		for _, name := range []string{"sequence", "type", "timestamp", "duration_millis"} {
			if _, exists := fields[name]; !exists {
				return 0, errors.New("invalid control log")
			}
		}
		var record controlRecord
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil || record.Sequence != last+1 || record.Type != "revoke_committed" ||
			record.Timestamp == "" || record.DurationMillis < 0 {
			return 0, errors.New("invalid control log")
		}
		timestamp, err := time.Parse(time.RFC3339Nano, record.Timestamp)
		if err != nil || timestamp.UTC().Format(time.RFC3339Nano) != record.Timestamp {
			return 0, errors.New("invalid control log")
		}
		last = record.Sequence
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return last, nil
}

func (l *controlLog) appendCommitted(at time.Time, duration time.Duration) error {
	if l == nil {
		return errors.New("control log unavailable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("control log unavailable")
	}
	l.sequence++
	record := controlRecord{
		Sequence: l.sequence, Type: "revoke_committed", Timestamp: at.UTC().Format(time.RFC3339Nano),
		DurationMillis: max(duration.Milliseconds(), 0),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.New("control log unavailable")
	}
	if _, err := l.buffer.Write(append(encoded, '\n')); err != nil {
		return errors.New("control log unavailable")
	}
	if err := l.buffer.Flush(); err != nil {
		return errors.New("control log unavailable")
	}
	return nil
}

func (l *controlLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return errors.Join(l.buffer.Flush(), l.file.Close())
}
