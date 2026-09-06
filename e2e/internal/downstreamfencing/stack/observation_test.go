package stack

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
	"golang.org/x/sys/unix"
)

func TestObservationWriterWritesOnlyBoundedMetadataAndContinuesSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress-observations.jsonl")
	first, err := newObservationWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Observe(transport.Observation{
		Type: transport.ObservationActionRead, Result: transport.ObservationResultComplete,
		MessageType: transport.ObservationMessageText, Bytes: 37,
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := newObservationWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Observe(transport.Observation{
		Type: transport.ObservationActionForwarded, Result: transport.ObservationResultSucceeded,
		MessageType: transport.ObservationMessageText, Bytes: 37,
	}); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("observation mode = %v", info.Mode())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) > 2*maxObservationRecordBytes || strings.Contains(string(contents), "claim") ||
		strings.Contains(string(contents), "owner") || strings.Contains(string(contents), "payload") {
		t.Fatalf("observation output is not bounded sanitized metadata: %q", contents)
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("observation line count = %d", len(lines))
	}
	allowed := map[string]bool{
		"sequence": true, "type": true, "timestamp": true, "result": true, "message_type": true, "bytes": true,
	}
	for index, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if len(record) != len(allowed) || record["sequence"] != float64(index+1) {
			t.Fatalf("record %d = %#v", index, record)
		}
		for name := range record {
			if !allowed[name] {
				t.Fatalf("record contains non-allowlisted field %q", name)
			}
		}
		if _, err := time.Parse(time.RFC3339Nano, record["timestamp"].(string)); err != nil {
			t.Fatalf("record timestamp = %#v: %v", record["timestamp"], err)
		}
	}
}

func TestObservationWriterRejectsUnsafeOutputAndPollutedHistory(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "locked.jsonl")
	first, err := newObservationWriter(locked)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := newObservationWriter(locked); second != nil || err == nil {
		t.Fatalf("simultaneous writer accepted: %#v, %v", second, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := newObservationWriter(locked); err != nil {
		t.Fatal(err)
	} else if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	unsafeMode := filepath.Join(root, "unsafe-mode.jsonl")
	if err := os.WriteFile(unsafeMode, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if writer, err := newObservationWriter(unsafeMode); writer != nil || err == nil {
		t.Fatalf("group-readable output accepted: %#v, %v", writer, err)
	}

	target := filepath.Join(root, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink.jsonl")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if writer, err := newObservationWriter(symlink); writer != nil || err == nil {
		t.Fatalf("symlink output accepted: %#v, %v", writer, err)
	}

	fifo := filepath.Join(root, "fifo.jsonl")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := newObservationWriter(fifo)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO output was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO output blocked")
	}

	valid := `{"sequence":1,"type":"resolve","timestamp":"2026-09-06T01:02:03Z","result":"succeeded","message_type":"none","bytes":17}`
	oversizedFile := filepath.Join(root, "oversized-file.jsonl")
	if err := os.WriteFile(oversizedFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversizedFile, maxObservationFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if writer, err := newObservationWriter(oversizedFile); writer != nil || err == nil {
		t.Fatalf("oversized existing file accepted: %#v, %v", writer, err)
	}
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "partial final record", content: valid},
		{name: "identity field", content: strings.TrimSuffix(valid, "}") + `,"claim":"private"}` + "\n"},
		{name: "duplicate field", content: strings.Replace(valid, `"bytes":17`, `"bytes":17,"bytes":18`, 1) + "\n"},
		{name: "sequence gap", content: valid + "\n" + strings.Replace(valid, `"sequence":1`, `"sequence":3`, 1) + "\n"},
		{name: "oversized record", content: strings.Repeat("x", maxObservationRecordBytes+1) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-")+".jsonl")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if writer, err := newObservationWriter(path); writer != nil || err == nil {
				t.Fatalf("polluted history accepted: %#v, %v", writer, err)
			}
		})
	}
}

func TestObservationWriterRejectsInvalidMetadataWithoutAppending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress-observations.jsonl")
	writer, err := newObservationWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Observe(transport.Observation{
		Type: transport.ObservationActionRead, Result: transport.ObservationResultComplete,
		MessageType: transport.ObservationMessageType("credential"), Bytes: 1,
	}); err == nil {
		t.Fatal("invalid message type was accepted")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 0 {
		t.Fatalf("invalid observation was appended: %q", contents)
	}
}

func TestObservationWriterSerializesConcurrentRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress-observations.jsonl")
	writer, err := newObservationWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	const records = 64
	results := make(chan error, records)
	var group sync.WaitGroup
	for index := 0; index < records; index++ {
		group.Add(1)
		go func(size uint64) {
			defer group.Done()
			results <- writer.Observe(transport.Observation{
				Type: transport.ObservationActionRead, Result: transport.ObservationResultComplete,
				MessageType: transport.ObservationMessageBinary, Bytes: size,
			})
		}(uint64(index))
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := newObservationWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.sequence != records {
		t.Fatalf("reopened sequence = %d, want %d", reopened.sequence, records)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestObservationWriterPoisonsAfterWriteOrSyncFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		writeErr  error
		syncErr   error
		wantWrite int
		wantSync  int
	}{
		{name: "write", writeErr: errors.New("write failed"), wantWrite: 1},
		{name: "sync", syncErr: errors.New("sync failed"), wantWrite: 1, wantSync: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ingress-observations.jsonl")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			output := &failingObservationOutput{File: file, writeErr: test.writeErr, syncErr: test.syncErr}
			writer := &observationWriter{file: output}
			value := transport.Observation{
				Type: transport.ObservationActionRead, Result: transport.ObservationResultComplete,
				MessageType: transport.ObservationMessageText, Bytes: 1,
			}
			if err := writer.Observe(value); err == nil {
				t.Fatal("injected output failure was ignored")
			}
			if err := writer.Observe(value); err == nil {
				t.Fatal("poisoned writer accepted a later observation")
			}
			writes, syncs := output.counts()
			if writes != test.wantWrite || syncs != test.wantSync || writer.sequence != 0 {
				t.Fatalf("output calls = write %d sync %d, sequence %d", writes, syncs, writer.sequence)
			}
			if err := writer.Close(); err == nil {
				t.Fatal("Close() hid the terminal writer failure")
			}
		})
	}
}

func TestObservationWriterFailsClosedAtFileByteLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress-observations.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxObservationFileBytes - 1); err != nil {
		t.Fatal(err)
	}
	writer := &observationWriter{file: file}
	if err := writer.Observe(transport.Observation{
		Type: transport.ObservationResolve, Result: transport.ObservationResultSucceeded,
		MessageType: transport.ObservationMessageNone, Bytes: 1,
	}); err == nil {
		t.Fatal("writer appended past the file byte limit")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != maxObservationFileBytes-1 || writer.sequence != 0 {
		t.Fatalf("bounded writer size/sequence = %d/%d", info.Size(), writer.sequence)
	}
	if err := writer.Close(); err == nil {
		t.Fatal("Close() hid the terminal size failure")
	}
}

type failingObservationOutput struct {
	*os.File
	mu       sync.Mutex
	writes   int
	syncs    int
	writeErr error
	syncErr  error
}

func (f *failingObservationOutput) Write(value []byte) (int, error) {
	f.mu.Lock()
	f.writes++
	err := f.writeErr
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return f.File.Write(value)
}

func (f *failingObservationOutput) Sync() error {
	f.mu.Lock()
	f.syncs++
	err := f.syncErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.File.Sync()
}

func (f *failingObservationOutput) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes, f.syncs
}
