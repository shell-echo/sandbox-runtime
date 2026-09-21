package desktopbroker

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
)

func TestBridgeReplayLedgerPersistsAcrossRestart(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "replay.json")
	now := time.Now().UTC()
	envelope := replayEnvelope(now.Add(time.Minute), "nonce-abcdefghijklmnopqrstuvwxyz123456")
	ledger, err := newBridgeReplayLedger(path, now)
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if ledger.claim(envelope) {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("concurrent replay acceptances = %d", accepted.Load())
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("replay ledger mode = %v, %v", info, err)
	}
	restarted, err := newBridgeReplayLedger(path, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if restarted.claim(envelope) {
		t.Fatal("replay was accepted after broker restart")
	}
	fresh := replayEnvelope(now.Add(time.Minute), "nonce-bcdefghijklmnopqrstuvwxyz1234567")
	if !restarted.claim(fresh) {
		t.Fatal("fresh bridge statement was rejected after broker restart")
	}
}

func TestBridgeReplayLedgerRejectsNonCanonicalOrUnsafeState(t *testing.T) {
	for name, document := range map[string]string{
		"unknown":   `{"version":1,"claims":[],"unknown":true}`,
		"duplicate": `{"version":1,"version":1,"claims":[]}`,
		"noncanonical": `{
"version": 1, "claims": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "replay.json")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := newBridgeReplayLedger(path, time.Now().UTC()); err == nil {
				t.Fatal("unsafe replay state was accepted")
			}
		})
	}
}

func TestBridgeReplayLedgerFailsClosedAtCapacityAndExpiry(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := newBridgeReplayLedger(filepath.Join(directory, "replay.json"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if ledger.claim(replayEnvelope(time.Now().UTC().Add(-time.Second), "nonce-expired-abcdefghijklmnopqrstuv")) {
		t.Fatal("expired bridge statement was accepted")
	}
	until := time.Now().UTC().Add(time.Minute)
	for index := 0; index < bridgeReplayMaxClaims; index++ {
		ledger.claimed["sha256:"+fixedReplayHex(index)] = until
	}
	if ledger.claim(replayEnvelope(until, "nonce-capacity-abcdefghijklmnopqrstu")) {
		t.Fatal("bridge statement was accepted beyond replay capacity")
	}
}

func replayEnvelope(expires time.Time, nonce string) *desktopbridge.Envelope {
	return &desktopbridge.Envelope{Statement: desktopbridge.Statement{
		Protocol:         desktopbridge.ProtocolID,
		Version:          desktopbridge.Version,
		Nonce:            nonce,
		ExecutorIdentity: "executor-desktop-1",
		ConnectionEpoch:  "epoch-1",
		HandoffExpiresAt: expires.UTC().Format(time.RFC3339Nano),
	}}
}

func fixedReplayHex(value int) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, 64)
	for index := range encoded {
		encoded[index] = '0'
	}
	for index := len(encoded) - 1; value > 0; index-- {
		encoded[index] = digits[value&15]
		value >>= 4
	}
	return string(encoded)
}
