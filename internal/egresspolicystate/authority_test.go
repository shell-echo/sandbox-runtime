package egresspolicystate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAuthorityLedgerCommitRestartAndFreshCurrent(t *testing.T) {
	binding, key, _ := stateFixture(t)
	root := privateTempDir(t)
	ledgerDirectory, snapshotDirectory := filepath.Join(root, "ledger"), filepath.Join(root, "snapshots")
	for _, path := range []string{ledgerDirectory, snapshotDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := AuthorityConfig{Binding: binding, LedgerPath: filepath.Join(ledgerDirectory, "ledger.json"),
		SnapshotPath: filepath.Join(snapshotDirectory, "current.json"), PrivateKey: key, Now: time.Now, AllowInitialize: true}
	authority, err := OpenAuthority(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAuthority(config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second writer acquired ledger lock: %v", err)
	}
	first, err := authority.Commit(0, "active", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	firstLedger, err := os.ReadFile(config.LedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Commit(0, "active", 10*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale CAS accepted: %v", err)
	}
	second, err := authority.Commit(1, "active", 10*time.Second)
	if err != nil || second.Generation != 2 || second.SnapshotDigest == first.SnapshotDigest {
		t.Fatalf("second commit = %#v, %v", second, err)
	}
	request, err := NewCurrentRequest(binding, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	response, err := authority.Current(request, time.Now().UTC())
	if err != nil || response.Verify(request, binding, time.Now().UTC()) != nil || CompareCurrent(second, response) != nil {
		t.Fatalf("current attestation = %#v, %v", response, err)
	}
	if _, err := authority.Current(request, time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("challenge replay accepted: %v", err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	config.AllowInitialize = false
	restarted, err := OpenAuthority(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	request, _ = NewCurrentRequest(binding, time.Now().UTC())
	response, err = restarted.Current(request, time.Now().UTC())
	if err != nil || response.Generation != 2 || CompareCurrent(first, response) == nil {
		t.Fatalf("restarted authority accepted old snapshot: %#v, %v", response, err)
	}
	if err := os.WriteFile(config.LedgerPath, firstLedger, 0o600); err != nil {
		t.Fatal(err)
	}
	request, _ = NewCurrentRequest(binding, time.Now().UTC())
	if _, err := restarted.Current(request, time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("live ledger rollback accepted: %v", err)
	}
}

func TestAuthorityCommittedRevocationBeatsStaleSnapshot(t *testing.T) {
	binding, key, _ := stateFixture(t)
	root := privateTempDir(t)
	ledgerDirectory, snapshotDirectory := filepath.Join(root, "ledger"), filepath.Join(root, "snapshots")
	for _, path := range []string{ledgerDirectory, snapshotDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := AuthorityConfig{Binding: binding, LedgerPath: filepath.Join(ledgerDirectory, "ledger.json"),
		SnapshotPath: filepath.Join(snapshotDirectory, "current.json"), PrivateKey: key, Now: time.Now, AllowInitialize: true}
	authority, err := OpenAuthority(config)
	if err != nil {
		t.Fatal(err)
	}
	active, err := authority.Commit(0, "active", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	activeDocument, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Commit(1, "revoked", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	// Model publication rollback after the ledger's durable revoked commit.
	if err := os.WriteFile(config.SnapshotPath, activeDocument, 0o600); err != nil {
		t.Fatal(err)
	}
	config.AllowInitialize = false
	restarted, err := OpenAuthority(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	request, _ := NewCurrentRequest(binding, time.Now().UTC())
	response, err := restarted.Current(request, time.Now().UTC())
	if err != nil || response.Status != "revoked" || CompareCurrent(active, response) == nil {
		t.Fatalf("revoked ledger did not defeat old active file: %#v, %v", response, err)
	}
	if _, err := restarted.Commit(2, "active", 10*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked policy reactivated: %v", err)
	}
}

func TestAuthorityMissingAndCorruptLedgerFailClosed(t *testing.T) {
	binding, key, _ := stateFixture(t)
	directory := privateTempDir(t)
	config := AuthorityConfig{Binding: binding, LedgerPath: filepath.Join(directory, "ledger.json"),
		SnapshotPath: filepath.Join(directory, "state.json"), PrivateKey: key, Now: time.Now}
	if _, err := OpenAuthority(config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("uninitialized authority accepted: %v", err)
	}
	config.AllowInitialize = true
	authority, err := OpenAuthority(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Commit(0, "active", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.LedgerPath, []byte(`{"schema":`), 0o600); err != nil {
		t.Fatal(err)
	}
	config.AllowInitialize = false
	if _, err := OpenAuthority(config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupt durable ledger accepted: %v", err)
	}
}

func TestAuthorityCurrentLinearizesWithRevocationAndRejectsOtherPolicy(t *testing.T) {
	binding, key, _ := stateFixture(t)
	directory := privateTempDir(t)
	authority, err := OpenAuthority(AuthorityConfig{Binding: binding,
		LedgerPath: filepath.Join(directory, "ledger.json"), SnapshotPath: filepath.Join(directory, "current.json"),
		PrivateKey: key, Now: time.Now, AllowInitialize: true})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	active, err := authority.Commit(0, "active", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	otherBinding := binding
	otherBinding.policyDigest = "sha256:" + repeatHex("f")
	otherRequest, err := NewCurrentRequest(otherBinding, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Current(otherRequest, time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("authority A signed policy B: %v", err)
	}
	var group sync.WaitGroup
	responses := make(chan CurrentResponse, 100)
	for range 100 {
		group.Add(1)
		go func() {
			defer group.Done()
			request, requestErr := NewCurrentRequest(binding, time.Now().UTC())
			if requestErr != nil {
				return
			}
			response, currentErr := authority.Current(request, time.Now().UTC())
			if currentErr == nil {
				responses <- response
			}
		}()
	}
	revoked, err := authority.Commit(1, "revoked", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	group.Wait()
	close(responses)
	count := 0
	for response := range responses {
		count++
		if (response.Generation == 1 && response.Status == "active" && response.SnapshotDigest == active.SnapshotDigest) ||
			(response.Generation == 2 && response.Status == "revoked" && response.SnapshotDigest == revoked.SnapshotDigest) {
			continue
		}
		t.Fatalf("nonlinearized Current response: %#v", response)
	}
	if count == 0 {
		t.Fatal("no concurrent Current response completed")
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(resolved, "p6-policy-ledger-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
