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
	ledgerDirectory := filepath.Join(root, "ledger")
	for _, path := range []string{ledgerDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := AuthorityConfig{Binding: binding, LedgerPath: filepath.Join(ledgerDirectory, "ledger.json"),
		PrivateKey: key, Now: time.Now, AllowInitialize: true}
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

func TestAuthorityCommittedRevocationIgnoresStaleAuditFile(t *testing.T) {
	binding, key, _ := stateFixture(t)
	root := privateTempDir(t)
	ledgerDirectory := filepath.Join(root, "ledger")
	for _, path := range []string{ledgerDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := AuthorityConfig{Binding: binding, LedgerPath: filepath.Join(ledgerDirectory, "ledger.json"),
		PrivateKey: key, Now: time.Now, AllowInitialize: true}
	authority, err := OpenAuthority(config)
	if err != nil {
		t.Fatal(err)
	}
	active, err := authority.Commit(0, "active", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(6 * time.Second)
	staleRequest, err := NewCurrentRequest(binding, future)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Current(staleRequest, future); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale active ledger still signed Current: %v", err)
	}
	if _, err := InspectRevoked(config.LedgerPath, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("active ledger produced revocation receipt: %v", err)
	}
	activeDocument, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Commit(1, "revoked", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	receipt, err := InspectRevoked(config.LedgerPath, binding)
	if err != nil || receipt.Status != "revoked" || receipt.Generation != 2 ||
		receipt.PolicyDigest != binding.policyDigest || receipt.LedgerDigest == "" {
		t.Fatalf("durable revocation receipt = %#v, %v", receipt, err)
	}
	terminalRequest, err := NewCurrentRequest(binding, future)
	if err != nil {
		t.Fatal(err)
	}
	terminalResponse, err := authority.Current(terminalRequest, future)
	if err != nil || terminalResponse.Status != "revoked" {
		t.Fatalf("terminal revoked state lost after active freshness window: %#v, %v", terminalResponse, err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	// A legacy signed active audit file is never an authorization source.
	if err := os.WriteFile(filepath.Join(ledgerDirectory, "current.json"), activeDocument, 0o600); err != nil {
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
		PrivateKey: key, Now: time.Now}
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

func TestFailedRevocationCommitNeverYieldsReceipt(t *testing.T) {
	binding, key, _ := stateFixture(t)
	directory := privateTempDir(t)
	ledgerPath := filepath.Join(directory, "ledger.json")
	authority, err := OpenAuthority(AuthorityConfig{Binding: binding, LedgerPath: ledgerPath,
		PrivateKey: key, Now: time.Now, AllowInitialize: true})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if _, err := authority.Commit(0, "active", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Commit(1, "revoked", 10*time.Second); !errors.Is(err, ErrInvalid) {
		_ = os.Chmod(directory, 0o700)
		t.Fatalf("unwritable ledger accepted revocation: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRevoked(ledgerPath, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("failed revocation produced receipt: %v", err)
	}
}

func TestAuthorityCurrentLinearizesWithRevocationAndRejectsOtherPolicy(t *testing.T) {
	binding, key, _ := stateFixture(t)
	directory := privateTempDir(t)
	authority, err := OpenAuthority(AuthorityConfig{Binding: binding,
		LedgerPath: filepath.Join(directory, "ledger.json"),
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
