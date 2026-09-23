package egresspolicystate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMonitorRequiresInitialStateAndDrainsOnSignedRevocation(t *testing.T) {
	binding, key, _ := stateFixture(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	initial := signedDocument(t, binding, key, 1, time.Now().UTC(), "active")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	monitor, err := NewMonitor(binding, path, 50*time.Millisecond, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Run(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("uninitialized monitor error = %v", err)
	}
	if err := monitor.Initial(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx) }()
	active := signedDocument(t, binding, key, 2, time.Now().UTC(), "active")
	writeStateAtomically(t, path, active)
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("higher active generation stopped monitor: %v", err)
	default:
	}
	revoked := signedDocument(t, binding, key, 3, time.Now().UTC(), "revoked")
	writeStateAtomically(t, path, revoked)
	select {
	case err := <-done:
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("revocation error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("signed revocation was not observed before deadline")
	}
}

func TestMonitorFailsClosedOnMissingAndExpiredState(t *testing.T) {
	binding, key, _ := stateFixture(t)
	for _, scenario := range []string{"missing", "expired", "partial"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			initial := signedDocument(t, binding, key, 1, time.Now().UTC(), "active")
			if err := os.WriteFile(path, initial, 0o600); err != nil {
				t.Fatal(err)
			}
			monitor, err := NewMonitor(binding, path, 50*time.Millisecond, time.Now)
			if err != nil || monitor.Initial() != nil {
				t.Fatalf("initial state = %v, %v", monitor, err)
			}
			switch scenario {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "expired":
				monitor.now = func() time.Time { return time.Now().Add(31 * time.Second) }
			case "partial":
				writeStateAtomically(t, path, []byte(`{"protocol":`))
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := monitor.Run(ctx); !errors.Is(err, ErrInvalid) {
				t.Fatalf("fail-closed monitor error = %v", err)
			}
		})
	}
}

func writeStateAtomically(t *testing.T, path string, document []byte) {
	t.Helper()
	temporary := path + ".next"
	if err := os.WriteFile(temporary, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}
