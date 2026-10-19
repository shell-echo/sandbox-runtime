//go:build darwin || linux

package controlstorage

import (
	"context"
	"os"
	"testing"
)

func dedicatedTestBackend() DedicatedBackend {
	return DedicatedBackend{Protocol: DedicatedBackendProtocol, Device: "/dev/loop17", BackingFile: "/var/lib/docker/volumes/control-backing-test/_data/receipt.ext4", Bytes: DedicatedBackendBytes}
}

func TestDedicatedBackendRejectsOrdinaryRootWithoutWriting(t *testing.T) {
	p := storageRoot(t)
	if _, err := InitializeDedicated(t.Context(), p, testBinding(), dedicatedTestBackend()); err == nil {
		t.Fatal("ordinary root accepted as dedicated backend")
	}
	names, err := os.ReadDir(p)
	if err != nil || len(names) != 0 {
		t.Fatal("failed admission mutated empty root", err)
	}
}

func TestDedicatedBackendCannotUpgradeLegacyOrSupplyObservation(t *testing.T) {
	p := storageRoot(t)
	b := testBinding()
	backend := dedicatedTestBackend()
	s, err := Initialize(t.Context(), p, b, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveDedicated(t.Context(), p, b, backend); err == nil {
		t.Fatal("legacy store produced dedicated observation")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p + "/namespace.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDedicated(p, b, backend); err == nil {
		t.Fatal("legacy namespace upgraded")
	}
	after, err := os.ReadFile(p + "/namespace.json")
	if err != nil || string(before) != string(after) {
		t.Fatal("legacy bytes changed")
	}
}

func TestDedicatedBackendRejectsUnsafeRequirements(t *testing.T) {
	for name, change := range map[string]func(*DedicatedBackend){
		"unbounded": func(b *DedicatedBackend) { b.Bytes = 0 }, "oversized": func(b *DedicatedBackend) { b.Bytes++ },
		"alias": func(b *DedicatedBackend) { b.Device = "/dev/../dev/loop17" }, "non loop": func(b *DedicatedBackend) { b.Device = "/dev/sda" },
		"ambiguous loop": func(b *DedicatedBackend) { b.Device = "/dev/loop017" }, "relative": func(b *DedicatedBackend) { b.BackingFile = "receipt.ext4" },
		"deleted": func(b *DedicatedBackend) { b.BackingFile += " (deleted)" }, "old protocol": func(b *DedicatedBackend) { b.Protocol = "old" },
	} {
		t.Run(name, func(t *testing.T) {
			b := dedicatedTestBackend()
			change(&b)
			if b.Validate() == nil {
				t.Fatal("unsafe requirement accepted")
			}
		})
	}
}
