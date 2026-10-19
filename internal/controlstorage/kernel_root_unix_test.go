//go:build darwin || linux

package controlstorage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelStorageRejectsOrdinaryDirectoryWithoutMarker(t *testing.T) {
	p := storageRoot(t)
	if s, err := InitializeKernelChecked(t.Context(), p, testBinding()); err == nil {
		s.Close()
		t.Fatal("ordinary host directory admitted")
	}
	entries, err := os.ReadDir(p)
	if err != nil || len(entries) != 0 {
		t.Fatal("kernel refusal changed an unadmitted root")
	}
}

func TestKernelStorageNeverUpgradesOrDowngradesManifest(t *testing.T) {
	s, p := newStore(t)
	s.Close()
	before, err := os.ReadFile(filepath.Join(p, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenKernelChecked(p, testBinding()); err == nil {
		got.Close()
		t.Fatal("legacy namespace promoted")
	}
	after, _ := os.ReadFile(filepath.Join(p, manifestName))
	if string(before) != string(after) {
		t.Fatal("legacy manifest rewritten")
	}
	var m manifest
	if json.Unmarshal(before, &m) != nil {
		t.Fatal("fixture")
	}
	m.Kernel = &kernelRootIdentity{Protocol: kernelRootProtocol}
	forged, _ := json.Marshal(m)
	if os.WriteFile(filepath.Join(p, manifestName), forged, 0o600) != nil {
		t.Fatal("fixture")
	}
	if got, err := Open(p, testBinding()); err == nil {
		got.Close()
		t.Fatal("kernel mode silently stripped by legacy opener")
	}
	after, _ = os.ReadFile(filepath.Join(p, manifestName))
	if string(forged) != string(after) {
		t.Fatal("failed reopen repaired manifest")
	}
}
