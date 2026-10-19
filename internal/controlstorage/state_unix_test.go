//go:build darwin || linux

package controlstorage

import (
	"context"
	"sync"
	"testing"
)

func TestStorageStateSnapshotAndWholeNamespaceCAS(t *testing.T) {
	s, _ := newStore(t)
	empty, err := s.ReadState(t.Context(), key(1))
	if err != nil || empty.Found || empty.Revision != 1 || empty.Digest != "" || len(empty.Data) != 0 {
		t.Fatal("unexpected initial state", empty, err)
	}
	if err := s.CompareState(t.Context(), key(1), empty, []byte("Unknown")); err != nil {
		t.Fatal(err)
	}
	first, err := s.ReadState(t.Context(), key(1))
	if err != nil || !first.Found || first.Revision != 2 || string(first.Data) != "Unknown" {
		t.Fatal(first, err)
	}
	first.Data[0] = 'x'
	copy, err := s.ReadState(t.Context(), key(1))
	if err != nil || string(copy.Data) != "Unknown" {
		t.Fatal("snapshot aliases store")
	}
	if s.CompareState(t.Context(), key(1), empty, []byte("lost update")) == nil {
		t.Fatal("stale absent state accepted")
	}
	wrong := copy
	wrong.Digest = sum([]byte("wrong"))
	if s.CompareState(t.Context(), key(1), wrong, []byte("wrong hash")) == nil {
		t.Fatal("stale hash accepted")
	}
	if _, err := s.ReadState(t.Context(), key(2)); err == nil {
		t.Fatal("wrong state identity accepted")
	}
	if err := s.Put(t.Context(), Closure, key(2), []byte("closure evidence")); err != nil {
		t.Fatal(err)
	}
	if s.CompareState(t.Context(), key(1), copy, []byte("missed evidence")) == nil {
		t.Fatal("evidence mutation did not invalidate CAS")
	}
	latest, err := s.ReadState(t.Context(), key(1))
	if err != nil || latest.Revision != 3 || latest.Digest != copy.Digest {
		t.Fatal(latest, err)
	}
	if err := s.CompareState(t.Context(), key(1), latest, []byte("Unknown; Closed")); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.ReadState(cancelled, key(1)); err == nil {
		t.Fatal("cancelled read admitted")
	}
	if s.CompareState(cancelled, key(1), latest, []byte("cancelled")) == nil {
		t.Fatal("cancelled write admitted")
	}
}

func TestStorageStateCASHasOneWinner(t *testing.T) {
	s, _ := newStore(t)
	snapshot, err := s.ReadState(t.Context(), key(1))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, value := range []string{"one", "two"} {
		workers.Go(func() { <-start; results <- s.CompareState(t.Context(), key(1), snapshot, []byte(value)) })
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d", winners)
	}
	actual, err := s.ReadState(t.Context(), key(1))
	if err != nil || !actual.Found || actual.Revision != 2 {
		t.Fatal(actual, err)
	}
}
