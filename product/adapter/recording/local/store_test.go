package local

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestEncryptedSegmentRoundTripIdempotencyTamperAndDelete(t *testing.T) {
	root := t.TempDir()
	store, err := New(root, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.CreateKeyReference(context.Background(), "tenant_a", "rec_test")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("terminal payload must be encrypted")
	reference, err := store.PutSegment(context.Background(), "tenant_a", "rec_test", key, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.PutSegment(context.Background(), "tenant_a", "rec_test", key, 1, payload); err != nil || replay != reference {
		t.Fatalf("idempotent PutSegment()=%q,%v", replay, err)
	}
	if _, err := store.PutSegment(context.Background(), "tenant_a", "rec_test", key, 1, []byte("different")); !errors.Is(err, product.ErrVersionConflict) {
		t.Fatalf("conflicting PutSegment() error=%v", err)
	}
	read, err := store.ReadSegment(context.Background(), "tenant_a", "rec_test", key, 1, reference)
	if err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("ReadSegment()=%q,%v", read, err)
	}
	segmentPath, ok := store.segmentPath("tenant_a", "rec_test", reference)
	if !ok {
		t.Fatal("segment path was rejected")
	}
	ciphertext, err := os.ReadFile(segmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, payload) || bytes.Contains(ciphertext, []byte(key)) {
		t.Fatal("recording segment exposed plaintext or key reference")
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if err := os.WriteFile(segmentPath, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadSegment(context.Background(), "tenant_a", "rec_test", key, 1, reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("tampered segment error=%v", err)
	}
	if err := store.DeleteRecording(context.Background(), "tenant_a", "rec_test", key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(segmentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted segment stat error=%v", err)
	}
}

func TestStoreRejectsSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "recordings")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("New(symlink) error=%v", err)
	}

	rootWithLinkedStorage := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(rootWithLinkedStorage, "recordings")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(rootWithLinkedStorage, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("New(linked storage directory) error=%v", err)
	}
}

func TestStoreRejectsSymlinkRecordingDirectory(t *testing.T) {
	root := t.TempDir()
	store, err := New(root, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.CreateKeyReference(context.Background(), "tenant_a", "rec_a")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), store.recordingDirectory("tenant_a", "rec_a")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSegment(context.Background(), "tenant_a", "rec_a", key, 1, []byte("payload")); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("PutSegment(linked recording directory) error=%v", err)
	}
	if err := store.DeleteRecording(context.Background(), "tenant_a", "rec_a", key); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("DeleteRecording(linked recording directory) error=%v", err)
	}
}

func TestStoreBindsKeyAndSegmentsToTenantAndRecording(t *testing.T) {
	store, err := New(t.TempDir(), bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.CreateKeyReference(context.Background(), "tenant_a", "rec_a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "rkey2:") || strings.HasPrefix(key, "rkey:") {
		t.Fatalf("key reference has unexpected format %q", key)
	}
	reference, err := store.PutSegment(context.Background(), "tenant_a", "rec_a", key, 1, []byte("tenant-a-payload"))
	if err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]func() error{
		"cross tenant put": func() error {
			_, putErr := store.PutSegment(context.Background(), "tenant_b", "rec_a", key, 1, []byte("substitution"))
			return putErr
		},
		"cross recording put": func() error {
			_, putErr := store.PutSegment(context.Background(), "tenant_a", "rec_b", key, 1, []byte("substitution"))
			return putErr
		},
		"cross tenant read": func() error {
			_, readErr := store.ReadSegment(context.Background(), "tenant_b", "rec_a", key, 1, reference)
			return readErr
		},
		"cross recording read": func() error {
			_, readErr := store.ReadSegment(context.Background(), "tenant_a", "rec_b", key, 1, reference)
			return readErr
		},
		"cross tenant delete": func() error {
			return store.DeleteRecording(context.Background(), "tenant_b", "rec_a", key)
		},
		"legacy handle": func() error {
			_, readErr := store.ReadSegment(context.Background(), "tenant_a", "rec_a", "rkey:"+strings.Repeat("A", 43), 1, reference)
			return readErr
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, product.ErrInvalid) {
				t.Fatalf("operation error = %v, want %v", err, product.ErrInvalid)
			}
		})
	}
	if payload, err := store.ReadSegment(context.Background(), "tenant_a", "rec_a", key, 1, reference); err != nil || string(payload) != "tenant-a-payload" {
		t.Fatalf("authorized read = %q, %v", payload, err)
	}
}
