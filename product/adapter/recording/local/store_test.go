package local

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestEncryptedSegmentRoundTripIdempotencyTamperAndDelete(t *testing.T) {
	root := t.TempDir()
	store, err := New(root, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.CreateKeyReference(context.Background(), "rec_test")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("terminal payload must be encrypted")
	reference, err := store.PutSegment(context.Background(), "rec_test", key, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.PutSegment(context.Background(), "rec_test", key, 1, payload); err != nil || replay != reference {
		t.Fatalf("idempotent PutSegment()=%q,%v", replay, err)
	}
	if _, err := store.PutSegment(context.Background(), "rec_test", key, 1, []byte("different")); !errors.Is(err, product.ErrVersionConflict) {
		t.Fatalf("conflicting PutSegment() error=%v", err)
	}
	read, err := store.ReadSegment(context.Background(), "rec_test", key, 1, reference)
	if err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("ReadSegment()=%q,%v", read, err)
	}
	segmentPath, _ := store.segmentPath(reference)
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
	if _, err := store.ReadSegment(context.Background(), "rec_test", key, 1, reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("tampered segment error=%v", err)
	}
	if err := store.DeleteRecording(context.Background(), "rec_test"); err != nil {
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
}
