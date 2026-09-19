package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestStoreResumesCommitsDeduplicatesAndReadsByDigest(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference := "staging:xfer_test"
	if err := store.EnsureStaging(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	if committed, err := store.Append(context.Background(), reference, 0, []byte("hello ")); err != nil || committed != 6 {
		t.Fatalf("Append() = %d, %v", committed, err)
	}
	if _, err := store.Append(context.Background(), reference, 0, []byte("replay")); !errors.Is(err, product.ErrVersionConflict) {
		t.Fatalf("stale Append() err=%v", err)
	}
	if committed, err := store.Append(context.Background(), reference, 6, []byte("world")); err != nil || committed != 11 {
		t.Fatalf("resumed Append() = %d, %v", committed, err)
	}
	digestBytes := sha256.Sum256([]byte("hello world"))
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	size, observed, err := store.Inspect(context.Background(), reference)
	if err != nil || size != 11 || observed != digest {
		t.Fatalf("Inspect() = %d, %s, %v", size, observed, err)
	}
	final, err := store.Commit(context.Background(), reference, digest, size)
	if err != nil || final != "blob:"+digest {
		t.Fatalf("Commit() = %q, %v", final, err)
	}
	chunk, eof, err := store.Read(context.Background(), final, 6, 10)
	if err != nil || !eof || string(chunk) != "world" {
		t.Fatalf("Read() = %q, %v, %v", chunk, eof, err)
	}
	opened, err := store.Open(context.Background(), "tenant-test", "wrk-test", "rev-test", digest, size)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := io.ReadAll(opened)
	closeErr := opened.Close()
	if err != nil || closeErr != nil || string(materialized) != "hello world" {
		t.Fatalf("Open() = %q, read=%v close=%v", materialized, err, closeErr)
	}
	if _, err := store.Open(context.Background(), "tenant-test", "wrk-test", "rev-test", digest, size+1); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("Open(wrong size) err=%v", err)
	}
	second := "staging:xfer_second"
	_ = store.EnsureStaging(context.Background(), second)
	_, _ = store.Append(context.Background(), second, 0, []byte("hello world"))
	deduplicated, err := store.Commit(context.Background(), second, digest, size)
	if err != nil || deduplicated != final {
		t.Fatalf("deduplicated Commit() = %q, %v", deduplicated, err)
	}
}

func TestStoreRejectsSymlinkRootAndDigestMismatchAndDeletesStaging(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "blob-root")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("New(symlink) err=%v", err)
	}
	store, _ := New(root)
	reference := "staging:xfer_delete"
	_ = store.EnsureStaging(context.Background(), reference)
	_, _ = store.Append(context.Background(), reference, 0, []byte("payload"))
	wrong := "sha256:" + strings.Repeat("0", 64)
	if _, err := store.Commit(context.Background(), reference, wrong, 7); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("digest mismatch err=%v", err)
	}
	if err := store.Delete(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Inspect(context.Background(), reference); err == nil {
		t.Fatal("deleted staging object remains readable")
	}
}
