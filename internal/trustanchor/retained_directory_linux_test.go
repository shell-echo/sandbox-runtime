//go:build linux

package trustanchor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"golang.org/x/sys/unix"
)

func testDirectoryAnchor() phase6security.TrustAnchor {
	return phase6security.TrustAnchor{ID: "internal-server-ca", MountDirectory: "/run/trust/internal-server-ca",
		TargetPath: "/run/trust/internal-server-ca/bundle.pem", WriterAuthority: "operator",
		BundleDigest: "sha256:" + strings.Repeat("a", 64)}
}

func TestRetainedDirectoryBindingShape(t *testing.T) {
	a := testDirectoryAnchor()
	if !validDirectoryAnchor(a) {
		t.Fatal("fixed binding rejected")
	}
	for name, mutate := range map[string]func(*phase6security.TrustAnchor){
		"directory": func(a *phase6security.TrustAnchor) { a.MountDirectory += "-other" },
		"file":      func(a *phase6security.TrustAnchor) { a.TargetPath += "-other" },
		"owner":     func(a *phase6security.TrustAnchor) { a.OwnerUID = 1 },
		"writer":    func(a *phase6security.TrustAnchor) { a.WriterAuthority = "controller" },
		"digest":    func(a *phase6security.TrustAnchor) { a.BundleDigest = "sha256:" + strings.Repeat("A", 64) },
		"id":        func(a *phase6security.TrustAnchor) { a.ID = "../wrong" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := a
			mutate(&candidate)
			if validDirectoryAnchor(candidate) {
				t.Fatal("drifted binding accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if session, err := RetainDirectory(ctx, a, time.Now()); err == nil || session != nil {
		t.Fatal("canceled context accepted")
	}
}

func TestTrustMountInfoRequiresExactReadonlyMountAndNoNestedMount(t *testing.T) {
	const path = "/run/trust/internal-server-ca"
	const parent = "1 0 0:1 / / rw - tmpfs tmpfs rw\n"
	const mount = "22 1 0:2 / /run/trust/internal-server-ca ro,nosuid,nodev - ext4 /dev/sda ro\n"
	if !verifyTrustMountInfo([]byte(parent+mount), path, 22) {
		t.Fatal("exact read-only mount rejected")
	}
	for name, text := range map[string]string{
		"no mount":         parent,
		"wrong id":         parent + mount,
		"writable":         parent + strings.Replace(mount, " ro,nosuid", " rw,nosuid", 1),
		"duplicate target": parent + mount + "23 1 0:2 / /run/trust/internal-server-ca ro - ext4 /dev/sdb ro\n",
		"nested file":      parent + mount + "23 22 0:3 / /run/trust/internal-server-ca/bundle.pem ro - ext4 /dev/sdb ro\n",
		"duplicate id":     parent + mount + mount,
		"malformed":        parent + strings.TrimSuffix(mount, "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			id := uint64(22)
			if name == "wrong id" {
				id = 23
			}
			if verifyTrustMountInfo([]byte(text), path, id) {
				t.Fatal("unsafe mountinfo accepted")
			}
		})
	}
	if got, ok := decodeTrustMountField("/run/trust/a\\040b"); !ok || got != "/run/trust/a b" {
		t.Fatal("mountinfo escaping failed")
	}
	if _, ok := decodeTrustMountField("/run/trust/a\\000b"); ok {
		t.Fatal("unknown mountinfo escape accepted")
	}
}

func TestReadRetainedBundleBoundedAndCancelable(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	document := []byte("original bytes")
	if _, err := f.Write(document); err != nil {
		t.Fatal(err)
	}
	got, err := readRetainedBundle(context.Background(), int(f.Fd()), int64(len(document)))
	if err != nil || string(got) != string(document) {
		t.Fatalf("retained bytes: %v", err)
	}
	clear(got)
	for _, size := range []int64{0, maxBundleBytes + 1, int64(len(document) - 1), int64(len(document) + 1)} {
		if _, err := readRetainedBundle(context.Background(), int(f.Fd()), size); err == nil {
			t.Fatalf("unsafe size %d accepted", size)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readRetainedBundle(ctx, int(f.Fd()), int64(len(document))); err == nil {
		t.Fatal("canceled read accepted")
	}
}

func TestRetainedDirectoryRejectsExtraEntryAndPoisonsFailedSession(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(path+"/bundle.pem", []byte("bundle"), 0o444); err != nil {
		t.Fatal(err)
	}
	dir, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file, err := unix.Openat(dir, "bundle.pem", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(dir)
		t.Fatal(err)
	}
	s := &DirectorySession{directory: dir, file: file, path: path, digest: "sha256:" + strings.Repeat("0", 64), initialized: true}
	if err := soleBundleEntry(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"/extra", []byte("extra"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := soleBundleEntry(dir); err == nil {
		t.Fatal("extra directory entry accepted")
	}
	if _, err := s.Observe(context.Background(), time.Now()); err == nil || !s.closed || s.file != -1 || s.directory != -1 {
		t.Fatal("failed session did not poison and release descriptors")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedDirectoryZeroValueDoesNotCloseStdin(t *testing.T) {
	var before, after unix.Stat_t
	if err := unix.Fstat(0, &before); err != nil {
		t.Fatal(err)
	}
	var s DirectorySession
	if _, err := s.Observe(context.Background(), time.Now()); err == nil {
		t.Fatal("zero session")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(0, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("zero session closed unrelated descriptor")
	}
}
