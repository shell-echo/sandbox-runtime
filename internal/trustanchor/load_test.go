package trustanchor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testBundle(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "pinned test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testAnchorFile(t *testing.T, document []byte) phase6security.TrustAnchor {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "root.pem")
	if err := os.WriteFile(file, document, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	digest := sha256.Sum256(document)
	return phase6security.TrustAnchor{ID: "test-root", BundleDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Purpose: "server_verification", TrustDomain: "sandbox-runtime.test", ArtifactID: "test-root-artifact",
		StorageID: "test-root-storage", TargetPath: file, WriterAuthority: "operator",
		OwnerUID: uint32(os.Getuid()), OwnerGID: uint32(os.Getgid()), Consumers: []string{"browser-runtime-role"}}
}

func TestLoadPinnedReadOnlyCABundle(t *testing.T) {
	document := testBundle(t)
	anchor := testAnchorFile(t, document)
	loaded, err := Load(anchor, time.Now())
	if err != nil || !bytes.Equal(loaded, document) {
		t.Fatalf("pinned bundle: %v", err)
	}
	clear(loaded)
}

func TestLoadRejectsBundleSubstitutionAndUnsafeSource(t *testing.T) {
	document := testBundle(t)
	for name, change := range map[string]func(*testing.T, *phase6security.TrustAnchor){
		"digest drift": func(_ *testing.T, anchor *phase6security.TrustAnchor) {
			anchor.BundleDigest = "sha256:" + hex.EncodeToString(make([]byte, 32))
		},
		"owner drift": func(_ *testing.T, anchor *phase6security.TrustAnchor) { anchor.OwnerUID++ },
		"writable file": func(t *testing.T, anchor *phase6security.TrustAnchor) {
			if err := os.Chmod(anchor.TargetPath, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"writable parent": func(t *testing.T, anchor *phase6security.TrustAnchor) {
			if err := os.Chmod(filepath.Dir(anchor.TargetPath), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, anchor *phase6security.TrustAnchor) {
			directory := filepath.Dir(anchor.TargetPath)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(anchor.TargetPath, filepath.Join(directory, "real.pem")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.pem", anchor.TargetPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0o555); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			anchor := testAnchorFile(t, document)
			change(t, &anchor)
			if _, err := Load(anchor, time.Now()); err == nil {
				t.Fatal("unsafe CA artifact accepted")
			}
		})
	}
	for name, unsafe := range map[string][]byte{
		"duplicate CA":   append(append([]byte(nil), document...), document...),
		"trailing bytes": append(append([]byte(nil), document...), []byte("junk")...),
		"extra root":     append(append([]byte(nil), document...), testBundle(t)...),
	} {
		t.Run(name, func(t *testing.T) {
			anchor := testAnchorFile(t, unsafe)
			if name == "extra root" {
				digest := sha256.Sum256(document)
				anchor.BundleDigest = "sha256:" + hex.EncodeToString(digest[:])
			}
			if _, err := Load(anchor, time.Now()); err == nil {
				t.Fatal("unsafe CA document accepted")
			}
		})
	}
}
