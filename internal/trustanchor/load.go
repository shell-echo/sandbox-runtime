// Package trustanchor loads a profile-pinned, read-only CA bundle from one
// opened inode. It does not grant trust to an arbitrary path or certificate.
package trustanchor

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const maxBundleBytes = 256 << 10

// Load returns exactly the original bytes whose digest and CA records were
// checked. Callers pass these bytes onward; they must never reopen the path.
func Load(anchor phase6security.TrustAnchor, now time.Time) ([]byte, error) {
	if anchor.ID == "" || anchor.WriterAuthority != "operator" || anchor.BundleDigest == "" ||
		anchor.TargetPath == "" || !filepath.IsAbs(anchor.TargetPath) || filepath.Clean(anchor.TargetPath) != anchor.TargetPath || now.IsZero() {
		return nil, errors.New("invalid trust anchor binding")
	}
	parentPath := filepath.Dir(anchor.TargetPath)
	for directory := parentPath; directory != "/"; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("trust anchor parent is not a real directory")
		}
	}
	parent, err := os.Lstat(parentPath)
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 ||
		(ownedByUID(parent, uint32(os.Getuid())) && parent.Mode().Perm()&0o200 != 0) {
		return nil, errors.New("trust anchor parent is writable or unavailable")
	}
	before, err := os.Lstat(anchor.TargetPath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Mode().Perm()&0o222 != 0 || before.Size() < 1 || before.Size() > maxBundleBytes ||
		!ownedBy(before, anchor.OwnerUID, anchor.OwnerGID) {
		return nil, errors.New("trust anchor is not a bounded read-only artifact")
	}
	file, err := os.Open(anchor.TargetPath)
	if err != nil {
		return nil, errors.New("open trust anchor")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() ||
		opened.Mode().Perm()&0o222 != 0 || !ownedBy(opened, anchor.OwnerUID, anchor.OwnerGID) {
		return nil, errors.New("trust anchor changed while opening")
	}
	document, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil || len(document) != int(opened.Size()) || len(document) > maxBundleBytes {
		clear(document)
		return nil, errors.New("read trust anchor")
	}
	after, fileErr := os.Lstat(anchor.TargetPath)
	parentAfter, parentErr := os.Lstat(parentPath)
	if fileErr != nil || parentErr != nil || !os.SameFile(opened, after) || !os.SameFile(parent, parentAfter) ||
		after.Mode().Perm()&0o222 != 0 || !ownedBy(after, anchor.OwnerUID, anchor.OwnerGID) {
		clear(document)
		return nil, errors.New("trust anchor changed while reading")
	}
	digest := sha256.Sum256(document)
	if anchor.BundleDigest != "sha256:"+hex.EncodeToString(digest[:]) || strictBundle(document, now) != nil {
		clear(document)
		return nil, errors.New("trust anchor digest or CA bundle mismatch")
	}
	return document, nil
}

func strictBundle(document []byte, now time.Time) error {
	remaining, count := document, 0
	seen := make(map[[32]byte]bool)
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || count >= 32 {
			return errors.New("invalid CA bundle PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return errors.New("invalid CA certificate")
		}
		fingerprint := sha256.Sum256(block.Bytes)
		if seen[fingerprint] {
			return errors.New("duplicate CA certificate")
		}
		seen[fingerprint] = true
		count++
		remaining = rest
	}
	if count == 0 {
		return errors.New("empty CA bundle")
	}
	return nil
}

func ownedBy(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}

func ownedByUID(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}
