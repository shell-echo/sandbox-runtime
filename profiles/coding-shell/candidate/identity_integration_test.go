//go:build integration

package candidate_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/profiles/coding-shell/candidate"
)

// Explicit private input availability and layer verification only. This does
// not rebuild, rescan, sign, or accept a runtime scenario on either platform.
func TestCandidateRetainedArchives(t *testing.T) {
	dir := os.Getenv("SANDBOX_RUNTIME_CODING_CANDIDATE_ARCHIVES")
	if dir == "" {
		t.Skip("explicit private candidate archive directory required")
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		t.Fatal("invalid private directory")
	}
	for platform, arch := range map[string]string{"linux/arm64/v8": "arm64", "linux/amd64": "amd64"} {
		t.Run(platform, func(t *testing.T) {
			i, err := candidate.LockedIdentity(platform)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "candidate-"+arch+"-a.oci.tar")
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 16<<20 {
				t.Fatal("invalid private archive")
			}
			checkBytes := func() {
				t.Helper()
				b, err := os.ReadFile(path)
				h := sha256.Sum256(b)
				if err != nil || "sha256:"+hex.EncodeToString(h[:]) != i.ArchiveDigest {
					t.Fatal("archive byte identity drift")
				}
			}
			checkBytes()
			d, proof, err := phase6security.ReadOCIArchiveDescriptorChain(path, "local", phase6security.ImageIdentityOCIManifest, i.ManifestDigest, i.ManifestDigest, platform, "")
			if err != nil || proof.ConfigDigest != i.ConfigDigest {
				t.Fatal("archive descriptor chain", err)
			}
			m, c, err := candidate.DescriptorDocuments(platform)
			if err != nil || !bytes.Equal(m, d.Manifest) || !bytes.Equal(c, d.Config) || len(d.Index) != 0 {
				t.Fatal("embedded records differ from original archive")
			}
			if err := phase6security.VerifyOCIArchiveLayers(path, d.Manifest, d.Config); err != nil {
				t.Fatal("actual layer/diffID chain", err)
			}
			checkBytes()
			t.Log("original archive, embedded descriptors and actual layer chain match; no fresh supply/runtime admission")
		})
	}
}
