//go:build integration

package dockercontrol

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

const codingRawOCIRecoveryArchiveEnv = "SANDBOX_RUNTIME_CODING_RAW_OCI_ARCHIVE"

// This opt-in test recovers the three exact public OCI metadata documents
// from one already-cached, private docker-save archive. It never opens Docker,
// creates a workload, or writes a synthesized/re-encoded descriptor. Existing
// fixture files are never overwritten.
func TestRecoverCodingRawOCIFixtureFromCachedArchive(t *testing.T) {
	archive := os.Getenv(codingRawOCIRecoveryArchiveEnv)
	if archive == "" {
		t.Skip("set " + codingRawOCIRecoveryArchiveEnv + " to one approved private archive")
	}
	info, err := os.Lstat(archive)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > 8<<30 {
		t.Fatal("archive is not a bounded private regular file")
	}
	publication := codingimage.LockedPublication()
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(archive,
		"registry", phase6security.ImageIdentityOCIIndex, publication.Image(), publication.Digest,
		"linux/arm64/v8", codingimage.PublishedARM64V8Digest)
	if err != nil || proof.ConfigDigest != codingimage.PublishedARM64ConfigDigest {
		t.Fatalf("cached OCI descriptor chain drift: %v", err)
	}
	if err := phase6security.VerifyOCIArchiveLayers(archive, documents.Manifest, documents.Config); err != nil {
		t.Fatalf("cached OCI layer chain drift: %v", err)
	}
	root := filepath.Join("testdata", "coding-oci-arm64-v8")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("fixture destination must be new: %v", err)
	}
	for _, item := range []struct {
		name string
		data []byte
	}{{"index.json", documents.Index}, {"manifest.json", documents.Manifest}, {"config.json", documents.Config}} {
		if len(item.data) < 1 || len(item.data) > 4<<20 {
			t.Fatal("unbounded descriptor document")
		}
		file, err := os.OpenFile(filepath.Join(root, item.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			t.Fatalf("fixture cannot overwrite existing file: %v", err)
		}
		written, writeErr := file.Write(item.data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || written != len(item.data) {
			t.Fatal("raw descriptor fixture write incomplete")
		}
	}
	t.Logf("recovered exact public arm64/v8 OCI metadata: index=%d manifest=%d config=%d proof=%s",
		len(documents.Index), len(documents.Manifest), len(documents.Config), proof.ProofDigest)
}
