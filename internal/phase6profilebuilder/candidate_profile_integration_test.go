//go:build integration

package phase6profilebuilder

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This checks a retained real Desktop OCI candidate's effective broker bytes.
// A prior-revision candidate cannot satisfy the final same-source freeze.
func TestSlice6DesktopBrokerFromRealCandidateArchive(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_DESKTOP_BROKER_ARCHIVE_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_DESKTOP_BROKER_ARCHIVE_INTEGRATION=1")
	}
	path := os.Getenv("SANDBOX_RUNTIME_PHASE6_DESKTOP_CANDIDATE_PATH")
	if !cleanAbsolute(path) {
		t.Fatal("missing absolute Desktop candidate path")
	}
	candidate, err := desktopcandidate.LoadCurrent(path)
	if err != nil {
		t.Fatalf("current candidate archive verification: %v", err)
	}
	archive := path + ".oci.tar"
	documents, err := phase6security.ReadOCIArchiveDocuments(archive, candidate.ImageIdentityKind,
		candidate.ImageDigest, candidate.SelectedManifestDigest, candidate.ConfigDigest)
	if err != nil {
		t.Fatalf("selected Desktop descriptor: %v", err)
	}
	broker, err := phase6security.ReadVerifiedOCIArchiveDesktopBroker(archive, documents.Manifest, documents.Config)
	if err != nil || len(broker) < 1 {
		t.Fatalf("effective Desktop broker extraction: %v", err)
	}
	t.Logf("prior candidate %s broker executable %s (%d bytes)", candidate.SourceRevision,
		fmt.Sprintf("sha256:%x", sha256.Sum256(broker)), len(broker))
}
