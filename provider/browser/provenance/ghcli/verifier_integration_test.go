//go:build integration

package ghcli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

// TestLockedPublicationIntegration verifies the attached OCI bundle and
// signer identity. It does not prove restricted egress or Browser composition.
func TestLockedPublicationIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BROWSER_PROVENANCE_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_BROWSER_PROVENANCE_INTEGRATION=1 to verify the locked Browser publication")
	}
	executable, err := exec.LookPath("gh")
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := digestExecutable(executable, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := New(Options{ExecutablePath: executable, ExecutableDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := verifier.Verify(ctx, browserimage.LockedPublication()); err != nil {
		t.Fatal(err)
	}
}
