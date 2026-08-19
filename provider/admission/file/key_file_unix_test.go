//go:build darwin || linux

package file_test

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	admissionfile "github.com/shell-echo/sandbox-runtime/provider/admission/file"
)

func TestLoadTrustedKeySourceRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := admissionfile.LoadTrustedKeySource([]admissionfile.TrustedKeyFile{{
		ID:        "key",
		Algorithm: admission.AlgorithmEdDSA,
		Path:      path,
	}}); err == nil {
		t.Fatal("LoadTrustedKeySource() accepted FIFO")
	}
}
