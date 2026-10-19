//go:build linux && integration

package controlbootstrap

import (
	"context"
	"encoding/json"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Executed in a real non-root Linux container by the operator harness. Only
// this test process assigns the test pin; no production config/env override.
func TestControlBootstrapSealedFDProcess(t *testing.T) {
	path := os.Getenv("CONTROL_BOOTSTRAP_TEST_PROFILE")
	if path == "" {
		t.Skip("private real-Linux fixture required")
	}
	if kind := os.Getenv("CONTROL_BOOTSTRAP_TEST_CHILD"); kind != "" {
		publicKeyPin = os.Getenv("CONTROL_BOOTSTRAP_TEST_PIN")
		if kind == "wrong-pin" {
			publicKeyPin = "sha256:" + strings.Repeat("f", 64)
		}
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		fd := uintptr(3)
		if kind == "wrong-fd" {
			fd = 4
		}
		r, e := Verify(context.Background(), data, os.NewFile(fd, "operator-key"))
		if kind == "positive" {
			if e != nil || r.Admission != "held-not-a-permit" {
				t.Fatal("real bootstrap", e)
			}
		} else if e == nil {
			t.Fatal("unsafe bootstrap accepted")
		}
		return
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var p phase6security.ProfileV2
	if json.Unmarshal(data, &p) != nil {
		t.Fatal("fixture")
	}
	key, e := os.ReadFile(os.Getenv("CONTROL_BOOTSTRAP_TEST_KEY"))
	if e != nil || len(key) != 32 {
		t.Fatal("test public key")
	}
	for _, kind := range []string{"positive", "wrong-pin", "wrong-fd", "unsealed", "legacy-pipe"} {
		t.Run(kind, func(t *testing.T) {
			fd, e := unix.MemfdCreate("real-bootstrap-test", unix.MFD_ALLOW_SEALING)
			if e != nil {
				t.Fatal(e)
			}
			f := os.NewFile(uintptr(fd), "public-key")
			defer f.Close()
			if f.Chmod(0600) != nil {
				t.Fatal("mode")
			}
			if _, e = f.Write(key); e != nil {
				t.Fatal(e)
			}
			_, _ = f.Seek(0, 0)
			if kind != "unsealed" {
				if _, e := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); e != nil {
					t.Fatal(e)
				}
			}
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(exe, "-test.run=^TestControlBootstrapSealedFDProcess$")
			cmd.Env = append(os.Environ(), "CONTROL_BOOTSTRAP_TEST_CHILD="+kind)
			cmd.ExtraFiles = []*os.File{f}
			if kind == "wrong-fd" {
				dummy, e := os.Open(os.DevNull)
				if e != nil {
					t.Fatal(e)
				}
				defer dummy.Close()
				cmd.ExtraFiles = []*os.File{dummy, f}
			}
			if kind == "legacy-pipe" {
				r, w, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				defer w.Close()
				cmd.ExtraFiles = []*os.File{r}
			}
			out, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("%s: %s %v", kind, out, e)
			}
		})
	}
}
