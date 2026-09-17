//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

const realProcessTestLimit = 15 * time.Second

func buildStartupProbe(t *testing.T, mode string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "startup-probe")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-ldflags=-X main.mode="+mode, "-o", path, "./testdata/startupprobe")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build startup probe: %v\n%s", err, output)
	}
	// Do not inherit a platform/user-specific umask into the executable
	// admission fixture. Production intentionally rejects group-writable files.
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func startedStartupProbe(t *testing.T, mode string) (*FrozenPreflight, *StartedProcess, *protocol.Codec) {
	return startedStartupProbeContext(t, mode, context.Background())
}

func startedStartupProbeContext(t *testing.T, mode string, runContext context.Context) (*FrozenPreflight, *StartedProcess, *protocol.Codec) {
	t.Helper()
	codec, err := protocol.NewCodec(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	frozen, launch := preparedProbeContext(t, buildStartupProbe(t, mode), runContext)
	ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
	t.Cleanup(cancel)
	process, err := StartProcess(ctx, launch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Close() })
	return frozen, process, codec
}

func TestObserveStartupBindsRealProcessBeforeInput(t *testing.T) {
	_, process, codec := startedStartupProbe(t, "valid")
	ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
	defer cancel()
	identity, err := process.ObserveStartup(ctx, codec)
	if err != nil {
		t.Fatal(err)
	}
	if identity.ProtocolID != protocol.ProtocolID || identity.ProtocolVersion != protocol.ProtocolVersion ||
		identity.ProtocolSchemaDigest != protocol.ExpectedProtocolSchemaDigest || identity.ProtocolSemanticsDigest != protocol.ExpectedProtocolSemanticsDigest ||
		identity.ExpectedValuesInjectedByHarness || len(identity.CredentialChannels) != 1 || identity.CredentialChannels[0].Actor == nil ||
		*identity.CredentialChannels[0].Actor != "controller_a" || process.core.admission.Machine().State() != protocol.PhaseStateReadyForInvocation ||
		process.core.decoder == nil {
		t.Fatalf("wrong observed identity: %+v", identity)
	}
	// Returned values and copies cannot mutate the stored identity.
	*identity.CredentialChannels[0].Actor = "changed"
	identity.CredentialChannels[0].ChannelID = "changed"
	stored, ok := process.StartupIdentity()
	if !ok || stored.CredentialChannels[0].ChannelID != "controller-a-provider" || *stored.CredentialChannels[0].Actor != "controller_a" {
		t.Fatal("startup snapshot mutated")
	}
	*stored.CredentialChannels[0].Actor = "other"
	again, ok := process.StartupIdentity()
	if !ok || *again.CredentialChannels[0].Actor != "controller_a" {
		t.Fatal("stored actor pointer escaped")
	}
	if _, err := process.ObserveStartup(ctx, codec); err == nil || !errors.Is(err, ErrStartup) {
		t.Fatal("duplicate startup accepted", err)
	}
	select {
	case <-process.core.done:
	case <-time.After(7 * time.Second):
		t.Fatal("duplicate did not reclaim process")
	}
}

func TestObserveStartupRejectsInvalidFirstRecordAndReaps(t *testing.T) {
	for _, mode := range []string{"wrong-authority", "duplicate-channel", "non-startup", "malformed", "truncated-exit", "empty-exit"} {
		t.Run(mode, func(t *testing.T) {
			frozen, process, codec := startedStartupProbe(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
			defer cancel()
			identity, err := process.ObserveStartup(ctx, codec)
			if err == nil || !errors.Is(err, ErrStartup) || len(identity.CredentialChannels) != 0 {
				t.Fatal("invalid startup accepted", err)
			}
			if strings.Contains(err.Error(), "must-not-leak") {
				t.Fatal("startup error leaked raw output")
			}
			select {
			case <-process.core.done:
			case <-time.After(7 * time.Second):
				t.Fatal("invalid startup not reaped")
			}
			if _, ok := process.StartupIdentity(); ok {
				t.Fatal("failed startup retained identity")
			}
			if frozen.core.failure == nil {
				t.Fatal("failed startup did not revoke run")
			}
		})
	}
}

func TestObserveStartupCancellationAndBadInputs(t *testing.T) {
	for _, kind := range []string{"deadline", "canceled", "nil-context", "nil-codec", "closed", "copied-after-attempt"} {
		t.Run(kind, func(t *testing.T) {
			_, process, codec := startedStartupProbe(t, "delay")
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			switch kind {
			case "canceled":
				cancel()
			case "nil-context":
				ctx = nil
			case "nil-codec":
				codec = nil
			case "closed":
				_ = process.Close()
			case "copied-after-attempt":
				firstCtx, firstCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				_, _ = process.ObserveStartup(firstCtx, codec)
				firstCancel()
				copy := *process
				process = &copy
			}
			identity, err := process.ObserveStartup(ctx, codec)
			if err == nil || !errors.Is(err, ErrStartup) || len(identity.CredentialChannels) != 0 {
				t.Fatal("invalid startup input accepted", err)
			}
			select {
			case <-process.core.done:
			case <-time.After(7 * time.Second):
				t.Fatal("startup failure not reaped")
			}
		})
	}
	var zero StartedProcess
	if _, ok := zero.StartupIdentity(); ok {
		t.Fatal("zero process has identity")
	}
	if _, err := zero.ObserveStartup(context.Background(), nil); err != ErrStartup {
		t.Fatal(err)
	}
	if _, err := (processOutput{}).Read(make([]byte, 1)); !errors.Is(err, ErrProcessIO) {
		t.Fatal("nil output reader accepted")
	}
}
