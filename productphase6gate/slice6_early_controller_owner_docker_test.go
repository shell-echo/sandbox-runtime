//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const slice6EarlyOwnerDockerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_EARLY_OWNER_NO_ISSUER_DOCKER"

// A disposable Alpine PID1 exercises the exact owner/attach join without
// Vault, PostgreSQL, a certificate issuer or any formal E admission.
func TestSlice6EarlyControllerOwnerRealDockerNoIssuer(t *testing.T) {
	if os.Getenv(slice6EarlyOwnerDockerEnv) != "1" {
		t.Skip("set " + slice6EarlyOwnerDockerEnv + "=1 for no-issuer exact owner drill")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("no-issuer exact-owner Docker fallback cleanup: %v", err)
		}
	})
	created, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-early-owner-"+run.id,
		"--label", run.label(), "--network=none", "--entrypoint=/bin/sleep",
		slice6PinnedAlpineImage, "30")
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("no-issuer exact owner container create unavailable")
	}
	type result struct{ err error }
	completed := make(chan result, 1)
	owner, err := slice6NewEarlyControllerAttachOwner(id,
		func(cleanup context.Context, args ...string) error {
			_, err := run.docker(cleanup, args...)
			return err
		}, func(cleanup context.Context) error {
			select {
			case <-completed:
				return nil // The attached OS command has actually returned.
			case <-cleanup.Done():
				return cleanup.Err()
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.finish(); err != nil {
			t.Errorf("no-issuer exact owner failure-path join unavailable: %v", err)
		}
	}()
	attachContext, cancelAttach := context.WithCancel(ctx)
	defer cancelAttach()
	if err := owner.attach(cancelAttach); err != nil {
		t.Fatal(err)
	}
	go func() {
		completed <- result{exec.CommandContext(attachContext, "docker", "start", "-a", id).Run()}
	}()
	running := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		state, inspectErr := run.docker(ctx, "inspect", "--format", "{{.State.Running}}", id)
		if inspectErr == nil && strings.TrimSpace(string(state)) == "true" {
			running = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !running {
		t.Fatal("no-issuer exact owner PID1 did not start")
	}
	if err := owner.finish(); err != nil {
		t.Fatalf("no-issuer exact owner did not cancel, join and remove PID1: %v", err)
	}
	if _, err := run.docker(ctx, "inspect", id); err == nil || owner.finish() != nil {
		t.Fatal("exact owner removal or one-shot cleanup unconfirmed")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"container", "network", "volume"} {
		ids, err := run.labeledIDs(ctx, resource)
		if err != nil || len(ids) != 0 {
			t.Fatalf("no-issuer exact owner residual %s: %v, %v", resource, ids, err)
		}
	}
}
