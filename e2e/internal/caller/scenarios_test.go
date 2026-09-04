package caller

import (
	"testing"
	"time"
)

func TestStaleExecReferenceRetainsOperationScope(t *testing.T) {
	accepted := execRef()
	stale := staleExecRef()
	if stale.OperationID != accepted.OperationID || stale.SandboxID != accepted.SandboxID {
		t.Fatalf("stale reference changed fencing scope: accepted=%#v stale=%#v", accepted, stale)
	}
	if stale.AttemptID == accepted.AttemptID {
		t.Fatal("stale reference must use a fresh attempt")
	}
	if stale.FencingToken >= accepted.FencingToken {
		t.Fatalf("stale fencing token = %d, accepted = %d", stale.FencingToken, accepted.FencingToken)
	}
}

func TestSessionWindowExpiresBeforeDeadline(t *testing.T) {
	now := time.Unix(1_000, 0).UTC()
	deadline, expiresAt := sessionWindow(now)
	if !expiresAt.After(now) || expiresAt.After(deadline) {
		t.Fatalf("invalid session window: now=%s expiry=%s deadline=%s", now, expiresAt, deadline)
	}
	if got := expiresAt.Sub(now); got != 3*time.Minute {
		t.Fatalf("session lifetime = %s", got)
	}
}

func TestArtifactRetentionExpiresBeforeDeadline(t *testing.T) {
	now := time.Unix(1_000, 0).UTC()
	deadline, retentionSeconds := artifactWindow(now)
	expiresAt := now.Add(time.Duration(retentionSeconds) * time.Second)
	if !expiresAt.After(now) || expiresAt.After(deadline) {
		t.Fatalf("invalid artifact window: now=%s expiry=%s deadline=%s", now, expiresAt, deadline)
	}
	if margin := deadline.Sub(expiresAt); margin != 2*time.Minute {
		t.Fatalf("artifact deadline margin = %s", margin)
	}
}

func TestOperationPollWindowAllowsBoundedBrowserProvenance(t *testing.T) {
	t.Parallel()
	if got := operationPollWindow(ProfileBrowser); got != 330*time.Second {
		t.Fatalf("Browser operation poll window = %v", got)
	}
	if got := operationPollWindow(ProfileCodingShell); got != 30*time.Second {
		t.Fatalf("coding/shell operation poll window = %v", got)
	}
}
