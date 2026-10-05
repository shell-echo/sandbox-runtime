//go:build integration

package dockercontrol

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// This opt-in read-only component check does not authenticate the fixture
// endpoint scope, inspect containers/volumes or prove daemon quiescence. It
// performs no Docker mutation and cannot be used as a Slice 6 release gate.
func TestCodingDaemonInfoObservationRealAPI(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CODING_DAEMON_INFO_OBSERVATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_CODING_DAEMON_INFO_OBSERVATION=1 for read-only Docker Info component observation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	api, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal("construct test-only Docker client:", err)
	}
	defer api.Close()
	scope := testControlDigest("7") // fixture only, not an authenticated production endpoint
	first, err := ObserveCodingDaemon(ctx, api, scope)
	if err != nil {
		t.Fatal("first bounded Info observation:", err)
	}
	second, err := ObserveCodingDaemon(ctx, api, scope)
	if err != nil || second != first {
		t.Fatalf("same-client Info observation drift or error: %v", err)
	}
	t.Logf("read-only daemon Info projection platform=%s identity_digest=%s environment_digest=%s",
		first.Platform, first.IdentityDigest, first.EnvironmentDigest)
}
