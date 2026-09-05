//go:build integration

package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestSharedValkeyStartsWithPrivateConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	providerRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	platform, err := dockerServerPlatform(ctx)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := lock.LoadSharedCapacity(providerRoot, platform)
	if err != nil {
		t.Fatal(err)
	}

	const (
		namespace = "shared-capacity-private-config-integration"
		password  = "shared-capacity-private-config-password"
	)
	namespaceDigest := sha256.Sum256([]byte(namespace))
	acl := strings.ReplaceAll(lock.SharedCapacityACLTemplate, "${PASSWORD}", password)
	acl = strings.ReplaceAll(acl, "${NAMESPACE_SHA256}", hex.EncodeToString(namespaceDigest[:]))
	image := locked.Valkey.Image + "@" + locked.Valkey.IndexDigest
	temporaryRoot := filepath.Join(providerRoot, "e2e", "tmp")
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	runRoot, err := os.MkdirTemp(temporaryRoot, runRootPrefix+"shared-valkey-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanupRunRoot(temporaryRoot, runRoot); err != nil {
			t.Errorf("clean shared-capacity test root: %v", err)
		}
	})
	valkey, err := startSharedValkey(ctx, runRoot, image, platform,
		locked.Valkey.SelectedChildDigest, lock.SharedCapacityServerConfig, acl, "e2e", password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if err := valkey.close(cleanupCtx); err != nil {
			t.Errorf("close shared-capacity Valkey: %v", err)
		}
	})

	client, err := newSharedRedisClient(valkey.redisURL,
		time.Duration(locked.CapacityPolicy.OperationTimeoutMillis)*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := waitForSharedRedis(ctx, client, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	capacity, err := sharedCapacityFromLock(client, namespace, locked.CapacityPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := capacity.Provision(ctx); err != nil {
		t.Fatalf("provision through the evidence ACL: %v", err)
	}
	if err := capacity.Verify(ctx); err != nil {
		t.Fatalf("verify through the evidence ACL: %v", err)
	}
	lease, err := capacity.Acquire(ctx, gateway.CapacitySubject{
		TenantID: "tenant-a", SandboxID: "sandbox-a", BrowserSessionID: "browser-a",
		CapabilityProfileID: "browser-v1", ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("acquire through the evidence ACL: %v", err)
	}
	select {
	case event := <-lease.Events():
		t.Fatalf("renew through the evidence ACL emitted %#v", event)
	case <-time.After(2 * time.Duration(locked.CapacityPolicy.RenewIntervalMillis) * time.Millisecond):
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("release through the evidence ACL: %v", err)
	}
}
