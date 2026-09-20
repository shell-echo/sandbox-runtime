package backup

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"
)

type memoryArtifacts map[string][]byte

func (m memoryArtifacts) Read(_ context.Context, reference string, maxBytes int64) ([]byte, error) {
	value, ok := m[reference]
	if !ok || int64(len(value)) > maxBytes {
		return nil, errors.New("missing artifact")
	}
	return append([]byte(nil), value...), nil
}

func artifactDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", digest[:])
}

func TestRestorePlanRequiresIsolatedTargetAndFixedOrdering(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	artifact := Artifact{Reference: "object://backup/one", Digest: digest, Version: "v1"}
	manifest := Manifest{Version: 1, CreatedAt: now.Add(-time.Minute), SourceIdentity: "region-a", DatabaseBaseBackup: artifact, DatabaseWAL: []Artifact{artifact}, ObjectVersions: []Artifact{artifact}, CoordinationSnapshot: artifact, EncryptionKeyRefs: []string{"kms://recording/key#v1"}}
	plan := RestorePlan{Manifest: manifest, TargetIdentity: "region-b-restore", TargetIsolated: true}
	steps, err := plan.Steps(now)
	if err != nil || len(steps) != 8 || steps[1] != "restore_database_base" || steps[6] != "reconcile_authority" {
		t.Fatalf("steps = %#v, %v", steps, err)
	}
	plan.TargetIdentity = "region-a"
	if _, err := plan.Steps(now); err != ErrUnsafeTarget {
		t.Fatalf("same target = %v", err)
	}
	plan.TargetIdentity = "region-b-restore"
	plan.Cutover = true
	if _, err := plan.Steps(now); err != ErrUnsafeTarget {
		t.Fatalf("pre-restore cutover = %v", err)
	}
}

func TestRestorePlanVerifiesEveryReferencedArtifact(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	base := []byte("base")
	wal := []byte("wal")
	objects := []byte("objects")
	coordination := []byte("coordination")
	store := memoryArtifacts{"object://base": base, "object://wal": wal, "object://objects": objects, "object://coordination": coordination}
	manifest := Manifest{Version: 1, CreatedAt: now.Add(-time.Minute), SourceIdentity: "region-a", DatabaseBaseBackup: Artifact{Reference: "object://base", Digest: artifactDigest(base), Version: "v1"}, DatabaseWAL: []Artifact{{Reference: "object://wal", Digest: artifactDigest(wal), Version: "v1"}}, ObjectVersions: []Artifact{{Reference: "object://objects", Digest: artifactDigest(objects), Version: "v1"}}, CoordinationSnapshot: Artifact{Reference: "object://coordination", Digest: artifactDigest(coordination), Version: "v1"}, EncryptionKeyRefs: []string{"kms://recording/key#v1"}}
	plan := RestorePlan{Manifest: manifest, TargetIdentity: "region-b", TargetIsolated: true}
	if err := plan.VerifyArtifacts(context.Background(), store, 1024, now); err != nil {
		t.Fatal(err)
	}
	store["object://wal"] = []byte("tampered")
	if err := plan.VerifyArtifacts(context.Background(), store, 1024, now); err != ErrInvalidPlan {
		t.Fatalf("tampered artifact = %v, want %v", err, ErrInvalidPlan)
	}
}
