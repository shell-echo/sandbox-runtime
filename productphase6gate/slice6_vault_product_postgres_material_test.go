//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

// Store only DSNs made from the two live, independently verified SQL logins.
// This is an operator bootstrap step before the Vault root is revoked.
func slice6VaultInstallProductPostgresMaterial(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string, profile phase6security.Profile, dsns slice6ProductPostgresDSNs) {
	t.Helper()
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		t.Fatal("Product PostgreSQL material access plan unavailable")
	}
	type item struct {
		access       phase6security.Slice6MaterialAccess
		binding      secretref.Binding
		path, file   string
		tokenFile    string
		accessorFile string
		material     []byte
	}
	var migration, runtime item
	for _, access := range plan {
		switch access.Agent {
		case "product-migration-agent":
			if access.Owner != "product-migration-job" || !access.Migration || len(access.Bindings) != 1 ||
				len(access.KVDataPaths) != 1 || access.Bindings[0].Purpose != secretref.PurposePostgresMigrationDSN ||
				access.KVDataPaths[0] != "kv/data/product-migration-agent/postgres_migration_dsn" {
				t.Fatal("Product migration DSN binding drifted")
			}
			migration = item{access: access, binding: access.Bindings[0], path: "product-migration-agent/postgres_migration_dsn",
				file: "product-migration-dsn-material.json", tokenFile: "product-migration-dsn-scope-token",
				accessorFile: "product-migration-dsn-scope-accessor", material: dsns.Migration}
		case "product-runtime-agent":
			if access.Owner != "product-runtime" || access.Migration || len(access.Bindings) != 2 ||
				len(access.KVDataPaths) != 2 || access.Bindings[1].Purpose != secretref.PurposePostgresRuntimeDSN ||
				access.KVDataPaths[1] != "kv/data/product-runtime-agent/postgres_runtime_dsn" {
				t.Fatal("Product runtime DSN binding drifted")
			}
			runtime = item{access: access, binding: access.Bindings[1], path: "product-runtime-agent/postgres_runtime_dsn",
				file: "product-runtime-dsn-material.json", tokenFile: "product-runtime-dsn-scope-token",
				accessorFile: "product-runtime-dsn-scope-accessor", material: dsns.Runtime}
		}
	}
	if migration.access.Agent == "" || runtime.access.Agent == "" ||
		len(migration.material) == 0 || len(runtime.material) == 0 || bytes.Equal(migration.material, runtime.material) {
		t.Fatal("two independent live Product PostgreSQL DSNs are required")
	}
	for _, entry := range []item{migration, runtime} {
		slice6VaultInstallOneProductPostgresMaterial(t, ctx, run, serverID, configDir, entry.access,
			entry.binding, entry.path, entry.file, entry.tokenFile, entry.accessorFile, entry.material)
	}
	// Even a successfully resolved purpose must not cross into its sibling.
	// The two tokens are revoked within each per-purpose install helper; use
	// root ACL readback here to preserve the exact policy, not token reuse.
	t.Log("two live Product SQL-role DSNs stored as separate KVv2 version-1 purpose bindings; scoped readback and token revocation passed")
}

func slice6VaultInstallOneProductPostgresMaterial(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string, access phase6security.Slice6MaterialAccess, binding secretref.Binding,
	path, filename, tokenFile, accessorFile string, material []byte) {
	t.Helper()
	now := time.Now().UTC()
	window := secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * time.Minute), State: secretref.KeyActive}
	digest := sha256.Sum256(material)
	document := slice6VaultKVMaterial{Schema: "sandbox-runtime.vault-kv-material.v1",
		BindingDigest: binding.Digest(), Version: binding.Version, Revision: "product-sql-" + run.id,
		Digest: "sha256:" + hex.EncodeToString(digest[:]), State: string(secretref.KeyActive),
		NotBefore: window.NotBefore.Format(time.RFC3339Nano), NotAfter: window.NotAfter.Format(time.RFC3339Nano),
		Material: material}
	if len(material) > 8<<10 || (secretref.SecretMaterial{Binding: binding, Bytes: material,
		Digest: document.Digest, Window: window, Revision: document.Revision}).Validate(now) != nil {
		t.Fatal("Product PostgreSQL DSN is not valid purpose-scoped material")
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 16<<10 {
		t.Fatal("encode bounded Product PostgreSQL KV material")
	}
	defer clear(encoded)
	materialPath := filepath.Join(configDir, filename)
	writeSlice6VaultPrivateFile(t, configDir, filename, encoded)
	defer func() {
		if err := os.Remove(materialPath); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove exact Product PostgreSQL bootstrap material: %v", err)
		}
	}()
	created, err := run.docker(ctx, slice6VaultExec(serverID, true, "kv", "put", "-format=json", "-mount=kv",
		"-cas=0", path, "@/vault/config/"+filename)...)
	clear(created)
	if err != nil {
		t.Fatal("real Vault Product PostgreSQL KVv2 create-only write failed")
	}
	if err := os.Remove(materialPath); err != nil {
		t.Fatal("remove Product PostgreSQL bootstrap plaintext after Vault write")
	}
	token, accessor := slice6VaultMintScopedTokenWithAccessor(t, ctx, run, serverID,
		access.TokenRole, access.BackendPolicy)
	writeSlice6VaultPrivateFile(t, configDir, tokenFile, []byte(token))
	writeSlice6VaultPrivateFile(t, configDir, accessorFile, []byte(accessor))
	token = ""
	defer func() {
		for _, name := range []string{tokenFile, accessorFile} {
			if err := os.Remove(filepath.Join(configDir, name)); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove exact Product PostgreSQL scoped credential file: %v", err)
			}
		}
	}()
	revoked := false
	defer func() {
		if !revoked {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := slice6VaultRevokeScopedToken(cleanup, run, serverID, accessorFile,
				accessor, access.BackendPolicy); err != nil {
				t.Errorf("Product PostgreSQL scoped token cleanup unproved: %v", err)
			}
		}
	}()
	readback, err := run.docker(ctx, slice6VaultExecMaterialToken(serverID, tokenFile,
		"kv", "get", "-format=json", "-mount=kv", path)...)
	defer clear(readback)
	var observed struct {
		Data struct {
			Data     json.RawMessage `json:"data"`
			Metadata struct {
				Version      int    `json:"version"`
				Destroyed    bool   `json:"destroyed"`
				DeletionTime string `json:"deletion_time"`
			} `json:"metadata"`
		} `json:"data"`
	}
	var actual slice6VaultKVMaterial
	if err != nil || len(readback) > 32<<10 || json.Unmarshal(readback, &observed) != nil ||
		observed.Data.Metadata.Version != 1 || observed.Data.Metadata.Destroyed ||
		observed.Data.Metadata.DeletionTime != "" || json.Unmarshal(observed.Data.Data, &actual) != nil ||
		!reflect.DeepEqual(actual, document) {
		clear(actual.Material)
		t.Fatal("scoped Product PostgreSQL token did not read exact KVv2 DSN")
	}
	clear(actual.Material)
	otherPath := "product-migration-agent/postgres_migration_dsn"
	if access.Agent == "product-migration-agent" {
		otherPath = "product-runtime-agent/postgres_runtime_dsn"
	}
	for _, deniedPath := range []string{otherPath, "guest-agent/guest_signing_key"} {
		denied, deniedErr := run.docker(ctx, slice6VaultExecMaterialToken(serverID, tokenFile,
			"kv", "get", "-format=json", "-mount=kv", deniedPath)...)
		if deniedErr == nil || !bytes.Contains(denied, []byte("permission denied")) {
			clear(denied)
			t.Fatal("Product PostgreSQL token crossed its purpose or owner")
		}
		clear(denied)
	}
	if err := slice6VaultRevokeScopedToken(ctx, run, serverID, accessorFile,
		accessor, access.BackendPolicy); err != nil {
		t.Fatal("Product PostgreSQL scoped token revocation/readback failed")
	}
	revoked = true
}
