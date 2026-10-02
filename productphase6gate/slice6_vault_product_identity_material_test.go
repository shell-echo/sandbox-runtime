//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/productapi/tokenidentity"
)

const slice6ProductIdentityScopeTokenFile = "product-identity-scope-token"

type slice6ProductKeyRing struct {
	Version       string             `json:"version"`
	Keys          []slice6ProductKey `json:"keys"`
	RevokedKeyIDs []string           `json:"revoked_key_ids"`
}

type slice6ProductKey struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	PublicKey string `json:"public_key"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type slice6VaultKVMaterial struct {
	Schema        string `json:"schema"`
	BindingDigest string `json:"binding_digest"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	Digest        string `json:"digest"`
	State         string `json:"state"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	Material      []byte `json:"material"`
}

// This installs only the Product public verification key-ring. The runtime
// DSN must come from a separately proven live PostgreSQL role; no placeholder
// DSN is written by this component gate.
func slice6VaultInstallProductIdentityMaterial(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string, profile phase6security.Profile) string {
	t.Helper()
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		t.Fatal("Product material access plan unavailable")
	}
	var access phase6security.Slice6MaterialAccess
	for _, candidate := range plan {
		if candidate.Agent == "product-runtime-agent" {
			access = candidate
			break
		}
	}
	if access.Owner != "product-runtime" || access.Migration || access.Role != secretref.RoleProduct ||
		len(access.Bindings) != 2 || len(access.KVDataPaths) != 2 ||
		access.Bindings[0].Purpose != secretref.PurposeIdentityKeyRing ||
		access.Bindings[1].Purpose != secretref.PurposePostgresRuntimeDSN ||
		access.KVDataPaths[0] != "kv/data/product-runtime-agent/identity_key_ring" {
		t.Fatal("Product identity key-ring path or owner drift")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate run-owned Product identity key")
	}
	defer clear(private)
	now := time.Now().UTC()
	keyRing, err := json.Marshal(slice6ProductKeyRing{Version: tokenidentity.KeyRingVersion, Keys: []slice6ProductKey{{KeyID: "product-slice6-" + run.id, Algorithm: "EdDSA",
		PublicKey: base64.RawURLEncoding.EncodeToString(public),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
		NotAfter:  now.Add(30 * time.Minute).Format(time.RFC3339)}}, RevokedKeyIDs: []string{}})
	if err != nil || len(keyRing) > 256<<10 {
		t.Fatal("encode bounded Product key-ring")
	}
	defer clear(keyRing)
	if _, err := tokenidentity.LoadMaterial(keyRing, "https://identity.product.example.test",
		"urn:shell-echo:sandbox-runtime:product-api:production", 20*time.Second, 10*time.Minute); err != nil {
		t.Fatal("Product identity key-ring is not admitted by production decoder")
	}
	digest := sha256.Sum256(keyRing)
	window := secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), State: secretref.KeyActive}
	revision := "product-keyring-" + run.id
	if (secretref.SecretMaterial{Binding: access.Bindings[0], Bytes: keyRing,
		Digest: "sha256:" + hex.EncodeToString(digest[:]), Window: window, Revision: revision}).Validate(now) != nil {
		t.Fatal("Product key-ring is not valid scoped material")
	}
	materialDocument := slice6VaultKVMaterial{Schema: "sandbox-runtime.vault-kv-material.v1", BindingDigest: access.Bindings[0].Digest(),
		Version: access.Bindings[0].Version, Revision: revision,
		Digest: "sha256:" + hex.EncodeToString(digest[:]), State: string(secretref.KeyActive),
		NotBefore: window.NotBefore.Format(time.RFC3339Nano), NotAfter: window.NotAfter.Format(time.RFC3339Nano),
		Material: keyRing}
	document, err := json.Marshal(materialDocument)
	if err != nil {
		t.Fatal("encode Product identity KV material")
	}
	defer clear(document)
	const materialFile = "product-identity-material.json"
	materialPath := filepath.Join(configDir, materialFile)
	writeSlice6VaultPrivateFile(t, configDir, materialFile, document)
	defer func() {
		if err := os.Remove(materialPath); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove exact Product identity bootstrap file: %v", err)
		}
	}()
	created, err := run.docker(ctx, slice6VaultExec(serverID, true, "kv", "put", "-format=json",
		"-mount=kv", "-cas=0", "product-runtime-agent/identity_key_ring", "@/vault/config/"+materialFile)...)
	clear(created)
	if err != nil {
		t.Fatal("real Vault Product identity KVv2 create-only write failed")
	}
	if err := os.Remove(materialPath); err != nil {
		t.Fatal("remove Product identity bootstrap plaintext after Vault write")
	}
	const accessorFile = "product-identity-scope-accessor"
	token, accessor := slice6VaultMintScopedTokenWithAccessor(t, ctx, run, serverID, access.TokenRole, access.BackendPolicy)
	writeSlice6VaultPrivateFile(t, configDir, slice6ProductIdentityScopeTokenFile, []byte(token))
	writeSlice6VaultPrivateFile(t, configDir, accessorFile, []byte(accessor))
	token = ""
	defer func() {
		for _, file := range []string{slice6ProductIdentityScopeTokenFile, accessorFile} {
			if err := os.Remove(filepath.Join(configDir, file)); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove exact Product scoped credential file: %v", err)
			}
		}
	}()
	revoked := false
	defer func() {
		if !revoked {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := slice6VaultRevokeScopedToken(cleanupContext, run, serverID, accessorFile,
				accessor, access.BackendPolicy); err != nil {
				t.Errorf("Product bootstrap token exact cleanup unproved: %v", err)
			}
		}
	}()
	readback, err := run.docker(ctx, slice6VaultExecMaterialToken(serverID, slice6ProductIdentityScopeTokenFile,
		"kv", "get", "-format=json", "-mount=kv", "product-runtime-agent/identity_key_ring")...)
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
	if err != nil || len(readback) > 1<<20 || json.Unmarshal(readback, &observed) != nil ||
		observed.Data.Metadata.Version != 1 || observed.Data.Metadata.Destroyed ||
		observed.Data.Metadata.DeletionTime != "" || json.Unmarshal(observed.Data.Data, &actual) != nil ||
		!reflect.DeepEqual(actual, materialDocument) {
		clear(actual.Material)
		t.Fatal("scoped Product token did not read exact KVv2 identity material")
	}
	clear(actual.Material)
	denied, deniedErr := run.docker(ctx, slice6VaultExecMaterialToken(serverID, slice6ProductIdentityScopeTokenFile,
		"kv", "get", "-format=json", "-mount=kv", "guest-agent/guest_signing_key")...)
	if deniedErr == nil || !bytes.Contains(denied, []byte("permission denied")) {
		clear(denied)
		t.Fatal("Product token cross-owner KV read was not denied")
	}
	clear(denied)
	if err := slice6VaultRevokeScopedToken(ctx, run, serverID, accessorFile,
		accessor, access.BackendPolicy); err != nil {
		t.Fatal("Product identity scoped token revocation/readback failed")
	}
	revoked = true
	t.Log("real Product identity key-ring stored in KVv2 version 1; exact scoped read, Guest cross-owner denial and bootstrap token revocation/readback passed; runtime resolution remains unproved")
	return "sha256:" + hex.EncodeToString(digest[:])
}
