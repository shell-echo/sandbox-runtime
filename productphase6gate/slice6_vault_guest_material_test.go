//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

const slice6GuestMaterialEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_MATERIAL"

// This writes a real run-owned Guest signing key through the installed KVv2
// path and exercises an actual scoped token. A live material agent and Guest
// consumer are separate, still-missing release observations.
func slice6VaultInstallGuestMaterial(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string, profile phase6security.Profile) {
	t.Helper()
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		t.Fatal("same-run material access plan unavailable")
	}
	var guest phase6security.Slice6MaterialAccess
	for _, entry := range plan {
		if entry.Agent == "guest-agent" {
			guest = entry
			break
		}
	}
	if guest.Agent != "guest-agent" || guest.Owner != "guest-runtime" || guest.Migration ||
		len(guest.Bindings) != 1 || len(guest.KVDataPaths) != 1 ||
		guest.Bindings[0].Purpose != secretref.PurposeGuestSigningKey ||
		guest.KVDataPaths[0] != "kv/data/guest-agent/guest_signing_key" {
		t.Fatal("Guest material path or owner drifted from the complete Profile")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate run-owned Guest signing key")
	}
	defer clear(private)
	now := time.Now().UTC()
	digest := sha256.Sum256(private)
	material := struct {
		Schema        string `json:"schema"`
		BindingDigest string `json:"binding_digest"`
		Version       string `json:"version"`
		Revision      string `json:"revision"`
		Digest        string `json:"digest"`
		State         string `json:"state"`
		NotBefore     string `json:"not_before"`
		NotAfter      string `json:"not_after"`
		Material      []byte `json:"material"`
	}{
		Schema: "sandbox-runtime.vault-kv-material.v1", BindingDigest: guest.Bindings[0].Digest(),
		Version: guest.Bindings[0].Version, Revision: "guest-key-" + run.id,
		Digest: "sha256:" + hex.EncodeToString(digest[:]), State: string(secretref.KeyActive),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339Nano),
		NotAfter:  now.Add(10 * time.Minute).Format(time.RFC3339Nano), Material: private,
	}
	if (secretref.SecretMaterial{Binding: guest.Bindings[0], Bytes: private, Digest: material.Digest,
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
			State: secretref.KeyActive}, Revision: material.Revision}).Validate(now) != nil {
		t.Fatal("generated Guest key is not valid scoped material")
	}
	document, err := json.Marshal(material)
	if err != nil {
		t.Fatal("encode Guest material")
	}
	defer clear(document)
	const materialFile = "guest-material.json"
	writeSlice6VaultPrivateFile(t, configDir, materialFile, document)
	defer func() {
		if err := os.Remove(filepath.Join(configDir, materialFile)); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove exact Guest material bootstrap file: %v", err)
		}
	}()
	created, err := run.docker(ctx, slice6VaultExec(serverID, true, "kv", "put", "-format=json",
		"-mount=kv", "-cas=0", "guest-agent/guest_signing_key", "@/vault/config/"+materialFile)...)
	clear(created)
	if err != nil {
		t.Fatal("real Vault Guest KVv2 create-only write failed")
	}
	if err := os.Remove(filepath.Join(configDir, materialFile)); err != nil {
		t.Fatal("remove Guest bootstrap plaintext after Vault write")
	}
	const tokenFile = "guest-material-scope-token"
	token := slice6VaultMintScopedToken(t, ctx, run, serverID, guest.TokenRole, guest.BackendPolicy)
	writeSlice6VaultPrivateFile(t, configDir, tokenFile, []byte(token))
	token = ""
	defer func() {
		if err := os.Remove(filepath.Join(configDir, tokenFile)); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove exact Guest scoped token file: %v", err)
		}
	}()
	readback, err := run.docker(ctx, slice6VaultExecGuestMaterialToken(serverID, "kv", "get", "-format=json",
		"-mount=kv", "guest-agent/guest_signing_key")...)
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
	var actual struct {
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
	if err != nil || len(readback) > 1<<20 || json.Unmarshal(readback, &observed) != nil ||
		observed.Data.Metadata.Version != 1 || observed.Data.Metadata.Destroyed ||
		observed.Data.Metadata.DeletionTime != "" ||
		json.Unmarshal(observed.Data.Data, &actual) != nil || !reflect.DeepEqual(actual, material) ||
		!ed25519.PrivateKey(actual.Material).Public().(ed25519.PublicKey).Equal(public) {
		clear(actual.Material)
		t.Fatal("scoped Guest token did not read back exact KVv2 version and key")
	}
	clear(actual.Material)
	denied, deniedErr := run.docker(ctx, slice6VaultExecGuestMaterialToken(serverID, "kv", "get", "-format=json",
		"-mount=kv", "gateway-agent/gateway_grant_key")...)
	if deniedErr == nil || !bytes.Contains(denied, []byte("permission denied")) {
		clear(denied)
		t.Fatal("Guest token cross-owner KV read was not explicitly denied")
	}
	clear(denied)
	revoked, revokeErr := run.docker(ctx, slice6VaultExecGuestMaterialToken(serverID, "token", "revoke", "-self")...)
	clear(revoked)
	if revokeErr != nil {
		t.Fatal("Guest scoped read token self-revocation failed")
	}
	if err := os.Remove(filepath.Join(configDir, tokenFile)); err != nil {
		t.Fatal("remove exact Guest scoped read token")
	}
	publicDigest := sha256.Sum256(public)
	t.Logf("real run-owned Guest Ed25519 key stored in KVv2 version 1; exact scoped read, cross-owner denial and token self-revocation passed; public key sha256:%x; no material agent or Guest consumer launched", publicDigest)
}

func slice6VaultExecGuestMaterialToken(containerID string, arguments ...string) []string {
	result := []string{"exec", "-e", "VAULT_ADDR=https://127.0.0.1:8200",
		"-e", "VAULT_CACERT=/vault/config/server-ca.pem", "-e", "VAULT_CLIENT_CERT=/vault/config/client.pem",
		"-e", "VAULT_CLIENT_KEY=/vault/config/client-key.pem", "-e", "VAULT_TLS_SERVER_NAME=vault.sandbox-runtime.test",
		containerID, "sh", "-c", "VAULT_TOKEN=\"$(cat /vault/config/guest-material-scope-token)\" exec vault \"$@\"", "--"}
	return append(result, arguments...)
}
