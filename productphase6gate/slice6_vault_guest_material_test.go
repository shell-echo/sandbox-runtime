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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	serverID, configDir string, profile phase6security.Profile) string {
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
	const accessorFile = "guest-material-scope-accessor"
	token, accessor := slice6VaultMintScopedTokenWithAccessor(t, ctx, run, serverID, guest.TokenRole, guest.BackendPolicy)
	writeSlice6VaultPrivateFile(t, configDir, tokenFile, []byte(token))
	writeSlice6VaultPrivateFile(t, configDir, accessorFile, []byte(accessor))
	token = ""
	defer func() {
		for _, name := range []string{tokenFile, accessorFile} {
			if err := os.Remove(filepath.Join(configDir, name)); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove exact Guest scoped credential file: %v", err)
			}
		}
	}()
	revoked := false
	defer func() {
		if !revoked {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := slice6VaultRevokeScopedToken(cleanupContext, run, serverID, accessorFile,
				accessor, guest.BackendPolicy); err != nil {
				t.Errorf("failed Guest bootstrap token cleanup remained unproved: %v", err)
			}
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
	if err := slice6VaultRevokeScopedToken(ctx, run, serverID, accessorFile,
		accessor, guest.BackendPolicy); err != nil {
		t.Fatal("Guest bootstrap token exact revocation/readback failed")
	}
	revoked = true
	if err := os.Remove(filepath.Join(configDir, tokenFile)); err != nil {
		t.Fatal("remove exact Guest scoped read token")
	}
	if err := os.Remove(filepath.Join(configDir, accessorFile)); err != nil {
		t.Fatal("remove exact Guest scoped accessor")
	}
	publicDigest := sha256.Sum256(public)
	t.Logf("real run-owned Guest Ed25519 key stored in KVv2 version 1; exact scoped read, cross-owner denial and bootstrap token revocation/readback passed; public key sha256:%x; no material agent or Guest consumer launched", publicDigest)
	return "sha256:" + hex.EncodeToString(publicDigest[:])
}

func slice6VaultRevokeScopedToken(ctx context.Context, run slice6DockerRun,
	serverID, accessorFile, accessor, policy string) error {
	lookup, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json",
		"auth/token/lookup-accessor", "accessor=@/vault/config/"+accessorFile)...)
	var observed struct {
		Data struct {
			Accessor string   `json:"accessor"`
			Policies []string `json:"policies"`
			Orphan   bool     `json:"orphan"`
			TTL      int64    `json:"ttl"`
		} `json:"data"`
	}
	valid := err == nil && len(lookup) <= 64<<10 && json.Unmarshal(lookup, &observed) == nil &&
		observed.Data.Accessor == accessor && slices.Equal(observed.Data.Policies, []string{policy}) &&
		!observed.Data.Orphan && observed.Data.TTL > 0 && observed.Data.TTL <= 60
	clear(lookup)
	if !valid {
		return errors.New("exact Guest token accessor lookup failed")
	}
	result, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "auth/token/revoke-accessor",
		"accessor=@/vault/config/"+accessorFile)...)
	clear(result)
	if err != nil {
		return errors.New("exact Guest token accessor revocation failed")
	}
	readback, readErr := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json",
		"auth/token/lookup-accessor", "accessor=@/vault/config/"+accessorFile)...)
	confirmed := readErr != nil && len(readback) <= 64<<10 &&
		bytes.Contains(readback, []byte("Code: 400")) && bytes.Contains(readback, []byte("invalid accessor"))
	clear(readback)
	if !confirmed {
		return errors.New("Guest accessor revocation readback was not the exact invalid-accessor response")
	}
	return nil
}

func slice6VaultExecGuestMaterialToken(containerID string, arguments ...string) []string {
	return slice6VaultExecMaterialToken(containerID, "guest-material-scope-token", arguments...)
}

func slice6VaultExecMaterialToken(containerID, tokenFile string, arguments ...string) []string {
	if tokenFile != "guest-material-scope-token" && tokenFile != "product-identity-scope-token" {
		return nil
	}
	result := []string{"exec", "-e", "VAULT_ADDR=https://127.0.0.1:8200",
		"-e", "VAULT_CACERT=/vault/config/server-ca.pem", "-e", "VAULT_CLIENT_CERT=/vault/config/client.pem",
		"-e", "VAULT_CLIENT_KEY=/vault/config/client-key.pem", "-e", "VAULT_TLS_SERVER_NAME=vault.sandbox-runtime.test",
		containerID, "sh", "-c", "VAULT_TOKEN=\"$(cat /vault/config/" + tokenFile + ")\" exec vault \"$@\"", "--"}
	return append(result, arguments...)
}

func TestSlice6VaultExecMaterialTokenRejectsArbitraryFile(t *testing.T) {
	if slice6VaultExecMaterialToken("container", "../../unreviewed", "kv", "get") != nil {
		t.Fatal("arbitrary Vault token file reached the shell command")
	}
	for _, allowed := range []string{"guest-material-scope-token", "product-identity-scope-token"} {
		if len(slice6VaultExecMaterialToken("container", allowed, "kv", "get")) == 0 {
			t.Fatal("fixed Vault token file was not admitted")
		}
	}
}
