//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

// This is controlled, run-owned Vault configuration evidence. It does not
// write placeholder KV documents or claim that a material consumer ran.
func slice6VaultScopedPolicyCommandDiagnostic(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string) {
	t.Helper()
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "secrets", "enable", "-path=kv", "-version=2", "kv")...); err != nil {
		t.Fatal("diagnostic Vault KVv2 mount failed")
	}
	policy := "slice6-vault-policy-diagnostic"
	acl := "path \"kv/data/slice6-diagnostic\" { capabilities = [\"read\"] }\n"
	slice6VaultWriteAndReadACL(t, ctx, run, serverID, configDir, policy, acl)
	role := workloadcredential.Phase6TokenRole(policy)
	slice6VaultWriteAndReadTokenRole(t, ctx, run, serverID, role, policy)
	token := slice6VaultMintScopedToken(t, ctx, run, serverID, role, policy)
	writeSlice6VaultPrivateFile(t, configDir, "scope-token-diagnostic", []byte(token))
	slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-diagnostic", "kv/data/slice6-diagnostic", "read")
	for _, denied := range []string{"kv/data/other-owner", "kv/metadata/slice6-diagnostic", "pki/sign/other", "auth/token/create"} {
		slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-diagnostic", denied, "deny")
	}
	if err := os.Remove(filepath.Join(configDir, "scope-token-diagnostic")); err != nil {
		t.Fatal("remove exact diagnostic Vault token file")
	}
	t.Log("real Vault CLI exact ACL/role write/read and scoped token capabilities passed without business material; diagnostic only")
}

func slice6VaultInstallScopedAccess(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string, profile phase6security.Profile, general, broker slice6VaultRoot) {
	t.Helper()
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil || len(plan) != 11 {
		t.Fatal("same-run Profile has no exact material access plan")
	}
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "secrets", "enable", "-path=kv", "-version=2", "kv")...); err != nil {
		t.Fatal("real Vault KVv2 mount failed")
	}
	mounts, err := run.docker(ctx, slice6VaultExec(serverID, true, "secrets", "list", "-format=json")...)
	var mounted map[string]struct {
		Type    string            `json:"type"`
		Options map[string]string `json:"options"`
	}
	if err != nil || json.Unmarshal(mounts, &mounted) != nil || mounted["kv/"].Type != "kv" ||
		mounted["kv/"].Options["version"] != "2" {
		t.Fatal("real Vault KV mount readback was not v2")
	}
	for _, entry := range plan {
		slice6VaultWriteAndReadACL(t, ctx, run, serverID, configDir, entry.BackendPolicy, entry.ACL)
		readback, err := run.docker(ctx, slice6VaultExec(serverID, true, "policy", "read", entry.BackendPolicy)...)
		if err != nil || phase6security.VerifySlice6MaterialACLReadback(profile, entry, readback) != nil {
			t.Fatalf("installed material policy did not match %s exact Profile paths", entry.Agent)
		}
		slice6VaultWriteAndReadTokenRole(t, ctx, run, serverID, entry.TokenRole, entry.BackendPolicy)
	}
	pkiACL := slice6VaultCertificatePKIACL(t, profile, general.ID, broker.ID)
	slice6VaultWriteAndReadACL(t, ctx, run, serverID, configDir, "certificate-controller-pki", pkiACL)
	pkiRoles := slice6VaultDesiredPKIRoles(t, profile, general.ID, broker.ID)
	slice6VaultInstallPKIRoles(t, ctx, run, serverID, pkiRoles)
	slice6VaultAssertControllerManagedSign(t, ctx, run, serverID, pkiRoles, general)
	certificateRole := workloadcredential.Phase6TokenRole("certificate-controller-pki")
	if certificateRole == "" {
		t.Fatal("certificate token role missing")
	}
	slice6VaultWriteAndReadTokenRole(t, ctx, run, serverID, certificateRole, "certificate-controller-pki")
	managementACL := slice6VaultCredentialManagementACL(plan, certificateRole)
	slice6VaultWriteAndReadACL(t, ctx, run, serverID, configDir, "phase6-credential-management", managementACL)
	managementToken := slice6VaultMintManagementToken(t, ctx, run, serverID)
	writeSlice6VaultPrivateFile(t, configDir, "scope-token-management", []byte(managementToken))
	for _, entry := range plan {
		slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-management",
			"auth/token/create/"+entry.TokenRole, "update")
		slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-management",
			"auth/token/roles/"+entry.TokenRole, "read")
	}
	for _, allowed := range []struct{ path, capability string }{
		{"auth/token/create/" + certificateRole, "update"},
		{"auth/token/roles/" + certificateRole, "read"},
		{"auth/token/lookup-accessor", "update"},
		{"auth/token/revoke-accessor", "update"},
		{"auth/token/lookup-self", "read"},
	} {
		slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-management", allowed.path, allowed.capability)
	}
	for _, denied := range []string{"auth/token/create", "auth/token/create-orphan",
		plan[0].KVDataPaths[0], "pki/sign/" + profile.CertificateController.ManagedVaultRole} {
		slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-management", denied, "deny")
	}
	if err := os.Remove(filepath.Join(configDir, "scope-token-management")); err != nil {
		t.Fatal("remove exact disposable management test token")
	}
	for index, entry := range plan {
		token := slice6VaultMintScopedToken(t, ctx, run, serverID, entry.TokenRole, entry.BackendPolicy)
		fileName := "scope-token-" + entry.Agent
		writeSlice6VaultPrivateFile(t, configDir, fileName, []byte(token))
		for _, own := range entry.KVDataPaths {
			slice6VaultRequireCapability(t, ctx, run, serverID, fileName, own, "read")
		}
		cross := plan[(index+1)%len(plan)].KVDataPaths[0]
		for _, denied := range []string{cross, "kv/metadata/" + entry.Agent,
			"pki/sign/" + profile.CertificateController.ManagedVaultRole,
			"auth/token/create", "auth/token/create/" + entry.TokenRole} {
			slice6VaultRequireCapability(t, ctx, run, serverID, fileName, denied, "deny")
		}
		if err := os.Remove(filepath.Join(configDir, fileName)); err != nil {
			t.Fatal("remove exact disposable material test token")
		}
	}
	certificateToken := slice6VaultMintScopedToken(t, ctx, run, serverID, certificateRole, "certificate-controller-pki")
	writeSlice6VaultPrivateFile(t, configDir, "scope-token-certificate", []byte(certificateToken))
	slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-certificate",
		"pki/sign/"+profile.CertificateController.ManagedVaultRole, "update")
	slice6VaultRequireCapability(t, ctx, run, serverID, "scope-token-certificate", plan[0].KVDataPaths[0], "deny")
	slice6VaultAssertScopedPKISign(t, ctx, run, serverID,
		profile.CertificateController.ManagedVaultRole, general, "spiffe://sandbox-runtime.test/certificate-controller")
	if err := os.Remove(filepath.Join(configDir, "scope-token-certificate")); err != nil {
		t.Fatal("remove exact disposable certificate test token")
	}
	t.Logf("real Vault KVv2 mount, 11 exact material ACLs, 12 scoped token roles, 38 issuer-pinned PKI roles, root and scoped PKI-token CSR sign/foreign CSR denial and positive/negative token capabilities passed for Profile %s; no material documents or controller process yet", profile.ProfileDigest)
}

func slice6VaultMintManagementToken(t *testing.T, ctx context.Context, run slice6DockerRun, serverID string) string {
	t.Helper()
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json", "auth/token/create-orphan",
		"policies=phase6-credential-management", "ttl=15m", "renewable=false", "no_default_policy=true")...)
	var issued struct {
		Auth struct {
			ClientToken string   `json:"client_token"`
			Policies    []string `json:"policies"`
			Orphan      bool     `json:"orphan"`
		} `json:"auth"`
	}
	if err != nil || json.Unmarshal(response, &issued) != nil || issued.Auth.ClientToken == "" ||
		!slices.Equal(issued.Auth.Policies, []string{"phase6-credential-management"}) || !issued.Auth.Orphan {
		t.Fatal("real Vault limited orphan management token issuance failed")
	}
	return issued.Auth.ClientToken
}

func slice6VaultWriteAndReadACL(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir, policy, acl string) {
	t.Helper()
	if policy == "" || strings.ContainsAny(policy, "/\\\x00 ") || acl == "" {
		t.Fatal("invalid closed Vault ACL input")
	}
	fileName := "policy-" + policy + ".hcl"
	writeSlice6VaultPrivateFile(t, configDir, fileName, []byte(acl))
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "policy", "write", policy, "/vault/config/"+fileName)...); err != nil {
		t.Fatalf("install exact Vault policy %s failed", policy)
	}
	readback, err := run.docker(ctx, slice6VaultExec(serverID, true, "policy", "read", policy)...)
	if err != nil || string(readback) != acl {
		t.Fatalf("Vault policy %s readback differs from exact intended ACL", policy)
	}
}

func slice6VaultWriteAndReadTokenRole(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, role, policy string) {
	t.Helper()
	if role != workloadcredential.Phase6TokenRole(policy) || role == "" {
		t.Fatal("unreviewed Vault token role")
	}
	_, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "auth/token/roles/"+role,
		"allowed_policies="+policy, "disallowed_policies=default,root", "token_no_default_policy=true",
		"token_type=service", "token_explicit_max_ttl=15m", "renewable=false", "orphan=false")...)
	if err != nil {
		t.Fatalf("install scoped Vault role for %s failed", policy)
	}
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "read", "-format=json", "auth/token/roles/"+role)...)
	var observed struct {
		Data struct {
			Name                 string   `json:"name"`
			AllowedPolicies      []string `json:"allowed_policies"`
			DisallowedPolicies   []string `json:"disallowed_policies"`
			TokenNoDefaultPolicy bool     `json:"token_no_default_policy"`
			TokenType            string   `json:"token_type"`
			TokenExplicitMaxTTL  int64    `json:"token_explicit_max_ttl"`
			Renewable            bool     `json:"renewable"`
			Orphan               bool     `json:"orphan"`
			Period               int64    `json:"period"`
			PathSuffix           string   `json:"path_suffix"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &observed) != nil || observed.Data.Name != role ||
		!slices.Equal(observed.Data.AllowedPolicies, []string{policy}) ||
		!slices.Equal(observed.Data.DisallowedPolicies, []string{"default", "root"}) ||
		!observed.Data.TokenNoDefaultPolicy || observed.Data.TokenType != "service" ||
		observed.Data.TokenExplicitMaxTTL != 900 || observed.Data.Renewable || observed.Data.Orphan ||
		observed.Data.Period != 0 || observed.Data.PathSuffix != "" {
		t.Fatalf("installed Vault token role for %s was not exactly scoped", policy)
	}
}

func slice6VaultMintScopedToken(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, role, policy string) string {
	t.Helper()
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json", "auth/token/create/"+role,
		"policies="+policy, "ttl=1m", "renewable=false", "no_default_policy=true")...)
	var issued struct {
		Auth struct {
			ClientToken string   `json:"client_token"`
			Policies    []string `json:"policies"`
			Orphan      bool     `json:"orphan"`
		} `json:"auth"`
	}
	if err != nil || json.Unmarshal(response, &issued) != nil || issued.Auth.ClientToken == "" ||
		!slices.Equal(issued.Auth.Policies, []string{policy}) || issued.Auth.Orphan {
		t.Fatalf("real Vault scoped token issuance for %s failed", policy)
	}
	return issued.Auth.ClientToken
}

func slice6VaultRequireCapability(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, tokenFile, path, expected string) {
	t.Helper()
	// The root bootstrap token queries the scoped token's effective ACL. The
	// scoped token itself does not gain sys/capabilities-self just for a test.
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json", "sys/capabilities",
		"token=@/vault/config/"+tokenFile, "path="+path)...)
	var observed struct {
		Data struct {
			Capabilities []string `json:"capabilities"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &observed) != nil ||
		!slices.Equal(observed.Data.Capabilities, []string{expected}) {
		t.Fatalf("Vault scoped token capability on %s: wanted %s, observed %v, err=%v",
			path, expected, observed.Data.Capabilities, err)
	}
}

func slice6VaultCertificatePKIACL(t *testing.T, profile phase6security.Profile, generalIssuer, brokerIssuer string) string {
	t.Helper()
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		!phase6security.ValidSlice6IssuerID(generalIssuer) || !phase6security.ValidSlice6IssuerID(brokerIssuer) ||
		generalIssuer == brokerIssuer {
		t.Fatal("unreviewed PKI ACL source")
	}
	roles := []string{profile.CertificateController.ManagedVaultRole,
		profile.CertificateController.CredentialController.VaultRole}
	for _, binding := range profile.TLSAgentBindings {
		roles = append(roles, binding.IssuerVaultRole)
	}
	for _, binding := range profile.PostgresClientAgents {
		roles = append(roles, binding.IssuerVaultRole)
	}
	slices.Sort(roles)
	if len(profile.TLSAgentBindings)+len(profile.PostgresClientAgents) != 36 ||
		len(profile.PostgresClientAgents) != 9 || len(roles) != 38 || slices.Contains(roles, "") {
		t.Fatal("incomplete exact PKI role inventory")
	}
	for index := 1; index < len(roles); index++ {
		if roles[index] == roles[index-1] {
			t.Fatal("shared PKI role between distinct certificate purposes")
		}
	}
	var acl strings.Builder
	for _, role := range roles {
		fmt.Fprintf(&acl, "path %q { capabilities = [\"read\"] }\n", "pki/roles/"+role)
		fmt.Fprintf(&acl, "path %q { capabilities = [\"update\"] }\n", "pki/sign/"+role)
	}
	for _, issuer := range []string{generalIssuer, brokerIssuer} {
		fmt.Fprintf(&acl, "path %q { capabilities = [\"read\"] }\n", "pki/issuer/"+issuer+"/der")
		fmt.Fprintf(&acl, "path %q { capabilities = [\"read\"] }\n", "pki/issuer/"+issuer+"/crl/der")
	}
	acl.WriteString("path \"pki/config/crl\" { capabilities = [\"read\"] }\n")
	acl.WriteString("path \"pki/crl\" { capabilities = [\"read\"] }\n")
	acl.WriteString("path \"pki/revoke\" { capabilities = [\"update\"] }\n")
	return acl.String()
}

func slice6VaultCredentialManagementACL(plan []phase6security.Slice6MaterialAccess, certificateRole string) string {
	roles := make([]string, 0, len(plan)+1)
	for _, entry := range plan {
		roles = append(roles, entry.TokenRole)
	}
	roles = append(roles, certificateRole)
	slices.Sort(roles)
	var acl strings.Builder
	for _, role := range roles {
		fmt.Fprintf(&acl, "path %q { capabilities = [\"update\"] }\n", "auth/token/create/"+role)
		fmt.Fprintf(&acl, "path %q { capabilities = [\"read\"] }\n", "auth/token/roles/"+role)
	}
	acl.WriteString("path \"auth/token/lookup-accessor\" { capabilities = [\"update\"] }\n")
	acl.WriteString("path \"auth/token/revoke-accessor\" { capabilities = [\"update\"] }\n")
	acl.WriteString("path \"auth/token/lookup-self\" { capabilities = [\"read\"] }\n")
	return acl.String()
}
