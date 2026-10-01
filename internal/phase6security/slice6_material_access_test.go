package phase6security

import (
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

func TestSlice6MaterialAccessIsClosedToRealV3Consumers(t *testing.T) {
	profile, err := BuildSlice6FinalExternalProfileTarget(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildSlice6DesiredMaterialAccess(profile)
	if err != nil || len(plan) != 11 {
		t.Fatalf("closed v3 material access plan rejected: %v, entries=%d", err, len(plan))
	}
	wanted := map[string][]secretref.Purpose{
		"browser-action-ingress-agent":     {secretref.PurposeActionHistoryWitnessDSN, secretref.PurposeCapacityValkeyCredentials},
		"gateway-agent":                    {secretref.PurposeGatewayGrantKey, secretref.PurposePostgresRuntimeDSN},
		"guest-agent":                      {secretref.PurposeGuestSigningKey},
		"product-migration-agent":          {secretref.PurposePostgresMigrationDSN},
		"product-runtime-agent":            {secretref.PurposeIdentityKeyRing, secretref.PurposePostgresRuntimeDSN},
		"provider-browser-migration-agent": {secretref.PurposePostgresMigrationDSN},
		"provider-browser-runtime-agent":   {secretref.PurposeAdmissionVerification, secretref.PurposePostgresRuntimeDSN},
		"provider-desktop-migration-agent": {secretref.PurposePostgresMigrationDSN},
		"provider-desktop-runtime-agent":   {secretref.PurposeAdmissionVerification, secretref.PurposeExecutorBridgeKey, secretref.PurposePostgresRuntimeDSN},
		"provider-migration-agent":         {secretref.PurposePostgresMigrationDSN},
		"provider-runtime-agent":           {secretref.PurposeAdmissionVerification, secretref.PurposePostgresRuntimeDSN},
	}
	seen := map[string]bool{}
	paths := map[string]bool{}
	for _, entry := range plan {
		purposes, ok := wanted[entry.Agent]
		if !ok || seen[entry.Agent] || len(entry.Bindings) != len(purposes) ||
			len(entry.KVDataPaths) != len(purposes) || entry.TokenRole != workloadcredential.Phase6TokenRole(entry.BackendPolicy) ||
			entry.Digest == "" || entry.SecurityProfileDigest != profile.ProfileDigest ||
			entry.AgentPrincipal == "" || entry.OwnerPrincipal == "" {
			t.Fatalf("wrong agent/policy binding for %s", entry.Agent)
		}
		seen[entry.Agent] = true
		for index, binding := range entry.Bindings {
			if binding.Purpose != purposes[index] || binding.Role != entry.Role ||
				binding.TenantID != secretref.SystemTenant || binding.Version != "v1" || binding.Validate() != nil ||
				binding.Reference.String() != "secret://phase6/kv/"+entry.Agent+"/"+string(purposes[index]) ||
				entry.KVDataPaths[index] != "kv/data/"+entry.Agent+"/"+string(purposes[index]) ||
				paths[entry.KVDataPaths[index]] {
				t.Fatalf("wrong or shared KV document for %s/%s", entry.Agent, purposes[index])
			}
			paths[entry.KVDataPaths[index]] = true
			line := "path \"" + entry.KVDataPaths[index] + "\" { capabilities = [\"read\"] }\n"
			if !strings.Contains(entry.ACL, line) {
				t.Fatalf("missing exact read-only ACL for %s", entry.KVDataPaths[index])
			}
		}
		if strings.Count(entry.ACL, "path ") != len(purposes) ||
			strings.ContainsAny(entry.ACL, "*+") || strings.Contains(entry.ACL, "list") ||
			strings.Contains(entry.ACL, "update") || strings.Contains(entry.ACL, "delete") ||
			strings.Contains(entry.ACL, "pki/") || strings.Contains(entry.ACL, "auth/") ||
			strings.Contains(entry.ACL, "sys/") {
			t.Fatalf("material agent %s gained a broader Vault ACL", entry.Agent)
		}
		if VerifySlice6MaterialACLReadback(profile, entry, []byte(entry.ACL)) != nil {
			t.Fatalf("exact installed ACL rejected for %s", entry.Agent)
		}
		for _, installed := range [][]byte{
			[]byte(entry.ACL + "\n"),
			[]byte(entry.ACL + `path "kv/data/other" { capabilities = ["read"] }`),
			[]byte(strings.Replace(entry.ACL, `"read"`, `"read", "list"`, 1)),
		} {
			if VerifySlice6MaterialACLReadback(profile, entry, installed) == nil {
				t.Fatalf("widened or noncanonical installed ACL accepted for %s", entry.Agent)
			}
		}
		changed := entry
		changed.BackendPolicy = "other-policy"
		if VerifySlice6MaterialACLReadback(profile, changed, []byte(entry.ACL)) == nil {
			t.Fatalf("credential policy drift accepted for %s", entry.Agent)
		}
	}
	if len(seen) != len(wanted) || len(paths) != 18 || !slices.IsSortedFunc(plan, func(a, b Slice6MaterialAccess) int {
		return strings.Compare(a.Agent, b.Agent)
	}) {
		t.Fatal("material agent inventory is incomplete, duplicated or reordered")
	}
	for _, retired := range []string{"browser-agent", "desktop-agent"} {
		if seen[retired] || slices.ContainsFunc(profile.CredentialIssuerSockets, func(binding CredentialIssuerSocketBinding) bool {
			return binding.ClientDeployment == retired
		}) {
			t.Fatalf("retired v2 material agent %s has credential authority", retired)
		}
	}
}

func TestSlice6MaterialAccessRejectsProfileDrift(t *testing.T) {
	base, err := BuildSlice6FinalExternalProfileTarget(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Profile){
		"missing credential socket": func(p *Profile) { p.CredentialIssuerSockets = p.CredentialIssuerSockets[1:] },
		"wrong agent UID": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == "gateway-agent" {
					p.Principals[i].UID++
				}
			}
		},
		"old agent reintroduced": func(p *Profile) {
			p.CredentialIssuerSockets = append(p.CredentialIssuerSockets, CredentialIssuerSocketBinding{ClientDeployment: "browser-agent"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Principals = slices.Clone(base.Principals)
			candidate.CredentialIssuerSockets = slices.Clone(base.CredentialIssuerSockets)
			mutate(&candidate)
			candidate.ProfileDigest = candidate.Digest()
			if _, err := BuildSlice6DesiredMaterialAccess(candidate); err == nil {
				t.Fatal("drifted material authorization admitted")
			}
		})
	}
}
