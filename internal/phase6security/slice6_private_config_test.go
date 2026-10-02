package phase6security

import (
	"slices"
	"strings"
	"testing"
)

func TestSlice6PrivateConfigPlanBindsOnlyActualReaders(t *testing.T) {
	final, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil || VerifySlice6PrivateConfigMounts(final) != nil {
		t.Fatalf("final private config plan absent: %v", err)
	}
	count := 0
	for _, principal := range final.Principals {
		if _, needed := Slice6PrivateConfigMount(principal.Name); needed {
			count++
		}
	}
	if count != 76 {
		t.Fatalf("private config consumers = %d, want 76", count)
	}
	for _, principal := range final.Principals {
		mount, needed := Slice6PrivateConfigMount(principal.Name)
		if !needed {
			continue
		}
		files := strings.Split(mount.PrivateFiles, ",")
		if slices.Contains(files, Slice6PeerCRLRoleFile) {
			edges, err := peerCRLRoleRequiredEdges(final, principal.PrincipalDigest)
			if err != nil || len(edges) == 0 {
				t.Fatalf("%s has a peer-role file without a derivable ordinary peer: %v", principal.Name, err)
			}
		}
		if slices.Contains(files, Slice6PostgresPeerCRLRoleFile) {
			if _, err := final.ResolveSlice6FinalPostgresAuthority(principal.Name); err != nil {
				t.Fatalf("%s has a PostgreSQL peer-role file without its signer authority: %v", principal.Name, err)
			}
		}
	}
	for name, files := range map[string]string{
		"break-glass-controller":         "profile.json",
		"certificate-controller":         "peer-crl-sources.json,profile.json",
		"workload-credential-controller": "profile.json",
		"gateway-runtime":                "credential-authority.json,dependency-authority.json,peer-crl-role.json,policy-authority.json,postgres-peer-crl-role.json,profile.json",
		"product-migration-job":          "postgres-peer-crl-role.json,profile.json",
		"gateway-postgres-tls-agent":     "peer-crl-sources.json,profile.json",
		"public-ingress-relay":           "profile.json,startup-authority.json",
	} {
		mount, ok := Slice6PrivateConfigMount(name)
		if !ok || mount.PrivateFiles != files || mount.Target != Slice6PrivateConfigDirectory ||
			!mount.ReadOnly || mount.MaxBytes != Slice6PrivateConfigMaxBytes {
			t.Fatalf("incorrect private files for %s", name)
		}
	}
	for _, value := range []struct {
		deployment, filename string
		limit                int64
	}{
		{"browser-executor-backend", Slice6StartupAuthorityFile, 64 << 10},
		{"desktop-executor-backend", Slice6StartupAuthorityFile, 64 << 10},
		{"public-ingress-relay", Slice6StartupAuthorityFile, 16 << 10},
		{"browser-action-ingress-runtime", Slice6StartupAuthorityFile, 16 << 10},
		{"gateway-runtime", Slice6CredentialAuthorityFile, 64 << 10},
		{"certificate-controller", Slice6ProfileConfigFile, 2 << 20},
		{"break-glass-controller", Slice6ProfileConfigFile, 2 << 20},
	} {
		limit, ok := Slice6PrivateConfigFileLimit(value.deployment, value.filename)
		if !ok || limit != value.limit {
			t.Fatalf("incorrect file limit for %s/%s", value.deployment, value.filename)
		}
	}
	if _, ok := Slice6PrivateConfigFileLimit("guest-runtime", Slice6StartupAuthorityFile); ok {
		t.Fatal("unlisted startup authority purpose accepted")
	}
	for _, name := range []string{"browser-sandbox-runtime", "desktop-sandbox-runtime", "unknown"} {
		if _, ok := Slice6PrivateConfigMount(name); ok {
			t.Fatalf("unreviewed private config consumer %s", name)
		}
	}
	if VerifySlice6PrivateConfigPath(final, "certificate-controller", Slice6ProfileConfigFile,
		Slice6PrivateConfigDirectory+"/profile.json") != nil ||
		VerifySlice6PrivateConfigPath(final, "certificate-controller", Slice6PeerCRLSourcesFile,
			Slice6PrivateConfigDirectory+"/peer-crl-sources.json") != nil ||
		VerifySlice6PrivateConfigPath(final, "gateway-runtime", Slice6PostgresPeerCRLRoleFile,
			Slice6PrivateConfigDirectory+"/postgres-peer-crl-role.json") != nil {
		t.Fatal("exact private config paths rejected")
	}
	for _, denied := range []struct{ deployment, file, path string }{
		{"workload-credential-controller", Slice6PeerCRLSourcesFile, Slice6PrivateConfigDirectory + "/peer-crl-sources.json"},
		{"certificate-controller", Slice6ProfileConfigFile, "/tmp/profile.json"},
		{"gateway-runtime", Slice6PostgresPeerCRLRoleFile, Slice6PrivateConfigDirectory + "/peer-crl-role.json"},
		{"browser-sandbox-runtime", Slice6ProfileConfigFile, Slice6PrivateConfigDirectory + "/profile.json"},
	} {
		if VerifySlice6PrivateConfigPath(final, denied.deployment, denied.file, denied.path) == nil {
			t.Fatalf("unreviewed private config path admitted for %s", denied.deployment)
		}
	}
	clone := func() Profile {
		changed := final
		changed.Principals = slices.Clone(final.Principals)
		for index := range changed.Principals {
			changed.Principals[index].Mounts = slices.Clone(final.Principals[index].Mounts)
		}
		return changed
	}
	for name, mutate := range map[string]func(*Profile){
		"missing": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "certificate-controller" {
					p.Principals[index].Mounts = slices.DeleteFunc(p.Principals[index].Mounts,
						func(m Mount) bool { return m.Kind == "private_config" })
				}
			}
		},
		"writable": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "certificate-controller" {
					for mount := range p.Principals[index].Mounts {
						if p.Principals[index].Mounts[mount].Kind == "private_config" {
							p.Principals[index].Mounts[mount].ReadOnly = false
						}
					}
				}
			}
		},
		"extra file purpose": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "workload-credential-controller" {
					for mount := range p.Principals[index].Mounts {
						if p.Principals[index].Mounts[mount].Kind == "private_config" {
							p.Principals[index].Mounts[mount].PrivateFiles += ",peer-crl-sources.json"
						}
					}
				}
			}
		},
		"cross owner storage": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "gateway-runtime" {
					for mount := range p.Principals[index].Mounts {
						if p.Principals[index].Mounts[mount].Kind == "private_config" {
							p.Principals[index].Mounts[mount].StorageID = "certificate-controller-private-config"
						}
					}
				}
			}
		},
		"nested mount": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "gateway-runtime" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts,
						Mount{Target: Slice6PrivateConfigDirectory + "/extra", Kind: "tmpfs", MaxBytes: 4096})
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone()
			mutate(&changed)
			changed.ProfileDigest = changed.Digest()
			if VerifySlice6PrivateConfigMounts(changed) == nil {
				t.Fatal("private config drift admitted")
			}
		})
	}
}
