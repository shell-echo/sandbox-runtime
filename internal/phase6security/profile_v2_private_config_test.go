package phase6security

import (
	"encoding/json"
	"path"
	"testing"
)

func TestV2PrivateStartupVolumesAndLedgerAliases(t *testing.T) {
	p := testCompleteV2Fields(t)
	if err := p.validateFields(); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"provider-docker-control", "provider-artifact-scanner", "provider-docker-control-tls-agent", "provider-artifact-scanner-tls-agent"} {
		purpose := Slice6PeerCRLRoleFile
		wrong := Slice6PeerCRLSourcesFile
		if role == "provider-docker-control-tls-agent" || role == "provider-artifact-scanner-tls-agent" {
			purpose, wrong = wrong, purpose
		}
		for _, file := range []string{Slice6ProfileConfigFile, purpose} {
			if verifyPrivateConfigPathV2Fields(p, role, file, path.Join(Slice6PrivateConfigDirectory, file)) != nil {
				t.Fatalf("%s/%s rejected", role, file)
			}
		}
		if verifyPrivateConfigPathV2Fields(p, role, wrong, path.Join(Slice6PrivateConfigDirectory, wrong)) == nil ||
			verifyPrivateConfigPathV2Fields(p, role, purpose, "/other/"+purpose) == nil {
			t.Fatal("wrong file purpose/path admitted")
		}
	}
	clone := func() ProfileV2 {
		data, _ := json.Marshal(p)
		var copy ProfileV2
		if json.Unmarshal(data, &copy) != nil {
			t.Fatal("copy")
		}
		return copy
	}
	for name, mutate := range map[string]func(*ProfileV2){
		"extra private file": func(v *ProfileV2) {
			for i := range v.Principals {
				if v.Principals[i].Name == "provider-docker-control" {
					for j := range v.Principals[i].Mounts {
						if v.Principals[i].Mounts[j].Kind == "private_config" {
							v.Principals[i].Mounts[j].PrivateFiles += ",peer-crl-sources.json"
						}
					}
				}
			}
		},
		"missing private mount": func(v *ProfileV2) {
			for i := range v.Principals {
				if v.Principals[i].Name == "provider-artifact-scanner" {
					for j, m := range v.Principals[i].Mounts {
						if m.Kind == "private_config" {
							v.Principals[i].Mounts = append(v.Principals[i].Mounts[:j], v.Principals[i].Mounts[j+1:]...)
							break
						}
					}
				}
			}
		},
		"shared storage": func(v *ProfileV2) {
			m, _ := slice6PrivateConfigMountV2("provider-docker-control")
			v.Principals[0].Mounts = append(v.Principals[0].Mounts, Mount{Target: "/alias", Kind: "tmpfs", StorageID: m.StorageID, MaxBytes: 4096})
		},
		"nested config": func(v *ProfileV2) {
			v.Principals[0].Mounts = append(v.Principals[0].Mounts, Mount{Target: Slice6PrivateConfigDirectory + "/alias", Kind: "tmpfs", MaxBytes: 4096})
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := clone()
			mutate(&bad)
			if verifyPrivateConfigMountsV2Fields(bad) == nil {
				t.Fatal("unsafe private config admitted")
			}
		})
	}
	for name, mount := range map[string]Mount{
		"same":    {Target: p.DockerControl.ReceiptTarget, Kind: "tmpfs", MaxBytes: 4096},
		"child":   {Target: p.DockerControl.ReceiptTarget + "/alias", Kind: "tmpfs", MaxBytes: 4096},
		"parent":  {Target: path.Dir(p.DockerControl.ReceiptTarget), Kind: "tmpfs", MaxBytes: 4096},
		"storage": {Target: "/alias", Kind: "tmpfs", StorageID: p.DockerControl.ReceiptStorageID, MaxBytes: 4096},
	} {
		t.Run("receipt-"+name, func(t *testing.T) {
			bad := clone()
			bad.Principals[0].Mounts = append(bad.Principals[0].Mounts, mount)
			if verifyControllerLedgerMountsV2Fields(bad) == nil {
				t.Fatal("receipt alias admitted")
			}
		})
	}
	if verifyControllerLedgerMountsFields(p.Principals, controllerLedgerOwners()) == nil {
		t.Fatal("legacy ledger rules admitted Control receipt")
	}
}

func TestV2CommandAccessorsRetainAdmissionHold(t *testing.T) {
	p := testCompleteV2Fields(t)
	if _, err := p.PrincipalRegistry(); err == nil {
		t.Fatal("registry bypassed hold")
	}
	if _, _, _, err := p.TLSAgentForSubject("provider-docker-control"); err == nil {
		t.Fatal("ordinary lookup bypassed hold")
	}
	if _, _, _, _, _, err := p.PostgresClientSignerForOwner("product-runtime"); err == nil {
		t.Fatal("PG lookup bypassed hold")
	}
	if _, _, _, err := p.CredentialIssuerSocketForClient("certificate-controller"); err == nil {
		t.Fatal("credential lookup bypassed hold")
	}
	if _, _, err := p.EdgeTrustAnchors("certificate-vault"); err == nil {
		t.Fatal("edge lookup bypassed hold")
	}
	if _, err := p.ConsumerTrustAnchor(p.CertificateController.BootstrapClientAnchorID, "certificate-controller", "client_verification"); err == nil {
		t.Fatal("anchor lookup bypassed hold")
	}
	if VerifySlice6PrivateConfigPathV2(p, "provider-docker-control", Slice6ProfileConfigFile, path.Join(Slice6PrivateConfigDirectory, Slice6ProfileConfigFile)) == nil {
		t.Fatal("path lookup bypassed hold")
	}
	if VerifySlice6ControllerLedgerMountsV2(p) == nil {
		t.Fatal("ledger lookup bypassed hold")
	}
}
