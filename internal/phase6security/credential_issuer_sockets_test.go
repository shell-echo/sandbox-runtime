package phase6security

import (
	"encoding/json"
	"testing"
)

func TestCredentialIssuerSocketsAreExactAndIsolated(t *testing.T) {
	base := validProfile()
	if len(base.CredentialIssuerSockets) != len(approvedCredentialIssuerClients) {
		t.Fatal("incomplete credential issuer inventory")
	}
	for name, mutate := range map[string]func(*Profile){
		"missing binding":   func(p *Profile) { p.CredentialIssuerSockets = p.CredentialIssuerSockets[1:] },
		"duplicate binding": func(p *Profile) { p.CredentialIssuerSockets[1] = p.CredentialIssuerSockets[0] },
		"path drift":        func(p *Profile) { p.CredentialIssuerSockets[0].SocketPath += "-other" },
		"storage alias": func(p *Profile) {
			p.CredentialIssuerSockets[0].SocketStorageID = p.CredentialIssuerSockets[1].SocketStorageID
		},
		"reverse edge": func(p *Profile) {
			for i := range p.TrustEdges {
				if p.TrustEdges[i].ID == p.CredentialIssuerSockets[0].UnixEdgeID {
					p.TrustEdges[i].From, p.TrustEdges[i].To = p.TrustEdges[i].To, p.TrustEdges[i].From
					break
				}
			}
		},
		"extra reader": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == "product-runtime" {
					p.Principals[i].Mounts = append(p.Principals[i].Mounts, Mount{Kind: "private_socket", ReadOnly: true,
						Target: p.CredentialIssuerSockets[0].SocketDirectory, StorageID: p.CredentialIssuerSockets[0].SocketStorageID})
				}
			}
		},
		"overlapping parent mount": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == "workload-credential-controller" {
					p.Principals[i].Mounts = append(p.Principals[i].Mounts, Mount{Kind: "tmpfs",
						Target: "/run/workload-credential-controller", MaxBytes: 4096})
				}
			}
		},
		"client mount writable": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == p.CredentialIssuerSockets[0].ClientDeployment {
					for j := range p.Principals[i].Mounts {
						if p.Principals[i].Mounts[j].StorageID == p.CredentialIssuerSockets[0].SocketStorageID {
							p.Principals[i].Mounts[j].ReadOnly = false
						}
					}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := base
			// Clone via the repository's strict JSON path to avoid shared fixture slices.
			encoded, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			profile, err = Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if profile.Validate() == nil {
				t.Fatal("credential issuer socket drift admitted")
			}
		})
	}
}
