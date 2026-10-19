package phase6security

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPostgresPeerCRLV2OwnerIsolationAndPinnedDecode(t *testing.T) {
	profile := testCompleteV2Fields(t)
	sources := testPeerCRLSourcesV2(t, profile)
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		t.Run(target.SubjectDeployment, func(t *testing.T) {
			role, err := derivePostgresPeerCRLRoleDocumentV2Fields(profile, sources, target.SubjectDeployment)
			if err != nil || len(role.Edges) != 1 || role.Edges[0].IssuerDigest != testDigest("v2-general-issuer") {
				t.Fatalf("single general-issuer PostgreSQL edge: %+v, %v", role, err)
			}
			document := mustPeerRoleJSON(t, role)
			decode := func(data []byte, mapping, pinned, owner, local string) error {
				_, err := decodePostgresPeerCRLRoleDocumentV2Fields(data, profile, mapping, pinned, owner, local)
				return err
			}
			if err := decode(document, sources.Digest(), role.Digest(), target.SubjectDeployment, role.LocalPrincipalDigest); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*PeerCRLRoleDocument){
				"profile":   func(d *PeerCRLRoleDocument) { d.SecurityProfileDigest = testDigest("other-profile") },
				"local":     func(d *PeerCRLRoleDocument) { d.LocalPrincipalDigest = testDigest("other-local") },
				"edge":      func(d *PeerCRLRoleDocument) { d.Edges[0].EdgeID = "unbound" },
				"direction": func(d *PeerCRLRoleDocument) { d.Edges[0].Direction = "inbound" },
				"anchor":    func(d *PeerCRLRoleDocument) { d.Edges[0].PeerAnchorID = "other-ca" },
				"issuer":    func(d *PeerCRLRoleDocument) { d.Edges[0].IssuerDigest = "" },
				"extra":     func(d *PeerCRLRoleDocument) { d.Edges = append(d.Edges, d.Edges[0]) },
			} {
				t.Run(name, func(t *testing.T) {
					var bad PeerCRLRoleDocument
					if json.Unmarshal(document, &bad) != nil {
						t.Fatal("copy")
					}
					mutate(&bad)
					if bad.validatePostgresV2Fields(profile, sources.Digest(), target.SubjectDeployment) == nil {
						t.Fatal("invalid PostgreSQL role admitted")
					}
				})
			}
			for _, owner := range []string{"", "unbound-owner", "provider-docker-control"} {
				if decode(document, sources.Digest(), role.Digest(), owner, role.LocalPrincipalDigest) == nil {
					t.Fatal("wrong owner admitted")
				}
			}
			for _, other := range Slice6DesiredFinalPostgresSignerTargets() {
				if other.SubjectDeployment != target.SubjectDeployment && decode(document, sources.Digest(), role.Digest(), other.SubjectDeployment, role.LocalPrincipalDigest) == nil {
					t.Fatal("cross-owner access admitted")
				}
			}
			if decode(document, testDigest("other-mapping"), role.Digest(), target.SubjectDeployment, role.LocalPrincipalDigest) == nil ||
				decode(document, sources.Digest(), testDigest("other-pin"), target.SubjectDeployment, role.LocalPrincipalDigest) == nil ||
				decode(document, sources.Digest(), role.Digest(), target.SubjectDeployment, testDigest("other-local")) == nil {
				t.Fatal("external pins ignored")
			}
			for _, bad := range [][]byte{append([]byte(" "), document...), append(bytes.Clone(document), document...),
				append(bytes.Clone(document[:len(document)-1]), []byte(`,"unknown":true}`)...),
				append(bytes.Clone(document[:len(document)-1]), []byte(`,"protocol":"duplicate"}`)...), bytes.Repeat([]byte(" "), (128<<10)+1)} {
				if decode(bad, sources.Digest(), role.Digest(), target.SubjectDeployment, role.LocalPrincipalDigest) == nil {
					t.Fatal("invalid encoding admitted")
				}
			}
			if role.validateV2Fields(profile, sources.Digest()) == nil {
				t.Fatal("ordinary role accepted PostgreSQL edge")
			}
			if role.ValidatePostgresV2(profile, sources.Digest(), target.SubjectDeployment, role.LocalPrincipalDigest) == nil {
				t.Fatal("public validator bypassed hold")
			}
			if _, err := DerivePostgresPeerCRLRoleDocumentV2(profile, sources, sources.Digest(), target.SubjectDeployment); err == nil {
				t.Fatal("public derive bypassed hold")
			}
			if _, err := DecodePostgresPeerCRLRoleDocumentV2(document, profile, sources.Digest(), role.Digest(), target.SubjectDeployment, role.LocalPrincipalDigest); err == nil {
				t.Fatal("public decode bypassed hold")
			}
		})
	}
	var ordinarySubject string
	for _, binding := range profile.TLSAgentBindings {
		if binding.SubjectDeployment == "provider-docker-control" {
			ordinarySubject = binding.SubjectPrincipalDigest
		}
	}
	ordinary, err := derivePeerCRLRoleDocumentV2Fields(profile, sources, ordinarySubject)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.validatePostgresV2Fields(profile, sources.Digest(), "provider-runtime") == nil {
		t.Fatal("PostgreSQL role accepted ordinary edges")
	}
}

func TestPrivatePeerCRLV2SnapshotIsolationAndAdmissionHold(t *testing.T) {
	profile := testCompleteV2Fields(t)
	sources := testPeerCRLSourcesV2(t, profile)
	beforeProfile, _ := json.Marshal(profile)
	beforeSources, _ := json.Marshal(sources)
	privateProfile, privateSources, err := copyPeerCRLSnapshotV2(profile, sources)
	if err != nil {
		t.Fatal(err)
	}
	profile.Principals[0].Name = "changed"
	for i := range profile.Principals {
		if p := &profile.Principals[i]; p.TLS != nil && len(p.TLS.DNSNames) > 0 {
			p.TLS.DNSNames[0] = "changed.invalid"
		}
		if p := &profile.Principals[i]; p.AuthorizationPrincipal != nil {
			p.AuthorizationPrincipal.Name = "changed"
		}
	}
	profile.TLSAgentBindings[0].AgentRequestKeyDigest = testDigest("changed")
	for name := range profile.SandboxGatewayLimits {
		delete(profile.SandboxGatewayLimits, name)
	}
	for name := range profile.ExternalResourceLimits {
		delete(profile.ExternalResourceLimits, name)
	}
	sources.Sources[0].IssuerID = "changed"
	sources.Edges[0].SourceID = "changed"
	afterProfile, _ := json.Marshal(privateProfile)
	afterSources, _ := json.Marshal(privateSources)
	if !bytes.Equal(beforeProfile, afterProfile) || !bytes.Equal(beforeSources, afterSources) {
		t.Fatal("snapshot aliases caller input")
	}
	p, s, index, err := CompilePrivatePeerCRLAuthorizerV2(privateProfile, privateSources, privateSources.Digest())
	if err == nil || !reflect.DeepEqual(p, ProfileV2{}) || !reflect.DeepEqual(s, PeerCRLSources{}) || index.MappingDigest() != "" {
		t.Fatal("held snapshot escaped compiler")
	}
	privateProfile.Principals[0].Name = strings.Repeat("a", maxBytes+1)
	if _, _, err := copyPeerCRLSnapshotV2(privateProfile, privateSources); err == nil {
		t.Fatal("oversized profile admitted")
	}
	privateSources.Sources[0].ID = strings.Repeat("a", (128<<10)+1)
	if _, _, err := copyPeerCRLSnapshotV2(ProfileV2{}, privateSources); err == nil {
		t.Fatal("oversized sources admitted")
	}
}
