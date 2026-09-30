package phase6profilebuilder

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testSlice6CertificateDraft(t *testing.T) CertificateDraft {
	t.Helper()
	topology, err := bindSlice6FinalTopologyDraft(testSlice6TrustDraft(t), testSlice6ExternalSupply())
	if err != nil {
		t.Fatal(err)
	}
	egressKeys, _ := testSlice6EgressKeys(t)
	egress, err := bindSlice6EgressDraft(topology, egressKeys)
	if err != nil {
		t.Fatal(err)
	}
	certificateKeys, _ := testSlice6CertificateKeys(t)
	certificate, err := bindSlice6CertificateDraft(egress, certificateKeys)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestSlice6StaticDraftBindsClosedNonSecretProfileFields(t *testing.T) {
	before := testSlice6CertificateDraft(t)
	bound, err := bindSlice6StaticDraft(before)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.SandboxIdentitySlots) != 2 || len(bound.ProviderDatabases) != 2 ||
		len(bound.PublicListeners) != 2 || len(bound.IngressBindings) != 2 ||
		len(bound.CleanupClasses) != 6 || bound.PostgresServerAuth.Scope != "shared_nine_roles" {
		t.Fatal("static profile fields incomplete")
	}
	// A synthetic executable digest below is deliberately confined to this
	// structural test. The production finalizer must read the real Desktop OCI
	// broker bytes; this test profile is never launched or accepted as evidence.
	identity := bound.Principals[0].AuthorizationPrincipal
	if identity == nil {
		t.Fatal("missing test principal identity")
	}
	profile := phase6security.Profile{Protocol: phase6security.ProtocolID, Version: phase6security.Version,
		Revision: "slice6-structural-test", EnvironmentDigest: identity.EnvironmentDigest,
		PrincipalProfileDigest: identity.ProfileDigest, Principals: bound.Principals,
		SandboxIdentitySlots: bound.SandboxIdentitySlots, ProviderDatabases: bound.ProviderDatabases,
		PostgresServerAuth: bound.PostgresServerAuth, Networks: bound.Networks, External: bound.External,
		TrustEdges: bound.TrustEdges, TrustAnchors: bound.TrustAnchors,
		PublicListeners: bound.PublicListeners, IngressBindings: bound.IngressBindings,
		CertificateController:   bound.CertificateController,
		CredentialIssuerSockets: bound.CredentialIssuerSockets,
		TLSAgentBindings:        bound.TLSAgentBindings, PostgresClientAgents: bound.PostgresClientAgents,
		EgressPolicies: bound.EgressPolicies, CleanupClasses: bound.CleanupClasses,
		Components: []phase6security.Component{{Name: "desktop-broker", ParentDeployment: "desktop-sandbox-runtime",
			Executable:       "/usr/local/libexec/sandbox-runtime/desktop-broker",
			ExecutableDigest: digestSlice6Bytes([]byte("structural-test-only")),
			Argv:             []string{"/usr/local/libexec/sandbox-runtime/desktop-broker", "serve"},
			Socket:           "/tmp/sandbox-runtime-desktop-broker.sock", BrokerProtocol: "sandbox.runtime/desktop-broker/v1",
			SessionProtocol: "sandbox.runtime/desktop-session.v2"}}}
	profile.Principals = slices.Clone(bound.Principals)
	for index := range profile.Principals {
		principal := &profile.Principals[index]
		principal.ImageReference = principal.ImageDigest
		principal.ImageLocation = "local"
		principal.ImageIdentityKind = phase6security.ImageIdentityOCIManifest
		principal.ImageConfigDigest = digestSlice6Bytes([]byte("synthetic-image-config/" + principal.Name))
	}
	profile.SandboxIdentitySlots = slices.Clone(bound.SandboxIdentitySlots)
	for index := range profile.SandboxIdentitySlots {
		for _, principal := range profile.Principals {
			if profile.SandboxIdentitySlots[index].Template == principal.Name {
				profile.SandboxIdentitySlots[index].TemplateDigest = phase6security.SandboxTemplateDigest(principal)
			}
		}
	}
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("static fields do not form a structurally valid test profile: %v", err)
	}
	if len(before.Principals[0].Listeners) != 0 && before.Principals[0].Kind != "egress_broker" {
		t.Fatal("static builder mutated earlier draft")
	}
	if bound.VerifySources(context.Background(), time.Now()) == nil ||
		func() bool {
			_, err := BindSlice6StaticDraft(context.Background(), before, time.Now())
			return err == nil
		}() {
		t.Fatal("synthetic upstream sources admitted to final freeze")
	}
	changed := before
	changed.Principals = slices.Clone(before.Principals)
	for index := range changed.Principals {
		if changed.Principals[index].Name == "public-ingress-relay" {
			changed.Principals[index].Listeners = []phase6security.Listener{{Name: "alternate", Protocol: "tcp", Port: 9999}}
		}
	}
	if _, err := bindSlice6StaticDraft(changed); err == nil {
		t.Fatal("preexisting public relay listener admitted")
	}
}
