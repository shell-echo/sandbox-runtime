package phase6profilebuilder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testSlice6CertificateKeys(t *testing.T) (CertificateKeySupply, map[string]string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]string)
	for _, id := range phase6security.Slice6DesiredCertificateKeyIDs() {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, id+".key")
		if err := os.WriteFile(path, private, 0o600); err != nil {
			t.Fatal(err)
		}
		clear(private)
		paths[id] = path
	}
	supply, err := LoadSlice6CertificateKeySupply(paths)
	if err != nil {
		t.Fatal(err)
	}
	return supply, paths
}

func TestSlice6CertificateDraftBindsControllerAndPurposeSpecificAgents(t *testing.T) {
	topology, err := bindSlice6FinalTopologyDraft(testSlice6TrustDraft(t), testSlice6ExternalSupply())
	if err != nil {
		t.Fatal(err)
	}
	egressKeys, _ := testSlice6EgressKeys(t)
	egress, err := bindSlice6EgressDraft(topology, egressKeys)
	if err != nil {
		t.Fatal(err)
	}
	keys, paths := testSlice6CertificateKeys(t)
	bound, err := bindSlice6CertificateDraft(egress, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.TLSAgentBindings)+len(bound.PostgresClientAgents) !=
		len(phase6security.Slice6DesiredCertificateKeyIDs())-3 || len(bound.PostgresClientAgents) != 9 ||
		len(bound.Principals) != 82 {
		t.Fatal("closed certificate agent inventory not bound")
	}
	for _, binding := range bound.TLSAgentBindings {
		if binding.AgentRequestKeyDigest != phase6security.TLSAgentRequestPublicKeyDigest(keys.keys[binding.AgentRequestKeyID]) {
			t.Fatal("TLS agent key digest mismatch")
		}
	}
	controllerFound := false
	for index, principal := range bound.Principals {
		if principal.Name != "certificate-controller" {
			continue
		}
		controllerFound = true
		if len(principal.Mounts) <= len(egress.Principals[index].Mounts) ||
			!slice6MountFound(principal, "private_socket", bound.CertificateController.SelfSocketDirectory,
				bound.CertificateController.SelfSocketStorageID, false) {
			t.Fatal("controller signer socket missing")
		}
	}
	if !controllerFound || bound.VerifySources(context.Background(), time.Now()) == nil ||
		func() bool {
			_, err := BindSlice6CertificateDraft(context.Background(), egress, keys, time.Now())
			return err == nil
		}() {
		t.Fatal("synthetic earlier sources admitted for final freeze")
	}
	ids := phase6security.Slice6DesiredCertificateKeyIDs()
	path := paths[ids[0]]
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if keys.VerifySources() == nil {
		t.Fatal("relaxed controller or agent key permissions admitted")
	}
	changed := egress
	changed.Principals = slices.Clone(egress.Principals)
	for index := range changed.Principals {
		if changed.Principals[index].Name == "certificate-controller" {
			changed.Principals[index].Mounts = append(slices.Clone(changed.Principals[index].Mounts),
				phase6security.Mount{Target: "/run/certificate-controller/self", Kind: "private_socket", StorageID: "stolen"})
		}
	}
	if _, err := bindSlice6CertificateDraft(changed, keys); err == nil {
		t.Fatal("unreviewed controller socket mount admitted")
	}
}
