//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ProductRuntimeOfflineInputsEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_RUNTIME_OFFLINE_INPUTS"

// This executes the Product runtime's source-bound config and private-volume
// preparation against synthetic public CA certificates. It neither asks Vault
// to issue anything nor proves that Product PID1 or the other 73 sockets ran.
func TestSlice6ProductRuntimeOfflineInputs(t *testing.T) {
	if os.Getenv(slice6ProductRuntimeOfflineInputsEnv) != "1" {
		t.Skip("set " + slice6ProductRuntimeOfflineInputsEnv + "=1 with immutable R3 source and OCI inputs")
	}
	if os.Getenv(slice6VaultTrustSwitchEnv) == "1" {
		t.Fatal("offline Product input validation must not enable the live Vault issuer gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	static := slice6VaultStaticInputsFromEnvironment()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	t.Cleanup(func() {
		if cleaned {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if err := run.cleanup(cleanupCtx); err != nil {
			t.Errorf("offline Product input exact Docker cleanup: %v", err)
		}
	})
	root := t.TempDir()
	// Two existing public-only Go toolchain fixtures avoid even test-CA
	// signing. They are never represented as Vault-issued certificates.
	fixtureCA := func(name string) ([]byte, *x509.Certificate) {
		t.Helper()
		contents, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "crypto", "x509", "testdata",
			"nist-pkits", "certs", name))
		if err != nil {
			t.Fatal("offline public CA fixture unavailable")
		}
		certificate, err := x509.ParseCertificate(contents)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) !=
				x509.KeyUsageCertSign|x509.KeyUsageCRLSign ||
			time.Now().Before(certificate.NotBefore) || !time.Now().Before(certificate.NotAfter) {
			t.Fatal("offline public CA fixture lacks valid cert/CRL signing scope")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: contents}), certificate
	}
	generalPEM, generalCertificate := fixtureCA("TrustAnchorRootCertificate.crt")
	brokerPEM, brokerCertificate := fixtureCA("BasicSelfIssuedCRLSigningKeyCACert.crt")
	general := slice6VaultRoot{ID: "11111111-1111-4111-8111-111111111111",
		PEM:         generalPEM,
		Certificate: generalCertificate}
	broker := slice6VaultRoot{ID: "22222222-2222-4222-8222-222222222222",
		PEM:         brokerPEM,
		Certificate: brokerCertificate}
	composed := slice6VaultComposeCandidateProfile(t, ctx, root, run.id, general, broker, static)
	// This is a construction-only Guest authority fixture. The ID is not a
	// durable Product binding; the actual selected image supplies its shell
	// digest for this run rather than reusing a historical R3 observation.
	guestPlan, guestPlanErr := slice6BuildGuestRuntimeLaunchPlan(composed.Profile)
	if guestPlanErr != nil || guestPlan.ProductNetwork.Name != "guest-product" ||
		guestPlan.InternalNetwork.Name != "network-guest-runtime" ||
		guestPlan.MaterialSocketID == guestPlan.TLSSocketID {
		t.Fatalf("offline Guest source-bound launch plan unavailable: %v", guestPlanErr)
	}
	guestShellDigest, guestShellErr := slice6MeasureGuestShell(ctx, run, guestPlan.Principal)
	if guestShellErr != nil {
		t.Fatalf("offline selected Guest toolchain observation unavailable: %v", guestShellErr)
	}
	guestInputs, guestInputErr := slice6BuildGuestRuntimeInputs(composed, run.id,
		"gst-phase6-offline", 1, guestShellDigest)
	if guestInputErr != nil || len(guestInputs) != 6 {
		t.Fatalf("offline Guest private startup input construction failed: count=%d err=%v", len(guestInputs), guestInputErr)
	}
	if _, err := slice6BuildGuestRuntimeInputs(composed, run.id, "gst-phase6-offline", 0,
		guestShellDigest); err == nil {
		t.Fatal("Guest input construction accepted a missing Product binding generation")
	}
	guestArchive, err := phase6security.BuildSlice6PrivateConfigArchive(composed.Profile,
		"guest-runtime", guestInputs)
	if err != nil {
		t.Fatal("Guest private config archive unavailable")
	}
	slice6PrepareOneControllerPrivateConfig(t, ctx, run, composed.Profile, "guest-runtime", guestArchive)
	config, err := slice6BuildProductRuntimeConfig(composed)
	if err != nil {
		t.Fatalf("source-bound Product runtime config rejected: %v", err)
	}
	if len(config) == 0 || strings.Contains(string(config), "PRIVATE KEY") ||
		strings.Contains(string(config), "postgres://") {
		t.Fatal("Product runtime config contains absent or secret material")
	}
	clear(config)
	plan, err := slice6BuildProductRuntimeLaunchPlan(composed.Profile)
	if err != nil || len(plan.Networks) != 7 || len(plan.SocketStorageID) != 3 {
		t.Fatalf("Product runtime source-bound launch plan unavailable: %v", err)
	}
	var ingress phase6security.Network
	for _, network := range plan.Networks {
		if network.Name == "ingress-product" {
			ingress = network
		}
	}
	observerIP, err := slice6ProductRuntimeObserverIP(ingress)
	if err != nil || observerIP == "" {
		t.Fatalf("Product component observer does not have a non-reserved ingress endpoint: %v", err)
	}
	sourceDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal("Product component observer source checkout unavailable")
	}
	observer, err := slice6BuildProductRuntimeObserver(t, ctx, sourceDir)
	if err != nil || len(observer.Digest) != 32 {
		t.Fatalf("Product component observer binary not built from current source: %v", err)
	}
	// These placeholders model only the exact 73 allocations in the prior
	// controller→break-glass→Guest→Product→migration preparation sequence.
	// They are not claimed as real volumes or running socket servers.
	existing := slice6OfflinePriorProductRuntimeSockets(t, composed.Profile)
	postgresSigner, _, _, _, _, err := composed.Profile.PostgresClientSignerForOwner("product-runtime")
	if err != nil || len(existing) != 73 || existing[postgresSigner.SocketStorageID] != "" {
		t.Fatalf("offline prior-socket inventory drift: count=%d error=%v", len(existing), err)
	}
	result := slice6PrepareProductRuntimeInputs(t, ctx, run, composed, existing)
	if len(result) != 74 || !strings.HasPrefix(result[postgresSigner.SocketStorageID], "sr-p6-socket-") {
		t.Fatal("Product runtime input preparation did not add the exact signer socket")
	}
	for _, resource := range []string{"container", "network", "volume"} {
		ids, err := run.labeledIDs(ctx, resource)
		if err != nil {
			t.Fatalf("inspect offline Product %s resources: %v", resource, err)
		}
		want := 0
		if resource == "volume" {
			want = 4 // Guest config, Product config, PG-agent config, Product PG signer socket.
		}
		if len(ids) != want {
			t.Fatalf("offline Product %s resources=%d, want %d", resource, len(ids), want)
		}
	}
	if os.Getenv(slice6GuestFixtureAdmissionNoIssuerEnv) == "1" {
		slice6GuestFixtureAdmissionNoIssuer(t, ctx, run, static, composed, plan, result)
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("offline Product input exact Docker cleanup failed: %v", err)
	}
	cleaned = true
	if os.Getenv(slice6GuestFixtureAdmissionNoIssuerEnv) == "1" {
		t.Log("synthetic-CA source-bound Guest/Product startup inputs and finite Guest fixture create/inspect admitted; all run-owned diagnostic containers/networks/volumes cleaned to zero; no Vault issuance, SQL, fixture execution or Guest/Product PID1")
	} else {
		t.Log("synthetic-CA source-bound Guest/Product startup inputs admitted; six Guest private files, four Product files, two PG-agent files and one signer socket passed exact Docker mode/digest/read-only checks; four run-owned volumes cleaned to zero; no Vault issuance or Guest/Product PID1")
	}
}

func slice6OfflinePriorProductRuntimeSockets(t *testing.T, profile phase6security.Profile) map[string]string {
	t.Helper()
	result := make(map[string]string, 73)
	add := func(id string) {
		t.Helper()
		if id == "" || result[id] != "" {
			t.Fatal("offline prior socket identity missing or repeated")
		}
		result[id] = "offline-prior-socket-" + id
	}
	for _, binding := range profile.CredentialIssuerSockets {
		add(binding.SocketStorageID)
	}
	add(profile.CertificateController.CredentialController.SocketStorageID)
	add(profile.CertificateController.SelfSocketStorageID)
	for _, binding := range profile.TLSAgentBindings {
		add(binding.ControllerSocketStorageID)
	}
	for _, binding := range profile.PostgresClientAgents {
		add(binding.ControllerSocketStorageID)
	}
	if len(result) != 50 {
		t.Fatalf("offline controller socket inventory=%d, want 50", len(result))
	}
	for _, binding := range profile.BreakGlassSockets {
		add(binding.SocketStorageID)
	}
	if len(result) != 65 {
		t.Fatalf("offline break-glass socket inventory=%d, want 65", len(result))
	}
	for _, item := range []struct {
		owner, agentSubject string
	}{
		{owner: "guest-runtime", agentSubject: "guest-agent"},
		{agentSubject: "product-runtime"},
		{owner: "product-runtime", agentSubject: "product-runtime-agent"},
		{owner: "product-migration-job", agentSubject: "product-migration-agent"},
	} {
		binding, _, _, err := profile.TLSAgentForSubject(item.agentSubject)
		if err != nil {
			t.Fatal("offline ordinary TLS signer binding unavailable")
		}
		add(binding.SocketStorageID)
		if item.owner != "" {
			material, err := profile.Slice6MaterialSocketForOwner(item.owner)
			if err != nil {
				t.Fatal("offline material socket binding unavailable")
			}
			add(material.SocketStorageID)
		}
		if item.owner == "product-migration-job" {
			postgres, _, _, _, _, err := profile.PostgresClientSignerForOwner(item.owner)
			if err != nil {
				t.Fatal("offline migration PostgreSQL signer binding unavailable")
			}
			add(postgres.SocketStorageID)
		}
	}
	if len(result) != 73 {
		t.Fatalf("offline prior Product socket inventory=%d, want 73", len(result))
	}
	return result
}
