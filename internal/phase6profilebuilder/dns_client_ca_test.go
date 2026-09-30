package phase6profilebuilder

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6DNSClientCAReopensExactSingleBrokerIssuer(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(testSlice6OperatorDirectory(t), "broker-ca.pem")
	if err := os.WriteFile(path, testSlice6CABundle(t, "broker-only", now), 0o400); err != nil {
		t.Fatal(err)
	}
	input := DNSClientCAInput{BundlePath: path, IssuerID: "11111111-1111-4111-8111-111111111111"}
	supply, err := LoadSlice6DNSClientCASupply(input, now)
	if err != nil || supply.VerifySources(now) != nil {
		t.Fatalf("single broker CA source rejected: %v", err)
	}
	bound, err := supply.Binding()
	if err != nil || bound.ArtifactID != "dns-broker-client-ca" ||
		!slices.Equal(bound.AllowedSubjects, phase6security.Slice6DNSBrokerSubjects()) {
		t.Fatalf("broker CA binding mismatch: %v", err)
	}
	if _, err := LoadSlice6DNSClientCASupply(DNSClientCAInput{BundlePath: path, IssuerID: "default"}, now); err == nil {
		t.Fatal("mutable default issuer admitted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, testSlice6CABundle(t, "replacement", now), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if supply.VerifySources(now) == nil {
		t.Fatal("changed broker CA source admitted")
	}
}
