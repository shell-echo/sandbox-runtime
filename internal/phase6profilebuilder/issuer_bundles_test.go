package phase6profilebuilder

import (
	"bytes"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6CandidateIssuerBundleMapping(t *testing.T) {
	now := time.Now().UTC()
	general := testSlice6CABundle(t, "general", now)
	broker := testSlice6CABundle(t, "broker-only", now)
	extra := testSlice6CABundle(t, "unexpected", now)
	original := map[string][]byte{
		"external-server-ca": general,
		"internal-client-ca": general,
		"internal-server-ca": append(bytes.Clone(general), broker...),
		"postgres-client-ca": general,
		"vault-client-ca":    general,
	}
	// The baseline follows the reviewed two-issuer mapping, not symmetric
	// inclusion of broker-only in every bundle.
	check := func(bundles map[string][]byte, dns []byte) error {
		t.Helper()
		anchors := phase6security.Slice6DesiredFinalTrustAnchorTemplates()
		for i := range anchors {
			anchors[i].BundleDigest = digestSlice6Bytes(bundles[anchors[i].ID])
		}
		return verifySlice6CandidateIssuerBundles(TrustAnchorSupply{anchors: anchors, bundles: bundles},
			DNSClientCASupply{bundle: dns})
	}
	if err := check(original, broker); err != nil {
		t.Fatalf("reviewed two-issuer mapping rejected: %v", err)
	}
	reversed := cloneSlice6IssuerTestBundles(original)
	reversed["internal-server-ca"] = append(bytes.Clone(broker), general...)
	if err := check(reversed, broker); err != nil {
		t.Fatal("the same exact DER issuer set depends on PEM order")
	}
	for name, change := range map[string]func(map[string][]byte){
		"missing broker on local server": func(value map[string][]byte) { value["internal-server-ca"] = general },
		"broker on local client":         func(value map[string][]byte) { value["internal-client-ca"] = append(bytes.Clone(general), broker...) },
		"broker on PostgreSQL client":    func(value map[string][]byte) { value["postgres-client-ca"] = broker },
		"extra internal server root": func(value map[string][]byte) {
			value["internal-server-ca"] = append(bytes.Clone(value["internal-server-ca"]), extra...)
		},
		"duplicate internal server root": func(value map[string][]byte) {
			value["internal-server-ca"] = append(bytes.Clone(value["internal-server-ca"]), broker...)
		},
		"malformed CA document": func(value map[string][]byte) { value["vault-client-ca"] = []byte("not a PEM") },
	} {
		t.Run(name, func(t *testing.T) {
			value := cloneSlice6IssuerTestBundles(original)
			change(value)
			if check(value, broker) == nil {
				t.Fatal("wrong issuer set admitted")
			}
		})
	}
	if check(original, general) == nil {
		t.Fatal("DNS general issuer admitted as broker-only")
	}
}

func cloneSlice6IssuerTestBundles(original map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(original))
	for id, bundle := range original {
		clone[id] = bytes.Clone(bundle)
	}
	return clone
}
