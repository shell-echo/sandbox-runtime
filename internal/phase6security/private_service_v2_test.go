package phase6security

import "testing"

func TestPrivateServiceV2SelectsExactScopedEdgesAndRetainsHold(t *testing.T) {
	p := testCompleteV2Fields(t)
	for _, scope := range []string{"browser", "coding", "desktop", "scanner"} {
		edgeID := "provider-" + scope + "-control"
		if scope == "scanner" {
			edgeID = "provider-coding-scanner"
		}
		var address string
		for _, e := range p.TrustEdges {
			if e.ID == edgeID {
				address = e.TargetAddress
			}
		}
		b, err := p.privateServiceBoundaryFields(scope, address)
		if err != nil || b.Edge.ID != edgeID || b.Provider.Name != b.Edge.From || b.Service.Name != b.Edge.To {
			t.Fatalf("scope %s: %+v %v", scope, b, err)
		}
		if _, err := p.PrivateServiceBoundary(scope, address); err == nil {
			t.Fatal("public hold bypassed")
		}
		if _, err := p.privateServiceBoundaryFields(scope, "0.0.0.0:8446"); err == nil {
			t.Fatal("unbound listener accepted")
		}
	}
	if _, err := p.privateServiceBoundaryFields("other", ""); err == nil {
		t.Fatal("unknown scope accepted")
	}
	for _, m := range []Mount{{Target: ScannerRuntimeDirectoryV2, Kind: "tmpfs", MaxBytes: 1 << 30}, {Target: "/run", Kind: "tmpfs", MaxBytes: ScannerRuntimeMaxBytesV2}, {Target: ScannerRuntimeDirectoryV2 + "/alias", Kind: "tmpfs", MaxBytes: ScannerRuntimeMaxBytesV2}} {
		q := p
		q.Principals = append([]Principal(nil), p.Principals...)
		q.Principals[0].Mounts = append(append([]Mount(nil), p.Principals[0].Mounts...), m)
		if validateScannerRuntimeMountsV2(q, Principal{Name: p.ArtifactScanner.Deployment}) == nil {
			t.Fatal("unbound runtime directory accepted")
		}
	}
}
