package phase6security

import "testing"

func TestSlice6ExternalTransportPlanCoversEveryReviewedEdgeWithoutRoleBypass(t *testing.T) {
	plan := Slice6DesiredExternalTransports()
	if err := VerifySlice6DesiredExternalTransportCoverage(plan); err != nil {
		t.Fatalf("reviewed logical-to-physical transport plan rejected: %v", err)
	}
	if len(plan) != 12 {
		t.Fatalf("physical external dependency paths = %d, want 12", len(plan))
	}
	for _, path := range plan {
		if path.LogicalCaller != path.Dialer && path.Network == "network-"+path.LogicalCaller {
			t.Fatalf("brokered %s path bypasses broker on role network", path.Service)
		}
	}
	wrong := Slice6DesiredExternalTransports()
	wrong[0].Dialer = wrong[0].LogicalCaller
	if VerifySlice6DesiredExternalTransportCoverage(wrong) == nil {
		t.Fatal("direct browser-action-history bypass admitted")
	}
	wrong = Slice6DesiredExternalTransports()
	wrong[0].EdgeIDs = wrong[0].EdgeIDs[:1]
	if VerifySlice6DesiredExternalTransportCoverage(wrong) == nil {
		t.Fatal("missing actual egress edge admitted")
	}
	wrong = Slice6DesiredExternalTransports()
	wrong[0].Network = "external-uplink"
	if VerifySlice6DesiredExternalTransportCoverage(wrong) == nil {
		t.Fatal("unreviewed shared service network admitted")
	}
}
