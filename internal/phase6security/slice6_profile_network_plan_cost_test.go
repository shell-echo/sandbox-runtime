package phase6security

import "testing"

// This is a synthetic same-call cost sample, not live network evidence.
func BenchmarkSlice6BindDesiredNetworkPlan(b *testing.B) {
	draft := validProfile()
	first, err := BindSlice6DesiredNetworkPlan(draft)
	if err != nil {
		b.Fatal(err)
	}
	expected := first.ProfileDigest
	var bound Profile
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bound, err = BindSlice6DesiredNetworkPlan(draft)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if bound.ProfileDigest != expected {
		b.Fatal("binding produced a different digest")
	}
}
