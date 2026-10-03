package phase6security

import "testing"

func TestGuestReceiptProfileRequiresBothLocalCandidates(t *testing.T) {
	profile := reviewedSlice6ImageFixture(t)
	origin := guestReceiptTestOrigin(profile)
	if err := VerifySlice6GuestReceiptLocalProfile(profile, origin); err != nil {
		t.Fatalf("local Product/Guest boundary rejected: %v", err)
	}
	for _, name := range []string{"product-runtime", "guest-runtime"} {
		t.Run(name+" registry", func(t *testing.T) {
			candidate := profile
			candidate.Principals = append([]Principal(nil), profile.Principals...)
			for index := range candidate.Principals {
				if candidate.Principals[index].Name == name {
					candidate.Principals[index].ImageLocation = "registry"
					candidate.Principals[index].ImageReference = "registry.example.test/runtime@" + candidate.Principals[index].ImageDigest
				}
			}
			candidate.ProfileDigest = candidate.Digest()
			if VerifySlice6GuestReceiptLocalProfile(candidate, origin) == nil {
				t.Fatal("registry or mixed local/registry profile admitted")
			}
		})
	}
	if VerifySlice6GuestReceiptLocalProfile(profile, origin+"/wrong") == nil {
		t.Fatal("wrong private Guest edge admitted")
	}
	broken := profile
	broken.ProfileDigest = "sha256:invalid"
	if VerifySlice6GuestReceiptLocalProfile(broken, origin) == nil {
		t.Fatal("wrong profile digest admitted")
	}
}

func guestReceiptTestOrigin(profile Profile) string {
	for _, edge := range profile.TrustEdges {
		if edge.ID == "guest-product" {
			return "wss://" + edge.TargetAddress + edge.RoutePath
		}
	}
	return ""
}
