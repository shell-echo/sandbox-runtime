package phase6security

import "testing"

func TestSlice6ManagedCertificateRequestTTL(t *testing.T) {
	for _, test := range []struct {
		name, reason    string
		maximum, rotate int64
		want            int64
	}{
		{name: "final profile", maximum: 900, rotate: 500, want: 869},
		{name: "short safe profile", maximum: 91, rotate: 40, want: 60},
		{name: "underflow", maximum: 60, rotate: 20, reason: "reject"},
		{name: "below minimum request", maximum: 90, rotate: 40, reason: "reject"},
		{name: "post-backdate rotation exceeds two thirds", maximum: 600, rotate: 390, reason: "reject"},
		{name: "profile rotation exceeds two thirds", maximum: 600, rotate: 401, reason: "reject"},
		{name: "maximum too large", maximum: 3601, rotate: 500, reason: "reject"},
		{name: "zero maximum", maximum: 0, rotate: 0, reason: "reject"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Slice6ManagedCertificateRequestTTL(test.maximum, test.rotate)
			if test.reason == "reject" {
				if err == nil || got != 0 {
					t.Fatal("invalid lifetime budget accepted")
				}
				return
			}
			if err != nil || got != test.want || got+Slice6VaultRoleBackdateSeconds > test.maximum {
				t.Fatalf("incorrect lifetime budget: got=%d err=%v", got, err)
			}
		})
	}
}
