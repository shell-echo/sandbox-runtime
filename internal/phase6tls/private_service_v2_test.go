package phase6tls

import (
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"testing"
)

func TestPrivateServiceV2ProcessGroupIsolation(t *testing.T) {
	if !privateServiceProcessMatches(12000, 13000, nil, 12000, 13000, []int{13000}) || !privateServiceProcessMatches(12000, 13000, []uint32{0}, 12000, 13000, []int{13000, 0}) {
		t.Fatal("exact identity rejected")
	}
	for _, v := range []struct {
		uid, gid int
		groups   []int
		extra    []uint32
	}{
		{0, 13000, nil, nil}, {12000, 0, nil, nil}, {12000, 13000, []int{0}, nil}, {12000, 13000, []int{13000}, []uint32{0}},
		{12000, 13000, []int{0, 42}, []uint32{0}}, {12000, 13000, []int{-1}, nil}, {12000, 13000, []int{42}, []uint32{42}},
	} {
		if privateServiceProcessMatches(12000, 13000, v.extra, v.uid, v.gid, v.groups) {
			t.Fatal("extra/missing group or identity accepted")
		}
	}
}
func TestPrivateServiceV2FactoriesCannotBypassProfileHold(t *testing.T) {
	p := phase6security.ProfileV2{Protocol: phase6security.ProtocolIDV2, Version: phase6security.VersionV2}
	for _, scope := range []string{"coding", "browser", "desktop", "scanner"} {
		a := PrivateServiceAuthorityV2{Scope: scope, Address: "127.0.0.1:8446", AgentSocket: "/must-not-open"}
		if _, _, _, err := PrivateServiceServerV2(p, a); err == nil {
			t.Fatal("server hold bypassed")
		}
		if _, _, err := PrivateServiceClientV2(p, a); err == nil {
			t.Fatal("client hold bypassed")
		}
	}
}
