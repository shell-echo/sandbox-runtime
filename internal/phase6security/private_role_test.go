package phase6security

import "testing"

func TestPrivateRoleAttachBoundaryBindsDistinctProviderInstances(t *testing.T) {
	profile := validProfile()
	for _, caseValue := range []struct {
		role, edgeID, provider, receiver string
	}{
		{"browser", "provider-browser-attach", "provider-browser-runtime", "browser-runtime-role"},
		{"desktop", "provider-desktop-attach", "provider-desktop-runtime", "desktop-runtime-role"},
	} {
		var address string
		for _, edge := range profile.TrustEdges {
			if edge.ID == caseValue.edgeID {
				address = edge.TargetAddress
			}
		}
		edge, provider, receiver, serverAnchor, clientAnchor, err := profile.PrivateRoleAttachBoundary(caseValue.role, address)
		if err != nil || edge.ID != caseValue.edgeID || provider.Name != caseValue.provider ||
			receiver.Name != caseValue.receiver || serverAnchor.ID != edge.ServerAnchorID ||
			clientAnchor.ID != edge.ClientAnchorID {
			t.Fatalf("%s attach boundary mismatch: %v", caseValue.role, err)
		}
		for _, wrong := range []string{"127.0.0.1:8450", address + "/executor", ""} {
			if _, _, _, _, _, err := profile.PrivateRoleAttachBoundary(caseValue.role, wrong); err == nil {
				t.Fatalf("%s accepted incorrect listener %q", caseValue.role, wrong)
			}
		}
	}
	if _, _, _, _, _, err := profile.PrivateRoleAttachBoundary("coding", "127.0.0.1:8450"); err == nil {
		t.Fatal("coding Provider alias accepted as Browser/Desktop attach")
	}
}

func TestPrivateRoleBackendBoundaryRejectsAttachAlias(t *testing.T) {
	profile := validProfile()
	for _, caseValue := range []struct {
		role, edgeID, caller, backend string
	}{
		{"browser", "executor-browser", "browser-runtime-role", "browser-executor-backend"},
		{"desktop", "executor-desktop", "desktop-runtime-role", "desktop-executor-backend"},
	} {
		var origin string
		for _, edge := range profile.TrustEdges {
			if edge.ID == caseValue.edgeID {
				origin = "wss://" + edge.TargetAddress + edge.RoutePath
			}
		}
		edge, caller, backend, serverAnchor, clientAnchor, err := profile.PrivateRoleBackendBoundary(caseValue.role, origin)
		if err != nil || edge.ID != caseValue.edgeID || caller.Name != caseValue.caller ||
			backend.Name != caseValue.backend || serverAnchor.ID != edge.ServerAnchorID ||
			clientAnchor.ID != edge.ClientAnchorID {
			t.Fatalf("%s backend boundary mismatch: %v", caseValue.role, err)
		}
		for _, wrong := range []string{origin + "/executor", "wss://" + edge.TargetAddress + "/private/terminal", ""} {
			if _, _, _, _, _, err := profile.PrivateRoleBackendBoundary(caseValue.role, wrong); err == nil {
				t.Fatalf("%s accepted incorrect backend origin %q", caseValue.role, wrong)
			}
		}
	}
}

func TestPrivateRoleBackendRequiresSingleCanonicalDNS(t *testing.T) {
	for _, backend := range []string{"browser-executor-backend", "desktop-executor-backend"} {
		for name, dns := range map[string][]string{
			"absent": nil, "multiple": {"a.sandbox-runtime.test", "b.sandbox-runtime.test"},
			"wildcard": {"*.sandbox-runtime.test"}, "IP": {"127.0.0.1"},
			"uppercase": {"Backend.sandbox-runtime.test"},
		} {
			t.Run(backend+"/"+name, func(t *testing.T) {
				profile := validProfile()
				for index := range profile.Principals {
					if profile.Principals[index].Name == backend {
						profile.Principals[index].TLS.DNSNames = dns
					}
				}
				profile.ProfileDigest = profile.Digest()
				if profile.Validate() == nil {
					t.Fatal("non-canonical backend server identity accepted")
				}
				if _, _, _, _, err := profile.ExecutorTLSBoundary(backend, 8443); err == nil {
					t.Fatal("executor TLS boundary accepted non-canonical backend DNS")
				}
			})
		}
	}
}
