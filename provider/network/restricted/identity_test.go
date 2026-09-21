package restricted

import "testing"

func TestSealedBrowserAndDesktopIdentitiesAreDistinct(t *testing.T) {
	browser, err := BrowserIdentity("namespace-1", "controller-1", "sandbox-1", "session-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	desktop, err := DesktopIdentity("namespace-1", "controller-1", "sandbox-1", "session-1", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if browser.Role() != "browser" || desktop.Role() != "desktop" || browser.WorkloadName() == desktop.WorkloadName() || browser.Digest() == desktop.Digest() {
		t.Fatalf("browser=%#v desktop=%#v", browser, desktop)
	}
	if browser.WorkloadName() != "sandbox-runtime-browser-36709253cbdcb9fb6c6243c00fc84c8f" || desktop.WorkloadName() != "sandbox-runtime-desktop-36709253cbdcb9fb6c6243c00fc84c8f" {
		t.Fatalf("names = %q, %q", browser.WorkloadName(), desktop.WorkloadName())
	}
}

func TestIdentityRejectsUnboundedOrMissingAuthority(t *testing.T) {
	for _, test := range []struct {
		namespace, controller, sandbox, session string
		generation, fence                       int64
	}{
		{controller: "controller", sandbox: "sandbox", session: "session", generation: 1, fence: 1},
		{namespace: "namespace", sandbox: "sandbox", session: "session", generation: 1, fence: 1},
		{namespace: "namespace", controller: "controller", session: "session", generation: 1, fence: 1},
		{namespace: "namespace", controller: "controller", sandbox: "sandbox", generation: 1, fence: 1},
		{namespace: "namespace", controller: "controller", sandbox: "sandbox", session: "session", fence: 1},
		{namespace: "namespace", controller: "controller", sandbox: "sandbox", session: "session", generation: 1},
	} {
		if _, err := BrowserIdentity(test.namespace, test.controller, test.sandbox, test.session, test.generation, test.fence); err == nil {
			t.Fatalf("accepted %#v", test)
		}
	}
}
