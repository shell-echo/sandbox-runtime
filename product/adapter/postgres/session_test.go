package productpostgres

import (
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestAuthorizeSessionSlotRequiresExactBrowserAuthority(t *testing.T) {
	exact := []byte(`[{"capability_id":"sandbox.browser","version":"1.0.0","profile_id":"browser-v1"}]`)
	for _, kind := range []string{product.SessionKindBrowserAutomation, product.SessionKindBrowserLive} {
		if err := authorizeSessionSlot(kind, "browser", exact); err != nil {
			t.Fatalf("kind=%q err=%v", kind, err)
		}
	}
	for _, test := range []struct {
		name         string
		kind         string
		slotKind     string
		capabilities []byte
		want         error
	}{
		{name: "browser on code slot", kind: product.SessionKindBrowserLive, slotKind: "code", capabilities: exact, want: product.ErrCapabilityUnsupported},
		{name: "missing capability", kind: product.SessionKindBrowserAutomation, slotKind: "browser", capabilities: []byte(`[]`), want: product.ErrCapabilityUnsupported},
		{name: "wrong profile", kind: product.SessionKindBrowserAutomation, slotKind: "browser", capabilities: []byte(`[{"capability_id":"sandbox.browser","version":"1.0.0","profile_id":"other"}]`), want: product.ErrCapabilityUnsupported},
		{name: "malformed authority", kind: product.SessionKindBrowserAutomation, slotKind: "browser", capabilities: []byte(`{`), want: product.ErrStoreUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := authorizeSessionSlot(test.kind, test.slotKind, test.capabilities); !errors.Is(err, test.want) {
				t.Fatalf("err=%v want=%v", err, test.want)
			}
		})
	}
}

func TestBrowserSessionOutboxIsSeparateFromTerminal(t *testing.T) {
	if got := sessionOutboxType(product.SessionKindTerminal, "open"); got != "session.open" {
		t.Fatalf("terminal type=%q", got)
	}
	for _, kind := range []string{product.SessionKindBrowserAutomation, product.SessionKindBrowserLive} {
		if got := sessionOutboxType(kind, "open"); got != "browser_session.open" {
			t.Fatalf("browser open type=%q", got)
		}
		if got := sessionOutboxType(kind, "close"); got != "browser_session.close" {
			t.Fatalf("browser close type=%q", got)
		}
	}
}
