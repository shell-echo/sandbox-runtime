package product

import (
	"errors"
	"strings"
	"testing"
)

func TestBrowserPolicyDenyByDefaultMatrix(t *testing.T) {
	policy := BrowserPolicy{Revision: 1}
	actions := []BrowserPolicyAction{
		{Kind: BrowserActionKeyboard}, {Kind: BrowserActionPointer}, {Kind: BrowserActionTouch, TouchPoints: 1},
		{Kind: BrowserActionClipboardRead}, {Kind: BrowserActionClipboardWrite, Text: "value"},
		{Kind: BrowserActionUpload}, {Kind: BrowserActionDownload},
		{Kind: BrowserActionNavigate, SourceOrigin: "https://example.test", TargetURL: "https://example.test/"},
		{Kind: BrowserActionPopup, SourceOrigin: "https://example.test", TargetURL: "https://example.test/"},
		{Kind: BrowserActionPermission, Permission: "camera"},
	}
	for _, action := range actions {
		if err := policy.Authorize(action); !errors.Is(err, ErrForbidden) {
			t.Fatalf("default policy admitted %q: %v", action.Kind, err)
		}
	}
}

func TestBrowserPolicyBoundsActivationConsentAndOrigins(t *testing.T) {
	policy := testPermissiveBrowserPolicy()
	allowed := []BrowserPolicyAction{
		{Kind: BrowserActionKeyboard},
		{Kind: BrowserActionPointer},
		{Kind: BrowserActionTouch, TouchPoints: 10},
		{Kind: BrowserActionClipboardRead, HasUserActivation: true, Consent: true},
		{Kind: BrowserActionClipboardWrite, Text: "bounded", HasUserActivation: true, Consent: true},
		{Kind: BrowserActionNavigate, SourceOrigin: "https://app.example", TargetURL: "https://app.example/page"},
		{Kind: BrowserActionPopup, SourceOrigin: "https://app.example", TargetURL: "https://files.example/view", OpenPopupCount: 0, HasUserActivation: true},
		{Kind: BrowserActionPermission, Permission: "clipboard-read", HasUserActivation: true, Consent: true},
	}
	for _, action := range allowed {
		if err := policy.Authorize(action); err != nil {
			t.Fatalf("action %q denied: %v", action.Kind, err)
		}
	}
	denied := []BrowserPolicyAction{
		{Kind: BrowserActionTouch, TouchPoints: 11},
		{Kind: BrowserActionClipboardRead, Consent: true},
		{Kind: BrowserActionClipboardWrite, Text: strings.Repeat("x", 33), HasUserActivation: true, Consent: true},
		{Kind: BrowserActionNavigate, SourceOrigin: "https://app.example", TargetURL: "https://evil.example/"},
		{Kind: BrowserActionPermission, Permission: "camera", HasUserActivation: true, Consent: true},
	}
	for _, action := range denied {
		if err := policy.Authorize(action); !errors.Is(err, ErrForbidden) {
			t.Fatalf("action admitted: %#v err=%v", action, err)
		}
	}
	policy.Navigation.AllowCrossOrigin = false
	if err := policy.Authorize(BrowserPolicyAction{Kind: BrowserActionNavigate, SourceOrigin: "https://app.example", TargetURL: "https://files.example/path"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-origin navigation admitted without policy: %v", err)
	}
}

func TestBrowserPolicyTransferConfinementAndDigestBounds(t *testing.T) {
	policy := testPermissiveBrowserPolicy()
	digest := "sha256:" + strings.Repeat("a", 64)
	action := BrowserPolicyAction{Kind: BrowserActionUpload, HasUserActivation: true, Consent: true, Files: []BrowserTransferFile{{TransferID: "xfer-1", Name: "report.txt", MediaType: "text/plain", Digest: digest, SizeBytes: 8}}}
	if err := policy.Authorize(action); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*BrowserPolicyAction){
		func(action *BrowserPolicyAction) { action.Files[0].Name = "../secret" },
		func(action *BrowserPolicyAction) { action.Files[0].MediaType = "application/octet-stream" },
		func(action *BrowserPolicyAction) { action.Files[0].Digest = "sha256:bad" },
		func(action *BrowserPolicyAction) { action.Files[0].SizeBytes = 1025 },
		func(action *BrowserPolicyAction) { action.Consent = false },
	} {
		candidate := action
		candidate.Files = append([]BrowserTransferFile(nil), action.Files...)
		mutate(&candidate)
		if err := policy.Authorize(candidate); !errors.Is(err, ErrForbidden) {
			t.Fatalf("unsafe transfer admitted: %#v err=%v", candidate, err)
		}
	}
}

func TestBrowserPolicyRejectsAmbiguousConfiguration(t *testing.T) {
	policy := testPermissiveBrowserPolicy()
	policy.Navigation.AllowedOrigins = []string{"https://files.example", "https://app.example"}
	if err := policy.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsorted origin err=%v", err)
	}
	policy = testPermissiveBrowserPolicy()
	policy.Permissions.Allowed = []string{"camera", "camera"}
	if err := policy.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate permission err=%v", err)
	}
}

func testPermissiveBrowserPolicy() BrowserPolicy {
	transfer := BrowserTransferPolicy{Enabled: true, MaxFiles: 2, MaxFileBytes: 1024, MaxTotalBytes: 2048, AllowedMediaTypes: []string{"text/plain"}, RequireActivation: true, RequireConsent: true}
	return BrowserPolicy{
		Revision:  1,
		Input:     BrowserInputPolicy{Keyboard: true, Pointer: true, Touch: true},
		Clipboard: BrowserClipboardPolicy{Read: true, Write: true, MaxBytes: 32, RequireActivation: true, RequireConsent: true},
		Upload:    transfer, Download: transfer,
		Navigation:  BrowserNavigationPolicy{AllowedOrigins: []string{"https://app.example", "https://files.example"}, AllowCrossOrigin: true},
		Popup:       BrowserPopupPolicy{Enabled: true, MaxOpen: 1, RequireActivation: true},
		Permissions: BrowserPermissionPolicy{Allowed: []string{"clipboard-read"}, RequireActivation: true, RequireConsent: true},
	}
}
