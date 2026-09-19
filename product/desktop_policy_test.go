package product

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDesktopPolicyDenyByDefaultAndDeviceMatrix(t *testing.T) {
	policy := DesktopPolicy{Revision: 1}
	for _, action := range []DesktopPolicyAction{
		{Kind: DesktopActionKeyboard},
		{Kind: DesktopActionPointer},
		{Kind: DesktopActionTouch, TouchPoints: 1},
		{Kind: DesktopActionClipboardRead},
		{Kind: DesktopActionClipboardWrite, Text: "secret"},
		{Kind: DesktopActionUpload, Files: []DesktopTransferFile{testDesktopTransferFile()}},
		{Kind: DesktopActionDownload, Files: []DesktopTransferFile{testDesktopTransferFile()}},
		{Kind: DesktopActionMicrophone},
		{Kind: DesktopActionCamera},
		{Kind: DesktopActionDevice},
	} {
		if err := policy.Authorize(action); !errors.Is(err, ErrForbidden) {
			t.Fatalf("action %q err=%v", action.Kind, err)
		}
	}
}

func TestDesktopPolicyActivationConsentAndTransferBounds(t *testing.T) {
	policy := testPermissiveDesktopPolicy()
	file := testDesktopTransferFile()
	allowed := []DesktopPolicyAction{
		{Kind: DesktopActionKeyboard, HasUserActivation: true},
		{Kind: DesktopActionPointer, HasUserActivation: true},
		{Kind: DesktopActionTouch, TouchPoints: 10, HasUserActivation: true},
		{Kind: DesktopActionClipboardRead, HasUserActivation: true, Consent: true},
		{Kind: DesktopActionClipboardWrite, Text: "hello", HasUserActivation: true, Consent: true},
		{Kind: DesktopActionUpload, Files: []DesktopTransferFile{file}, HasUserActivation: true, Consent: true},
		{Kind: DesktopActionDownload, Files: []DesktopTransferFile{file}, HasUserActivation: true, Consent: true},
	}
	for _, action := range allowed {
		if err := policy.Authorize(action); err != nil {
			t.Fatalf("action %q err=%v", action.Kind, err)
		}
	}

	badDigest := file
	badDigest.Digest = "sha256:nope"
	badPath := file
	badPath.Path = "/workspace/../secret"
	wrongMount := file
	wrongMount.Path = "/tmp/file.txt"
	duplicate := []DesktopTransferFile{file, file}
	for _, action := range []DesktopPolicyAction{
		{Kind: DesktopActionKeyboard},
		{Kind: DesktopActionClipboardRead, HasUserActivation: true},
		{Kind: DesktopActionClipboardWrite, Text: strings.Repeat("x", MaxDesktopClipboardBytes+1), HasUserActivation: true, Consent: true},
		{Kind: DesktopActionUpload, Files: []DesktopTransferFile{file}, HasUserActivation: true},
		{Kind: DesktopActionUpload, Files: []DesktopTransferFile{badDigest}, HasUserActivation: true, Consent: true},
		{Kind: DesktopActionUpload, Files: []DesktopTransferFile{badPath}, HasUserActivation: true, Consent: true},
		{Kind: DesktopActionUpload, Files: []DesktopTransferFile{wrongMount}, HasUserActivation: true, Consent: true},
		{Kind: DesktopActionUpload, Files: duplicate, HasUserActivation: true, Consent: true},
	} {
		if err := policy.Authorize(action); !errors.Is(err, ErrForbidden) {
			t.Fatalf("denied action %#v err=%v", action, err)
		}
	}
}

func TestDesktopPolicyValidationRejectsNonCanonicalLimitsAndMedia(t *testing.T) {
	policy := testPermissiveDesktopPolicy()
	for _, mutate := range []func(*DesktopPolicy){
		func(value *DesktopPolicy) { value.Revision = 0 },
		func(value *DesktopPolicy) { value.Clipboard.MaxBytes = MaxDesktopClipboardBytes + 1 },
		func(value *DesktopPolicy) { value.Upload.MaxFiles = MaxDesktopTransferFiles + 1 },
		func(value *DesktopPolicy) { value.Upload.MaxTotalBytes = MaxDesktopPolicyTransferByte + 1 },
		func(value *DesktopPolicy) {
			value.Upload.AllowedMediaTypes = []string{"text/plain", "application/json"}
		},
		func(value *DesktopPolicy) { value.Upload.AllowedMediaTypes = []string{"text/plain; charset=utf-8"} },
	} {
		candidate := policy
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid policy accepted: %#v", candidate)
		}
	}
}

func TestDesktopPolicyServiceValidatesRevisionAndBuildsCommand(t *testing.T) {
	store := &desktopPolicyStoreSpy{}
	service, err := NewDesktopPolicyService(store, desktopPolicyIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPermissiveDesktopPolicy()
	result, replay, err := service.Put(context.Background(), "tenant-desktop-policy", ActorRef{Type: ActorHuman, ID: "owner"}, "workspace-policy", "policy-key", 0, policy)
	if err != nil || replay || result.Revision != 1 {
		t.Fatalf("result=%#v replay=%t err=%v", result, replay, err)
	}
	if store.command.ExpectedRevision != 0 || store.command.Policy.Revision != 1 || store.command.AuditID != "aud_fixed" || store.command.Path != "/internal/workspaces/workspace-policy/desktop-policy" || store.command.RequestDigest == ([32]byte{}) {
		t.Fatalf("command=%#v", store.command)
	}
	policy.Revision = 3
	if _, _, err := service.Put(context.Background(), "tenant-desktop-policy", ActorRef{Type: ActorHuman, ID: "owner"}, "workspace-policy", "policy-key-2", 1, policy); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-contiguous revision err=%v", err)
	}
}

func testPermissiveDesktopPolicy() DesktopPolicy {
	transfer := DesktopTransferPolicy{
		Enabled: true, MaxFiles: 2, MaxFileBytes: 1024, MaxTotalBytes: 2048,
		AllowedMediaTypes: []string{"application/json", "text/plain"}, RequireActivation: true, RequireConsent: true,
	}
	return DesktopPolicy{
		Revision:  1,
		Input:     DesktopInputPolicy{Keyboard: true, Pointer: true, Touch: true, RequireActivation: true},
		Clipboard: DesktopClipboardPolicy{Read: true, Write: true, MaxBytes: MaxDesktopClipboardBytes, RequireActivation: true, RequireConsent: true},
		Upload:    transfer, Download: transfer,
	}
}

func testDesktopTransferFile() DesktopTransferFile {
	return DesktopTransferFile{
		TransferID: "transfer-1", Path: "/workspace/docs/file.txt", MediaType: "text/plain",
		Digest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 10,
	}
}

type desktopPolicyStoreSpy struct{ command DesktopPolicyCommand }

func (s *desktopPolicyStoreSpy) PutDesktopPolicy(_ context.Context, command DesktopPolicyCommand) (DesktopPolicy, bool, error) {
	s.command = command
	return command.Policy, false, nil
}

func (*desktopPolicyStoreSpy) CurrentDesktopPolicy(context.Context, GatewayBinding) (DesktopPolicy, error) {
	return DesktopPolicy{}, ErrNotFound
}

type desktopPolicyIDGenerator struct{}

func (desktopPolicyIDGenerator) NewID(prefix string) (string, error) { return prefix + "_fixed", nil }
