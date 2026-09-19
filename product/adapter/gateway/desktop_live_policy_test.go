package productgateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestDesktopLivePolicyActionMatrixAndClosedDeviceDenial(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	media := testDesktopLiveMediaPolicy(false)
	digest := "sha256:" + strings.Repeat("a", 64)
	for sequence, test := range []struct {
		document string
		kind     string
	}{
		{`{"kind":"keyboard","event":"down","code":"KeyA","key":"a","modifiers":["shift"],"user_activation":true}`, product.DesktopActionKeyboard},
		{`{"kind":"pointer","event":"wheel","x":20,"y":30,"button":0,"delta_x":1,"delta_y":-2,"user_activation":true}`, product.DesktopActionPointer},
		{`{"kind":"touch","event":"start","points":[{"id":1,"x":20,"y":30}],"user_activation":true}`, product.DesktopActionTouch},
		{`{"kind":"clipboard.read","user_activation":true,"consent":true}`, product.DesktopActionClipboardRead},
		{`{"kind":"clipboard.write","text":"safe","user_activation":true,"consent":true}`, product.DesktopActionClipboardWrite},
		{`{"kind":"transfer.upload","files":[{"transfer_id":"xfer-1","path":"/workspace/safe.txt","media_type":"text/plain","digest":"` + digest + `","size_bytes":4}],"user_activation":true,"consent":true}`, product.DesktopActionUpload},
		{`{"kind":"transfer.download","files":[{"transfer_id":"xfer-2","path":"/workspace/safe.txt","media_type":"text/plain","digest":"` + digest + `","size_bytes":4}],"user_activation":true,"consent":true}`, product.DesktopActionDownload},
	} {
		document := `{"type":"input","sequence":` + string(rune('1'+sequence)) + `,"action":` + test.document + `}`
		input, err := decodeDesktopLiveInput([]byte(document), media, binding)
		if err != nil || input.Action.Kind != test.kind || input.Kind != test.kind {
			t.Fatalf("kind=%s input=%#v err=%v", test.kind, input, err)
		}
	}
	for _, kind := range []string{product.DesktopActionMicrophone, product.DesktopActionCamera, product.DesktopActionDevice} {
		document := `{"type":"input","sequence":1,"action":{"kind":"` + kind + `"}}`
		if _, err := decodeDesktopLiveInput([]byte(document), media, binding); !errors.Is(err, product.ErrForbidden) {
			t.Fatalf("kind=%s err=%v", kind, err)
		}
	}
}

func TestDesktopLivePolicyRevisionChangeRevokesPeer(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	policySource := &desktopPolicySourceSpy{policy: testDesktopPolicy()}
	handler := &DesktopLiveHandler{
		grants: &grantStoreSpy{binding: binding, active: true}, policy: policySource, transfers: denyDesktopTransferAuthority{}, audit: &auditStoreSpy{},
		maxVideoQueue: 1, maxAudioQueue: 1, maxInputQueue: 1, pollInterval: 10 * time.Millisecond,
		sessions: map[string]int{binding.SessionID: 1}, peers: 1,
	}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	state := newDesktopLivePeer(handler, peer, newDesktopLiveMediaSessionSpy(), binding, testDesktopLiveMediaPolicy(false), testDesktopPolicy())
	go state.authorityLoop()
	policySource.setRevision(2)
	select {
	case <-state.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Desktop policy revision change did not revoke peer")
	}
}

func TestProductTransferDesktopAuthorityBindsExactTransfer(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	digest := "sha256:" + strings.Repeat("c", 64)
	store := &browserTransferStoreSpy{record: product.TransferRecord{
		BlobTransfer: product.BlobTransfer{ID: "xfer-1", WorkspaceID: binding.WorkspaceID, Direction: "upload", Digest: digest, SizeBytes: 4, State: "complete"},
		TenantID:     binding.TenantID, Actor: binding.Actor,
	}}
	authority := &ProductTransferDesktopAuthority{Store: store}
	action := product.DesktopPolicyAction{Kind: product.DesktopActionUpload, Files: []product.DesktopTransferFile{{TransferID: "xfer-1", Path: "/workspace/safe.txt", MediaType: "text/plain", Digest: digest, SizeBytes: 4}}}
	if err := authority.AuthorizeDesktopTransfer(context.Background(), binding, action); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*product.TransferRecord){
		func(record *product.TransferRecord) { record.WorkspaceID = "wrk-other" },
		func(record *product.TransferRecord) { record.Direction = "download" },
		func(record *product.TransferRecord) { record.State = "transferring" },
		func(record *product.TransferRecord) { record.Digest = "sha256:" + strings.Repeat("d", 64) },
		func(record *product.TransferRecord) { record.SizeBytes++ },
	} {
		original := store.record
		mutate(&store.record)
		if err := authority.AuthorizeDesktopTransfer(context.Background(), binding, action); !errors.Is(err, product.ErrForbidden) {
			t.Fatalf("mismatched transfer=%#v err=%v", store.record, err)
		}
		store.record = original
	}
}

func TestDesktopLiveClipboardResultIsBounded(t *testing.T) {
	policy := testDesktopPolicy()
	action := product.DesktopPolicyAction{Kind: product.DesktopActionClipboardRead}
	if !validDesktopLiveInputResult(policy, action, DesktopLiveInputResult{Text: "safe"}) {
		t.Fatal("valid clipboard result rejected")
	}
	if validDesktopLiveInputResult(policy, action, DesktopLiveInputResult{Text: strings.Repeat("x", product.MaxDesktopClipboardBytes+1)}) {
		t.Fatal("oversized clipboard result accepted")
	}
	if validDesktopLiveInputResult(policy, product.DesktopPolicyAction{Kind: product.DesktopActionPointer}, DesktopLiveInputResult{Text: "unexpected"}) {
		t.Fatal("non-clipboard input returned text")
	}
}

func (s *desktopPolicySourceSpy) setRevision(revision int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy.Revision = revision
}
