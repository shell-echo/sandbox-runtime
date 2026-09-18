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

func TestBrowserLiveInputClosedActionMatrix(t *testing.T) {
	binding := testBrowserLiveBinding(product.GrantAccessControl)
	video := BrowserLiveVideoPolicy{Width: 640, Height: 480}
	actions := []struct {
		document string
		kind     string
	}{
		{`{"kind":"keyboard","event":"down","code":"KeyA","key":"a","modifiers":["shift"],"user_activation":true}`, product.BrowserActionKeyboard},
		{`{"kind":"pointer","event":"wheel","x":20,"y":30,"button":0,"delta_x":1,"delta_y":-2,"user_activation":true}`, product.BrowserActionPointer},
		{`{"kind":"touch","event":"start","points":[{"id":1,"x":20,"y":30}],"user_activation":true}`, product.BrowserActionTouch},
		{`{"kind":"clipboard.read","user_activation":true,"consent":true}`, product.BrowserActionClipboardRead},
		{`{"kind":"clipboard.write","text":"safe","user_activation":true,"consent":true}`, product.BrowserActionClipboardWrite},
		{`{"kind":"upload","files":[{"transfer_id":"xfer-1","name":"safe.txt","media_type":"text/plain","digest":"sha256:` + strings.Repeat("a", 64) + `","size_bytes":4}],"user_activation":true,"consent":true}`, product.BrowserActionUpload},
		{`{"kind":"download","files":[{"transfer_id":"xfer-2","name":"safe.txt","media_type":"text/plain","digest":"sha256:` + strings.Repeat("b", 64) + `","size_bytes":4}],"user_activation":true,"consent":true}`, product.BrowserActionDownload},
		{`{"kind":"navigate","source_origin":"https://app.example","target_url":"https://app.example/path","user_activation":true}`, product.BrowserActionNavigate},
		{`{"kind":"popup","source_origin":"https://app.example","target_url":"https://app.example/path","open_popup_count":0,"user_activation":true}`, product.BrowserActionPopup},
		{`{"kind":"permission","permission":"clipboard-read","user_activation":true,"consent":true}`, product.BrowserActionPermission},
	}
	for index, test := range actions {
		document := `{"type":"input","sequence":` + string(rune('1'+index)) + `,"action":` + test.document + `}`
		// Keep sequences in the decoder's range; ordering is enforced by inputLoop.
		if index >= 9 {
			document = `{"type":"input","sequence":10,"action":` + test.document + `}`
		}
		input, err := decodeBrowserLiveInput([]byte(document), video, binding)
		if err != nil || input.Action.Kind != test.kind {
			t.Fatalf("kind=%s input=%#v err=%v document=%s", test.kind, input, err, document)
		}
	}

	invalid := []string{
		`{"type":"input","sequence":1,"action":{"kind":"pointer","event":"move","x":640,"y":1,"button":0,"delta_x":0,"delta_y":0,"user_activation":true}}`,
		`{"type":"input","sequence":1,"action":{"kind":"touch","event":"start","points":[{"id":1,"x":1,"y":1},{"id":1,"x":2,"y":2}],"user_activation":true}}`,
		`{"type":"input","sequence":1,"action":{"kind":"keyboard","event":"down","code":"KeyA","key":"a","modifiers":["shift","shift"],"user_activation":true}}`,
		`{"type":"input","sequence":1,"action":{"kind":"permission","permission":"camera","user_activation":true,"consent":true,"unknown":1}}`,
		`{"type":"input","sequence":1,"action":{"kind":"raw.cdp"}}`,
	}
	for _, document := range invalid {
		if _, err := decodeBrowserLiveInput([]byte(document), video, binding); err == nil {
			t.Fatalf("invalid input accepted: %s", document)
		}
	}
}

func TestBrowserLivePolicyRevisionChangeRevokesPeer(t *testing.T) {
	binding := testBrowserLiveBinding(product.GrantAccessControl)
	policySource := &browserPolicySourceSpy{policy: testGatewayBrowserPolicy()}
	handler := &BrowserLiveHandler{
		grants: &grantStoreSpy{binding: binding, active: true}, policy: policySource, transfers: denyBrowserTransferAuthority{}, audit: &auditStoreSpy{},
		maxRTPQueue: 1, maxInputQueue: 1, pollInterval: 10 * time.Millisecond, connectionTimeout: time.Second,
		sessions: map[string]int{binding.SessionID: 1}, peers: 1,
	}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	media := newBrowserLiveMediaSessionSpy()
	state := newBrowserLivePeer(handler, peer, media, nil, binding, BrowserLiveVideoPolicy{}, testGatewayBrowserPolicy())
	go state.authorityLoop()
	policySource.setRevision(2)
	select {
	case <-state.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("policy revision change did not revoke peer")
	}
}

func TestProductTransferBrowserAuthorityBindsExactTransfer(t *testing.T) {
	binding := testBrowserLiveBinding(product.GrantAccessControl)
	digest := "sha256:" + strings.Repeat("c", 64)
	store := &browserTransferStoreSpy{record: product.TransferRecord{
		BlobTransfer: product.BlobTransfer{ID: "xfer-1", WorkspaceID: binding.WorkspaceID, Direction: "upload", Digest: digest, SizeBytes: 4, State: "complete"},
		TenantID:     binding.TenantID, Actor: binding.Actor,
	}}
	authority := &ProductTransferBrowserAuthority{Store: store}
	action := product.BrowserPolicyAction{Kind: product.BrowserActionUpload, Files: []product.BrowserTransferFile{{TransferID: "xfer-1", Digest: digest, SizeBytes: 4}}}
	if err := authority.AuthorizeBrowserTransfer(context.Background(), binding, action); err != nil {
		t.Fatal(err)
	}
	store.record.WorkspaceID = "wrk-other"
	if err := authority.AuthorizeBrowserTransfer(context.Background(), binding, action); !errors.Is(err, product.ErrForbidden) {
		t.Fatalf("cross-workspace transfer err=%v", err)
	}
}

type browserTransferStoreSpy struct {
	record product.TransferRecord
	err    error
}

func (s *browserTransferStoreSpy) GetTransfer(_ context.Context, tenantID string, actor product.ActorRef, transferID string) (product.TransferRecord, error) {
	if s.err != nil || tenantID != s.record.TenantID || actor != s.record.Actor || transferID != s.record.ID {
		return product.TransferRecord{}, product.ErrNotFound
	}
	return s.record, nil
}
