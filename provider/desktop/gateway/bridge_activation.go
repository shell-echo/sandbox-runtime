package desktopgateway

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

type activationRead struct {
	kind     websocket.MessageType
	document []byte
	err      error
}

// serveActivated keeps the bounded Provider reservation but deliberately
// leaves the executor/broker unopened until the caller's explicit start.
func (h *Handler) serveActivated(writer http.ResponseWriter, request *http.Request) {
	if h.boundMedia == nil || h.bindingRegistrar == nil {
		http.Error(writer, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{ActivationSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(h.maxMessageBytes)
	setupCtx, cancelSetup := context.WithTimeout(request.Context(), h.operationTimeout)
	defer cancelSetup()
	kind, document, err := connection.Read(setupCtx)
	if err != nil || kind != websocket.MessageText || len(document) > handoff.MaxDocumentBytes {
		return
	}
	var open desktophandoffv2.OpenRequest
	now, trusted := h.now()
	if !trusted || desktophandoffv2.Decode(document, &open) != nil || open.Validate(now) != nil ||
		!h.claim(open.RequestID, now, mustExpiry(open.AuthorityExpiresAt)) {
		return
	}
	if h.bindingRegistrar.BindHandoff(setupCtx, open.Binding()) != nil {
		return
	}
	legacyOpen := open.OpenRequest
	legacyOpen.Protocol = desktophandoff.ProtocolID
	endpoint, err := h.resolveClosedEndpoint(setupCtx, legacyOpen)
	if err != nil || !h.acquire(open.DesktopSessionID) {
		return
	}
	defer h.release(open.DesktopSessionID)
	authorityExpiry := mustExpiry(open.AuthorityExpiresAt)
	handoffExpiry := mustExpiry(open.HandoffExpiresAt)
	authority := requestAuthority{reference: open.HandoffReference, providerRevision: open.ProviderRevisionID,
		tenantDigest: open.TenantBindingDigest, allocationReference: endpoint.AllocationReference,
		sandboxID: open.SandboxID, sessionID: open.DesktopSessionID, profileID: open.CapabilityProfileID,
		generation: open.ConnectionGeneration, connectionEpoch: open.ConnectionEpoch,
		expiresAt: authorityExpiry, handoffExpiresAt: handoffExpiry, policy: open.MediaPolicy}
	binding := open.Binding()
	authority.binding = &binding
	prepared, err := handoff.Encode(desktophandoffv2.PreparedResponse(open))
	if err != nil || connection.Write(setupCtx, websocket.MessageText, prepared) != nil {
		return
	}
	start, ok := h.waitActivationStart(setupCtx, connection, open, authority)
	if !ok {
		return
	}
	// Resolve/Attach again immediately before opening the real media reader.
	// This rejects a handoff, allocation, fence or expiry drift during prepare.
	endpoint, attachment, err := h.resolveClosed(setupCtx, legacyOpen)
	if err != nil || endpoint.AllocationReference != authority.allocationReference || h.check(setupCtx, authority) != nil {
		return
	}
	session, err := h.boundMedia.OpenBound(setupCtx, legacyOpen, endpoint, attachment)
	if err != nil || nilDependency(session) {
		return
	}
	sessionClose := newSessionClose(session)
	defer func() { _ = sessionClose.closeAndWait(h.operationTimeout) }()
	if h.check(setupCtx, authority) != nil || setupCtx.Err() != nil {
		return
	}
	started, err := handoff.Encode(desktophandoffv2.StartedResponse(start))
	if err != nil || connection.Write(setupCtx, websocket.MessageText, started) != nil {
		return
	}
	bridgeCtx, cancelBridge := context.WithDeadline(request.Context(), authorityExpiry)
	defer cancelBridge()
	bridge := &connectionBridge{connection: connection, session: session, sessionClose: sessionClose,
		authority: authority, handler: h}
	bridge.run(bridgeCtx)
}

func (h *Handler) waitActivationStart(ctx context.Context, connection *websocket.Conn,
	open desktophandoffv2.OpenRequest, authority requestAuthority) (desktophandoffv2.Start, bool) {
	read := make(chan activationRead, 1)
	go func() {
		kind, document, err := connection.Read(ctx)
		read <- activationRead{kind: kind, document: document, err: err}
	}()
	ticker := time.NewTicker(h.authorityPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return desktophandoffv2.Start{}, false
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, h.operationTimeout)
			failed := h.check(checkCtx, authority) != nil
			cancel()
			if failed {
				return desktophandoffv2.Start{}, false
			}
		case received := <-read:
			var start desktophandoffv2.Start
			if received.err != nil || received.kind != websocket.MessageText ||
				len(received.document) > handoff.MaxDocumentBytes ||
				desktophandoffv2.Decode(received.document, &start) != nil ||
				start.Validate(open) != nil || h.check(ctx, authority) != nil {
				return desktophandoffv2.Start{}, false
			}
			return start, true
		}
	}
}
