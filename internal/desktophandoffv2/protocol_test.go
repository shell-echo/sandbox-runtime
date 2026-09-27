package desktophandoffv2

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func validOpen(now time.Time) OpenRequest {
	legacy := desktophandoff.OpenRequest{BindingVersion: desktophandoff.BindingVersion,
		BindingIssuer: desktophandoff.BindingIssuer, Protocol: ProtocolID, RequestID: "request-1",
		Resource:            desktophandoff.ResourceDesktop,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64),
		ProviderRevisionID:  "provider-revision-1", SandboxID: "sandbox-1",
		DesktopSessionID: "desktop-1", CapabilityProfileID: "desktop-v1",
		MediaProfileID: desktophandoff.MediaProfileID, ControlProfileID: desktophandoff.ControlProfileID,
		HandoffReference:     "ref:desktop-session:opaque",
		HandoffDigest:        desktophandoff.ReferenceDigest("ref:desktop-session:opaque"),
		ConnectionGeneration: 2, ConnectionEpoch: "connection-1",
		AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt:   now.Add(2 * time.Minute).Format(time.RFC3339Nano),
		ControllerFence:    strings.Repeat("b", handoff.MinFenceBytes),
		MediaPolicy: desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 640, Height: 480,
			MaxFPS: 30, MaxVideoBitrateKbps: 1000,
			MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames,
			MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs,
			MaxInputBytes:   desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}}
	legacy.AuthorityDigest = desktophandoff.AuthorityDigest(legacy)
	legacy.RequestDigest = desktophandoff.RequestDigest(legacy)
	open := OpenRequest{OpenRequest: legacy}
	open.TransportDigest = TransportDigest(open)
	return open
}

func TestV2PrepareAndStartBindExactConnection(t *testing.T) {
	now := time.Now().UTC()
	open := validOpen(now)
	if err := open.Validate(now); err != nil {
		t.Fatal(err)
	}
	prepared := PreparedResponse(open)
	if err := prepared.Validate(open); err != nil {
		t.Fatal(err)
	}
	start := NewStart(open)
	if err := start.Validate(open); err != nil {
		t.Fatal(err)
	}
	started := StartedResponse(start)
	if err := started.Validate(start); err != nil {
		t.Fatal(err)
	}
	changed := open
	changed.ConnectionEpoch = "connection-2"
	if err := start.Validate(changed); err == nil {
		t.Fatal("old connection epoch activated a new connection")
	}
	changed = open
	changed.ControllerFence = strings.Repeat("c", handoff.MinFenceBytes)
	if err := start.Validate(changed); err == nil {
		t.Fatal("old controller fence activated a new connection")
	}
	changed = open
	changed.Protocol = desktophandoff.ProtocolID
	if err := changed.Validate(now); err == nil {
		t.Fatal("v1 protocol accepted as prepared v2")
	}
	changed = open
	changed.TransportDigest = strings.Replace(changed.TransportDigest, "a", "b", 1)
	if changed.TransportDigest == open.TransportDigest {
		changed.TransportDigest = "sha256:" + strings.Repeat("0", 64)
	}
	if err := changed.Validate(now); err == nil {
		t.Fatal("transport digest drift accepted")
	}
}

func TestV2WireRejectsUnknownDuplicateAndNoncanonical(t *testing.T) {
	open := validOpen(time.Now().UTC())
	document, err := handoff.Encode(open)
	if err != nil {
		t.Fatal(err)
	}
	var decoded OpenRequest
	if err := Decode(document, &decoded); err != nil || decoded.Validate(time.Now().UTC()) != nil {
		t.Fatalf("canonical open = %#v, %v", decoded, err)
	}
	for _, bad := range [][]byte{
		append([]byte(" "), document...),
		append(bytes.TrimSuffix(document, []byte("}")), []byte(`,"unknown":1}`)...),
		append(bytes.TrimSuffix(document, []byte("}")), []byte(`,"request_id":"replay"}`)...),
	} {
		if err := Decode(bad, &OpenRequest{}); err == nil {
			t.Fatalf("invalid v2 open accepted: %s", bad)
		}
	}
	start := NewStart(open)
	startDocument, err := handoff.Encode(start)
	if err != nil {
		t.Fatal(err)
	}
	var decodedStart Start
	if err := Decode(startDocument, &decodedStart); err != nil || decodedStart.Validate(open) != nil {
		t.Fatalf("canonical start = %#v, %v", decodedStart, err)
	}
	bad := append(bytes.TrimSuffix(startDocument, []byte("}")), []byte(`,"connection_epoch":"old"}`)...)
	if err := Decode(bad, &Start{}); err == nil {
		t.Fatal("duplicate start tuple field accepted")
	}
}
