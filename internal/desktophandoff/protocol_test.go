package desktophandoff

import (
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func validOpen(now time.Time) OpenRequest {
	value := OpenRequest{BindingVersion: BindingVersion, BindingIssuer: BindingIssuer, Protocol: ProtocolID, RequestID: "request-1", Resource: ResourceDesktop,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1",
		DesktopSessionID: "desktop-1", CapabilityProfileID: "desktop-v1", MediaProfileID: MediaProfileID, ControlProfileID: ControlProfileID,
		HandoffReference: "ref:desktop-session:opaque", HandoffDigest: ReferenceDigest("ref:desktop-session:opaque"),
		ConnectionGeneration: 2, ConnectionEpoch: "connection-1", AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), ControllerFence: strings.Repeat("b", handoff.MinFenceBytes),
		MediaPolicy: desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 640, Height: 480, MaxFPS: 30, MaxVideoBitrateKbps: 1000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}}
	value.AuthorityDigest = AuthorityDigest(value)
	value.RequestDigest = RequestDigest(value)
	return value
}

func TestOpenRequestValidatesOpaqueBindingAndMediaPolicy(t *testing.T) {
	now := time.Now().UTC()
	if err := validOpen(now).Validate(now); err != nil {
		t.Fatal(err)
	}
	invalid := validOpen(now)
	invalid.TenantBindingDigest = "tenant-1"
	if err := invalid.Validate(now); err == nil {
		t.Fatal("plaintext tenant binding accepted")
	}
	invalid = validOpen(now)
	invalid.MediaPolicy.VideoCodec = "video/H264"
	if err := invalid.Validate(now); err == nil {
		t.Fatal("unsupported media policy accepted")
	}
	invalid = validOpen(now)
	invalid.HandoffDigest = ReferenceDigest("ref:desktop-session:other")
	if err := invalid.Validate(now); err == nil {
		t.Fatal("mismatched handoff digest accepted")
	}
	invalid = validOpen(now)
	invalid.AuthorityExpiresAt = now.Add(3 * time.Minute).Format(time.RFC3339Nano)
	if err := invalid.Validate(now); err == nil {
		t.Fatal("authority beyond handoff expiry accepted")
	}
	invalid = validOpen(now)
	invalid.AuthorityExpiresAt = "not-a-time"
	if err := invalid.Validate(now); err == nil {
		t.Fatal("invalid authority expiry accepted")
	}
}
