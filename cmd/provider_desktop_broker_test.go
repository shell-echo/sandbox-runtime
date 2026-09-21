package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

type staticDesktopBrokerResolver struct {
	endpoint desktopreference.Endpoint
	err      error
}

func (r staticDesktopBrokerResolver) Resolve(context.Context, string) (desktopreference.Endpoint, error) {
	return r.endpoint, r.err
}

func TestProductionDesktopBrokerAuthorityRevalidatesAndMintsOneUseProbe(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}
	handoffReference := "ref:desktop-session:11111111111111111111111111111111"
	authorityExpiry := now.Add(time.Minute)
	handoffExpiry := now.Add(2 * time.Minute)
	binding := &desktophandoff.Binding{Version: desktophandoff.BindingVersion, Issuer: desktophandoff.BindingIssuer, TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", DesktopSessionID: "desktop-session-1", HandoffReference: handoffReference, ConnectionGeneration: 1, ConnectionEpoch: "epoch-1", ControllerFence: strings.Repeat("b", handoff.MinFenceBytes), AuthorityExpiresAt: authorityExpiry, HandoffExpiresAt: handoffExpiry, AuthorityDigest: "sha256:" + strings.Repeat("e", 64), RequestDigest: "sha256:" + strings.Repeat("f", 64), MediaPolicy: policy}
	endpoint := desktopreference.Endpoint{Reference: handoffReference, ProviderRevisionID: binding.ProviderRevisionID, SandboxID: binding.SandboxID, DesktopSessionID: binding.DesktopSessionID, AllocationReference: "ref:desktop/11111111111111111111111111111111", CapabilityProfileID: providerdesktop.CapabilityProfileID, ConnectionGeneration: 1, ExpiresAt: handoffExpiry, TenantBindingDigest: binding.TenantBindingDigest, Binding: binding}
	open := desktopbroker.SessionOpen{BindingVersion: desktopbroker.SessionBindingV2, BindingIssuer: desktopbroker.SessionBindingIssuerV2, Protocol: desktopbroker.SessionProtocolV2ID, RequestID: "broker-open-1", Method: desktopbroker.SessionMethod, TenantBindingDigest: binding.TenantBindingDigest, ProviderRevisionID: binding.ProviderRevisionID, SandboxID: binding.SandboxID, DesktopSessionID: binding.DesktopSessionID, CapabilityProfileID: providerdesktop.CapabilityProfileID, MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID, HandoffReferenceDigest: desktophandoff.ReferenceDigest(handoffReference), AllocationReference: endpoint.AllocationReference, ConnectionGeneration: 1, ConnectionEpoch: binding.ConnectionEpoch, Fence: binding.ControllerFence, AuthorityExpiresAt: authorityExpiry.Format(time.RFC3339Nano), HandoffExpiresAt: handoffExpiry.Format(time.RFC3339Nano), AuthorityDigest: "sha256:" + strings.Repeat("c", 64), RequestDigest: "sha256:" + strings.Repeat("d", 64), HandoffReference: handoffReference, MediaPolicy: policy}
	statement := desktopbridge.Statement{Protocol: desktopbridge.ProtocolID, Version: desktopbridge.Version, KeyID: "provider-desktop-v2", ExecutorRole: "desktop", ExecutorIdentity: "executor-desktop-1", ProviderRevisionID: open.ProviderRevisionID, TenantBindingDigest: open.TenantBindingDigest, SandboxID: open.SandboxID, RuntimeSessionID: open.DesktopSessionID, HandoffReferenceDigest: open.HandoffReferenceDigest, AllocationReference: open.AllocationReference, MediaPolicy: policy, ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch, Fence: open.Fence, AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt, NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: open.AuthorityDigest, ExecutorRequestDigest: open.RequestDigest, Nonce: "nonce-authority-abcdefghijklmnopqrstuvwxyz12"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, err := desktopbridge.Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	open.Bridge = &bridge
	authority := &productionDesktopBrokerAuthority{resolver: staticDesktopBrokerResolver{endpoint: endpoint}, executorIdentity: statement.ExecutorIdentity, bridgeKeyID: statement.KeyID, bridgePrivateKey: privateKey}
	if err := authority.Authorize(context.Background(), open); err != nil {
		t.Fatal(err)
	}
	probe, err := authority.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if probe.RequestID == open.RequestID || probe.Bridge.Statement.Nonce == open.Bridge.Statement.Nonce || probe.Bridge.Verify(time.Now().UTC(), map[string]ed25519.PublicKey{statement.KeyID: publicKey}) != nil {
		t.Fatal("probe did not receive a fresh verified one-use bridge")
	}
	drifted := open
	drifted.Fence = strings.Repeat("z", handoff.MinFenceBytes)
	if authority.Authorize(context.Background(), drifted) == nil {
		t.Fatal("fence drift was accepted")
	}
}
