package executorprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func validOpen() Open {
	now := time.Now().UTC()
	reference := "ref:desktop-session:" + strings.Repeat("a", 32)
	policy := &desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}
	value := Open{Protocol: ProtocolID, Role: RoleDesktop, RequestID: "request-1", TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("b", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", RuntimeSessionID: "desktop-session-1", CapabilityProfileID: "desktop-v1", MediaProfileID: "desktop-media-v1", ControlProfileID: "desktop-control-v1", AllocationReference: "ref:desktop/11111111111111111111111111111111", MediaPolicy: policy, MediaPolicyDigest: PolicyDigest(*policy), HandoffReference: reference, HandoffDigest: referenceDigest(reference), ConnectionGeneration: 2, ConnectionEpoch: "epoch-1", Fence: strings.Repeat("c", handoff.MinFenceBytes), AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), Codec: "video/VP8"}
	value.AuthorityDigest = value.CalculateAuthorityDigest()
	value.RequestDigest = value.CalculateRequestDigest()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	_ = publicKey
	statement := desktopbridge.Statement{Protocol: desktopbridge.ProtocolID, Version: desktopbridge.Version, KeyID: "provider-desktop-v2", ExecutorRole: RoleDesktop, ExecutorIdentity: "executor-desktop-1", ProviderRevisionID: value.ProviderRevisionID, TenantBindingDigest: value.TenantBindingDigest, SandboxID: value.SandboxID, RuntimeSessionID: value.RuntimeSessionID, HandoffReferenceDigest: value.HandoffDigest, AllocationReference: value.AllocationReference, MediaPolicy: *value.MediaPolicy, ConnectionGeneration: value.ConnectionGeneration, ConnectionEpoch: value.ConnectionEpoch, Fence: value.Fence, AuthorityExpiresAt: value.AuthorityExpiresAt, HandoffExpiresAt: value.HandoffExpiresAt, NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: value.AuthorityDigest, ExecutorRequestDigest: value.RequestDigest, Nonce: "nonce-abcdefghijklmnopqrstuvwxyz123456"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	envelope, _ := desktopbridge.Sign(statement, privateKey)
	value.Bridge = &envelope
	return value
}

func TestOpenRejectsBindingDriftAndExpiry(t *testing.T) {
	open := validOpen()
	if err := open.Validate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Open){
		"wrong reference digest": func(value *Open) { value.HandoffDigest = "sha256:" + strings.Repeat("f", 64) },
		"wrong tenant":           func(value *Open) { value.TenantBindingDigest = "sha256:" + strings.Repeat("a", 64) },
		"expired": func(value *Open) {
			value.AuthorityExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
		},
		"wrong role":                func(value *Open) { value.Role = "provider" },
		"wrong allocation":          func(value *Open) { value.AllocationReference = "ref:desktop/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"wrong media policy digest": func(value *Open) { value.MediaPolicyDigest = "sha256:" + strings.Repeat("f", 64) },
		"wrong queue policy":        func(value *Open) { value.MediaPolicy.MaxQueuedFrames = 129 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := open
			policy := *open.MediaPolicy
			candidate.MediaPolicy = &policy
			bridge := *open.Bridge
			candidate.Bridge = &bridge
			mutate(&candidate)
			if candidate.Validate(time.Now().UTC()) == nil {
				t.Fatal("invalid executor authority accepted")
			}
		})
	}
}

func TestDecodeRejectsUnknownDuplicateAndTrailing(t *testing.T) {
	open := validOpen()
	document, err := json.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Open
	if err := Decode(document, &decoded); err != nil {
		t.Fatal(err)
	}
	valid := string(document)
	for _, candidate := range []string{
		strings.Replace(valid, `"role":"desktop"`, `"role":"desktop","role":"desktop"`, 1),
		strings.Replace(valid, `"role":"desktop"`, `"unknown":true,"role":"desktop"`, 1),
		valid + `{}`,
	} {
		if err := Decode([]byte(candidate), &decoded); err == nil {
			t.Fatal("unsafe executor authority accepted")
		}
	}
}
