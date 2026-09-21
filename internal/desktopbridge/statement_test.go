package desktopbridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func validStatement(t *testing.T) (Statement, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	now := time.Now().UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := Statement{Protocol: ProtocolID, Version: Version, KeyID: "provider-desktop-v2", ExecutorRole: "desktop", ExecutorIdentity: "executor-desktop-1", ProviderRevisionID: "provider-revision-1", TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), SandboxID: "sandbox-1", RuntimeSessionID: "desktop-session-1", HandoffReferenceDigest: "sha256:" + strings.Repeat("e", 64), AllocationReference: "ref:desktop/11111111111111111111111111111111", MediaPolicy: desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}, ConnectionGeneration: 2, ConnectionEpoch: "epoch-1", Fence: strings.Repeat("b", handoff.MinFenceBytes), AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: "sha256:" + strings.Repeat("c", 64), ExecutorRequestDigest: "sha256:" + strings.Repeat("d", 64), Nonce: "nonce-abcdefghijklmnopqrstuvwxyz123456"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	return statement, publicKey, privateKey
}

func TestStatementSignsAndVerifiesClosedBinding(t *testing.T) {
	statement, publicKey, privateKey := validStatement(t)
	envelope, err := Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.Verify(time.Now().UTC(), map[string]ed25519.PublicKey{statement.KeyID: publicKey}); err != nil {
		t.Fatal(err)
	}
	envelope.Statement.MediaPolicy.Width++
	if envelope.Verify(time.Now().UTC(), map[string]ed25519.PublicKey{statement.KeyID: publicKey}) == nil {
		t.Fatal("policy drift accepted")
	}
}

func TestEnvelopeDecodeRejectsNonCanonicalAndUnknownDocuments(t *testing.T) {
	statement, _, privateKey := validStatement(t)
	envelope, err := Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	document, err := Encode(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := Decode(document, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{
		strings.Replace(string(document), `"signature":"`, `"unknown":true,"signature":"`, 1),
		strings.Replace(string(document), `"signature":"`, `"signature":"`, 1) + "{}",
	} {
		if err := Decode([]byte(unsafe), &decoded); err == nil {
			t.Fatal("unsafe bridge document accepted")
		}
	}
}
