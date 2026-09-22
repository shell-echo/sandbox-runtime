package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/product"
)

type memoryKeyProvider struct {
	keys map[string][]byte
}

func (p memoryKeyProvider) ResolveKey(_ context.Context, reference secretref.Reference, version string) (secretref.KeyMaterial, error) {
	key, ok := p.keys[reference.String()+"\x00"+version]
	if !ok {
		return secretref.KeyMaterial{}, secretref.ErrUnavailable
	}
	digest := sha256.Sum256(key)
	return secretref.KeyMaterial{
		Reference: reference,
		Version:   version,
		Bytes:     append([]byte(nil), key...),
		Digest:    "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

type memoryEnvelopeProvider struct {
	keys              memoryKeyProvider
	err               error
	sealCalls         int
	openCalls         int
	lastSealPlaintext []byte
	lastOpenPlaintext []byte
	badOpenSize       bool
}

func (p *memoryEnvelopeProvider) SealEnvelope(ctx context.Context, binding secretref.Binding, plaintext, associatedData []byte) (secretref.OpaqueEnvelope, error) {
	p.sealCalls++
	p.lastSealPlaintext = plaintext
	if p.err != nil {
		return secretref.OpaqueEnvelope{}, p.err
	}
	sealed, err := secretref.Seal(ctx, p.keys, binding.Reference, binding.Version, plaintext, associatedData)
	if err != nil || len(sealed.Nonce) > 255 {
		return secretref.OpaqueEnvelope{}, secretref.ErrUnavailable
	}
	ciphertext := make([]byte, 1+len(sealed.Nonce)+len(sealed.Ciphertext))
	ciphertext[0] = byte(len(sealed.Nonce))
	copy(ciphertext[1:], sealed.Nonce)
	copy(ciphertext[1+len(sealed.Nonce):], sealed.Ciphertext)
	return secretref.OpaqueEnvelope{
		BindingDigest: binding.Digest(),
		KeyID:         binding.KeyID,
		KeyVersion:    binding.Version,
		Algorithm:     secretref.EnvelopeAlgorithmV1,
		Ciphertext:    ciphertext,
	}, nil
}

func (p *memoryEnvelopeProvider) OpenEnvelope(ctx context.Context, binding secretref.Binding, envelope secretref.OpaqueEnvelope, associatedData []byte) ([]byte, error) {
	p.openCalls++
	if p.err != nil {
		return nil, p.err
	}
	if envelope.Validate(binding) != nil || len(envelope.Ciphertext) < 2 {
		return nil, secretref.ErrInvalidEnvelope
	}
	nonceLength := int(envelope.Ciphertext[0])
	if nonceLength < 1 || len(envelope.Ciphertext) <= 1+nonceLength {
		return nil, secretref.ErrInvalidEnvelope
	}
	plaintext, err := secretref.Open(ctx, p.keys, binding.Reference, secretref.Envelope{
		KeyVersion: envelope.KeyVersion,
		Nonce:      append([]byte(nil), envelope.Ciphertext[1:1+nonceLength]...),
		Ciphertext: append([]byte(nil), envelope.Ciphertext[1+nonceLength:]...),
	}, associatedData)
	if err != nil {
		return nil, err
	}
	if p.badOpenSize {
		clear(plaintext)
		plaintext = make([]byte, 31)
	}
	p.lastOpenPlaintext = plaintext
	return plaintext, nil
}

func testVersion(now time.Time, version string, state secretref.KeyState) secretref.EnvelopeKeyVersion {
	return secretref.EnvelopeKeyVersion{
		Reference: secretref.Reference("kms://primary/recording/key-" + version),
		Version:   version,
		KeyID:     "recording-primary",
		Window: secretref.RotationWindow{
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(time.Hour),
			State:     state,
		},
	}
}

func testBindingSet(t *testing.T, now *time.Time, active string, versions ...secretref.EnvelopeKeyVersion) *secretref.EnvelopeBindingSet {
	t.Helper()
	set, err := secretref.NewEnvelopeBindingSet(
		secretref.PurposeRecordingEnvelopeKey,
		secretref.RoleProduct,
		"recording-primary",
		active,
		versions,
		func() time.Time { return *now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func testMemoryKMS(versions ...secretref.EnvelopeKeyVersion) *memoryEnvelopeProvider {
	keys := make(map[string][]byte, len(versions))
	for index, version := range versions {
		keys[version.Reference.String()+"\x00"+version.Version] = bytes.Repeat([]byte{byte(index + 1)}, 32)
	}
	return &memoryEnvelopeProvider{keys: memoryKeyProvider{keys: keys}}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func TestStoreWrapsPerRecordingKeyRoundTripRestartAndDelete(t *testing.T) {
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	version := testVersion(now, "v1", secretref.KeyActive)
	bindings := testBindingSet(t, &now, "v1", version)
	provider := testMemoryKMS(version)
	root := t.TempDir()
	store, err := New(root, provider, bindings)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(handle, keyHandlePrefix) || strings.Contains(handle, "kms://") || strings.Contains(handle, "tenant-a") || strings.Contains(handle, version.Reference.String()) {
		t.Fatalf("unsafe key handle %q", handle)
	}
	if len(provider.lastSealPlaintext) != 32 || !allZero(provider.lastSealPlaintext) {
		t.Fatal("recording data key was not cleared after wrap")
	}
	decodedHandle, err := decodeKeyHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	if decodedHandle.KMSKeyVersion != "v1" || decodedHandle.ProviderKeyID != "recording-primary" || decodedHandle.BindingDigest == "" || len(decodedHandle.WrappedDataKey) == 0 {
		t.Fatalf("decoded handle = %#v", decodedHandle)
	}

	payload := []byte("recording plaintext must never reach storage")
	reference, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", handle, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.lastOpenPlaintext) != 32 || !allZero(provider.lastOpenPlaintext) {
		t.Fatal("unwrapped data key was not cleared after segment write")
	}
	if replay, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", handle, 1, payload); err != nil || replay != reference {
		t.Fatalf("idempotent put = %q, %v", replay, err)
	}
	if _, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", handle, 1, []byte("different")); !errors.Is(err, product.ErrVersionConflict) {
		t.Fatalf("conflicting put error = %v", err)
	}

	restarted, err := New(root, provider, bindings)
	if err != nil {
		t.Fatal(err)
	}
	read, err := restarted.ReadSegment(context.Background(), "tenant-a", "rec-a", handle, 1, reference)
	if err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("restart read = %q, %v", read, err)
	}
	segmentPath, ok := store.segmentPath("tenant-a", "rec-a", reference)
	if !ok {
		t.Fatal("segment path was rejected")
	}
	stored, err := os.ReadFile(segmentPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{payload, []byte("tenant-a"), []byte(version.Reference), provider.keys.keys[version.Reference.String()+"\x00"+version.Version]} {
		if bytes.Contains(stored, forbidden) {
			t.Fatalf("stored segment exposed %q", forbidden)
		}
	}
	if err := restarted.DeleteRecording(context.Background(), "tenant-a", "rec-a", handle); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(segmentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted segment stat = %v", err)
	}
}

func TestStoreRejectsTenantRecordingHandleAndAADSubstitution(t *testing.T) {
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	version := testVersion(now, "v1", secretref.KeyActive)
	bindings := testBindingSet(t, &now, "v1", version)
	provider := testMemoryKMS(version)
	store, err := New(t.TempDir(), provider, bindings)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-a")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", handle, 1, []byte("authorized"))
	if err != nil {
		t.Fatal(err)
	}
	openCalls := provider.openCalls
	if _, err := store.PutSegment(context.Background(), "tenant-b", "rec-a", handle, 1, []byte("denied")); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("cross-tenant put error = %v", err)
	}
	if provider.openCalls != openCalls {
		t.Fatal("cross-tenant handle reached KMS")
	}
	if _, err := store.PutSegment(context.Background(), "tenant-a", "rec-b", handle, 1, []byte("denied")); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("cross-recording put error = %v", err)
	}
	if _, err := store.ReadSegment(context.Background(), "tenant-a", "rec-a", handle, 2, reference); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("sequence substitution error = %v", err)
	}
	if err := store.DeleteRecording(context.Background(), "tenant-b", "rec-a", handle); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("cross-tenant delete error = %v", err)
	}
	if payload, err := store.ReadSegment(context.Background(), "tenant-a", "rec-a", handle, 1, reference); err != nil || string(payload) != "authorized" {
		t.Fatalf("authorized content after denied delete = %q, %v", payload, err)
	}

	decoded, err := decodeKeyHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*keyHandle){
		"binding": func(value *keyHandle) { value.BindingDigest = "sha256:" + strings.Repeat("0", 64) },
		"version": func(value *keyHandle) { value.KMSKeyVersion = "v9" },
		"key id":  func(value *keyHandle) { value.ProviderKeyID = "other-key" },
		"cipher":  func(value *keyHandle) { value.WrappedDataKey[len(value.WrappedDataKey)-1] ^= 0xff },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := decoded
			candidate.WrappedDataKey = append([]byte(nil), decoded.WrappedDataKey...)
			mutate(&candidate)
			encoded, err := encodeKeyHandle(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.ReadSegment(context.Background(), "tenant-a", "rec-a", encoded, 1, reference); !errors.Is(err, product.ErrStoreUnavailable) {
				t.Fatalf("tampered handle error = %v", err)
			}
		})
	}
	if _, err := store.ReadSegment(context.Background(), "tenant-a", "rec-a", "rkey:"+strings.Repeat("A", 43), 1, reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("legacy handle error = %v", err)
	}
}

func TestStoreRejectsSegmentDocumentDriftAndCorruption(t *testing.T) {
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	version := testVersion(now, "v1", secretref.KeyActive)
	bindings := testBindingSet(t, &now, "v1", version)
	provider := testMemoryKMS(version)
	store, err := New(t.TempDir(), provider, bindings)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-a")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", handle, 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	path, ok := store.segmentPath("tenant-a", "rec-a", reference)
	if !ok {
		t.Fatal("segment path was rejected")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document, err := decodeSegmentDocument(original)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), original[:len(original)-1]...), []byte(`,"unknown":true}`)...)
	duplicate := bytes.Replace(original, []byte(`"schema":"`+segmentSchema+`"`), []byte(`"schema":"`+segmentSchema+`","schema":"`+segmentSchema+`"`), 1)
	noncanonical := append(append([]byte(nil), original...), '\n')
	drift := document
	drift.BindingDigest = "sha256:" + strings.Repeat("0", 64)
	driftBytes, err := canonicalJSON(drift)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := document
	corrupt.Ciphertext = append([]byte(nil), document.Ciphertext...)
	corrupt.Ciphertext[len(corrupt.Ciphertext)-1] ^= 0xff
	corruptBytes, err := canonicalJSON(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "noncanonical": noncanonical,
		"binding drift": driftBytes, "ciphertext": corruptBytes,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ReadSegment(context.Background(), "tenant-a", "rec-a", handle, 1, reference); !errors.Is(err, product.ErrStoreUnavailable) {
				t.Fatalf("ReadSegment() error = %v", err)
			}
		})
	}
}

func TestStoreRotationGraceRevocationExpiryAndCleanup(t *testing.T) {
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	v1 := testVersion(now, "v1", secretref.KeyActive)
	v2 := testVersion(now, "v2", secretref.KeyActive)
	provider := testMemoryKMS(v1, v2)
	root := t.TempDir()
	v1Store, err := New(root, provider, testBindingSet(t, &now, "v1", v1))
	if err != nil {
		t.Fatal(err)
	}
	v1Handle, err := v1Store.CreateKeyReference(context.Background(), "tenant-a", "rec-v1")
	if err != nil {
		t.Fatal(err)
	}
	v1Reference, err := v1Store.PutSegment(context.Background(), "tenant-a", "rec-v1", v1Handle, 1, []byte("v1 payload"))
	if err != nil {
		t.Fatal(err)
	}

	v1Grace := v1
	v1Grace.Window.State = secretref.KeyGrace
	rotated := testBindingSet(t, &now, "v2", v1Grace, v2)
	rotatedStore, err := New(root, provider, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := rotatedStore.ReadSegment(context.Background(), "tenant-a", "rec-v1", v1Handle, 1, v1Reference); err != nil || string(payload) != "v1 payload" {
		t.Fatalf("grace read = %q, %v", payload, err)
	}
	v2Handle, err := rotatedStore.CreateKeyReference(context.Background(), "tenant-a", "rec-v2")
	if err != nil {
		t.Fatal(err)
	}
	decodedV2, err := decodeKeyHandle(v2Handle)
	if err != nil {
		t.Fatal(err)
	}
	if decodedV2.KMSKeyVersion != "v2" {
		t.Fatalf("new recording key version = %q", decodedV2.KMSKeyVersion)
	}

	v1Revoked := v1
	v1Revoked.Window.State = secretref.KeyRevoked
	revokedStore, err := New(root, provider, testBindingSet(t, &now, "v2", v1Revoked, v2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokedStore.ReadSegment(context.Background(), "tenant-a", "rec-v1", v1Handle, 1, v1Reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("revoked read error = %v", err)
	}
	v1Path, ok := revokedStore.segmentPath("tenant-a", "rec-v1", v1Reference)
	if !ok {
		t.Fatal("segment path was rejected")
	}
	if err := revokedStore.DeleteRecording(context.Background(), "tenant-a", "rec-v1", v1Handle); err != nil {
		t.Fatalf("revoked cleanup = %v", err)
	}
	if _, err := os.Stat(v1Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked cleanup stat = %v", err)
	}

	now = v2.Window.NotAfter
	if _, err := rotatedStore.CreateKeyReference(context.Background(), "tenant-a", "rec-expired"); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("expired active key error = %v", err)
	}
}

func TestStoreKMSLossCancellationAndInvalidDEKFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	version := testVersion(now, "v1", secretref.KeyActive)
	provider := testMemoryKMS(version)
	store, err := New(t.TempDir(), provider, testBindingSet(t, &now, "v1", version))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-a")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", handle, 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	provider.err = errors.New("private KMS endpoint and credential details")
	if _, err := store.ReadSegment(context.Background(), "tenant-a", "rec-a", handle, 1, reference); !errors.Is(err, product.ErrStoreUnavailable) || strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("KMS loss read error = %v", err)
	}
	if _, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-b"); !errors.Is(err, product.ErrStoreUnavailable) || strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("KMS loss create error = %v", err)
	}
	if err := store.DeleteRecording(context.Background(), "tenant-a", "rec-a", handle); err != nil {
		t.Fatalf("KMS-independent cleanup = %v", err)
	}

	provider.err = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sealCalls, openCalls := provider.sealCalls, provider.openCalls
	if _, err := store.CreateKeyReference(ctx, "tenant-a", "rec-cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled create error = %v", err)
	}
	if provider.sealCalls != sealCalls || provider.openCalls != openCalls {
		t.Fatal("cancelled request reached KMS")
	}

	badHandle, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-bad")
	if err != nil {
		t.Fatal(err)
	}
	provider.badOpenSize = true
	if _, err := store.PutSegment(context.Background(), "tenant-a", "rec-bad", badHandle, 1, []byte("payload")); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("invalid DEK error = %v", err)
	}
}

func TestStoreRejectsUnsafeRootsWrongScopeAndNoncanonicalHandles(t *testing.T) {
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	version := testVersion(now, "v1", secretref.KeyActive)
	provider := testMemoryKMS(version)
	bindings := testBindingSet(t, &now, "v1", version)

	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "recordings")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link, provider, bindings); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("symlink root error = %v", err)
	}

	wrongScope, err := secretref.NewEnvelopeBindingSet(secretref.PurposeTicketEnvelopeKey, secretref.RoleProduct, version.KeyID, version.Version, []secretref.EnvelopeKeyVersion{version}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(t.TempDir(), provider, wrongScope); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("wrong binding scope error = %v", err)
	}

	store, err := New(t.TempDir(), provider, bindings)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-a")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeKeyHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"unknown":true}`)...)
	duplicate := bytes.Replace(document, []byte(`"schema":"`+keyHandleSchema+`"`), []byte(`"schema":"`+keyHandleSchema+`","schema":"`+keyHandleSchema+`"`), 1)
	for name, candidate := range map[string][]byte{
		"unknown":   unknown,
		"duplicate": duplicate,
		"trailing":  append(append([]byte(nil), document...), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			encoded := keyHandlePrefix + base64.RawURLEncoding.EncodeToString(candidate)
			if _, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", encoded, 1, []byte("payload")); !errors.Is(err, product.ErrStoreUnavailable) {
				t.Fatalf("noncanonical handle error = %v", err)
			}
		})
	}
}

func TestStoreRejectsSymlinkRecordingDirectory(t *testing.T) {
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	version := testVersion(now, "v1", secretref.KeyActive)
	store, err := New(t.TempDir(), testMemoryKMS(version), testBindingSet(t, &now, "v1", version))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := store.CreateKeyReference(context.Background(), "tenant-a", "rec-a")
	if err != nil {
		t.Fatal(err)
	}
	directory := store.recordingDirectory("tenant-a", "rec-a")
	if err := os.Symlink(t.TempDir(), directory); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSegment(context.Background(), "tenant-a", "rec-a", handle, 1, []byte("payload")); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("PutSegment(linked recording directory) error = %v", err)
	}
	if _, err := store.ReadSegment(context.Background(), "tenant-a", "rec-a", handle, 1, "recording:rec-a:1"); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("ReadSegment(linked recording directory) error = %v", err)
	}
	if err := store.DeleteSegments(context.Background(), "tenant-a", "rec-a", handle, []string{"recording:rec-a:1"}); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("DeleteSegments(linked recording directory) error = %v", err)
	}
	if err := store.DeleteRecording(context.Background(), "tenant-a", "rec-a", handle); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("DeleteRecording(linked recording directory) error = %v", err)
	}
}
