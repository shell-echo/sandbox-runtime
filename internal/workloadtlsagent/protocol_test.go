package workloadtlsagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testProtocolRequest(now time.Time, kind string) Request {
	digest := sha256.Sum256([]byte("transcript"))
	generation := int64(1)
	value := digest[:]
	if kind == SnapshotType {
		generation, value = 0, nil
	}
	return newRequest(kind, "tls_"+strings.Repeat("a", 32), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		now.Add(10*time.Second), generation, value)
}

func TestProtocolRejectsUnknownDuplicateTrailingAndNonCanonicalInput(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request := testProtocolRequest(now, SnapshotType)
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(document[:len(document)-1], []byte(`,"unknown":true}`)...)
	duplicate := append(document[:len(document)-1], []byte(`,"nonce":"`+request.Nonce+`"}`)...)
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "trailing": append(append([]byte(nil), document...), '\n'),
		"noncanonical": bytes.Replace(document, []byte(`"protocol"`), []byte(`"protocol" `), 1),
		"oversized":    bytes.Repeat([]byte{'x'}, maxRequestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequest(candidate, now); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("decodeRequest() error = %v", err)
			}
		})
	}
}

func TestProtocolBindsDeadlineGenerationHashAndDigest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := testProtocolRequest(now, SignType)
	if valid.Validate(now) != nil {
		t.Fatal("valid sign request rejected")
	}
	mutations := []func(*Request){
		func(value *Request) { value.Protocol = "sandbox-runtime.workload-tls-agent.v0" },
		func(value *Request) { value.Deadline = now.Add(-time.Second).Format(time.RFC3339Nano) },
		func(value *Request) { value.Deadline = now.Add(2 * time.Minute).Format(time.RFC3339Nano) },
		func(value *Request) { value.Generation = 0 },
		func(value *Request) { value.Hash = "sha512" },
		func(value *Request) { value.Digest = value.Digest[:31] },
		func(value *Request) { value.RequestDigest = "sha256:" + strings.Repeat("0", 64) },
	}
	for index, mutate := range mutations {
		candidate := valid
		candidate.Digest = append([]byte(nil), valid.Digest...)
		mutate(&candidate)
		if candidate.Validate(now) == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}

func TestProtocolResponseRejectsStaleOrCrossRequestData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request := testProtocolRequest(now, SnapshotType)
	response := Response{Protocol: ProtocolID, Type: SuccessType, RequestID: request.RequestID, RequestDigest: request.RequestDigest,
		Generation: 1, IssuerRevision: "vault-test", Serial: "01:02", CertificateDER: [][]byte{{1}, {2}}, PublicKeyDER: []byte{1},
		NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), NotAfter: now.Add(time.Minute).Format(time.RFC3339Nano),
		RevocationSafeTo: now.Add(30 * time.Second).Format(time.RFC3339Nano)}
	if response.Validate(request, now) != nil {
		t.Fatal("valid snapshot response rejected")
	}
	response.RequestDigest = "sha256:" + strings.Repeat("0", 64)
	if response.Validate(request, now) == nil {
		t.Fatal("cross-request response accepted")
	}
	response.RequestDigest = request.RequestDigest
	response.RevocationSafeTo = now.Format(time.RFC3339Nano)
	if response.Validate(request, now) == nil {
		t.Fatal("stale snapshot accepted")
	}
}
