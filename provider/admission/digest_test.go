package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVerifyRequestDigestCanonicalizesStrictJSON(t *testing.T) {
	canonical := "{\"a\":{\"a\":1,\"b\":2},\"currency\":\"\xe2\x82\xac\",\"n\":4.5,\"z\":0}"
	document := []byte("{\"z\":0,\"currency\":\"\xe2\x82\xac\",\"a\":{\"b\":2,\"a\":1},\"n\":4.50}")
	if err := VerifyRequestDigest(DigestProfileFullDocument, digestForTest(canonical), document); err != nil {
		t.Fatalf("VerifyRequestDigest() error = %v", err)
	}
}

func TestVerifyRequestDigestExcludesAndBindsRequestDigest(t *testing.T) {
	canonical := "{\"nested\":{\"a\":1,\"b\":2},\"operation\":\"exec\"}"
	expected := digestForTest(canonical)
	document := []byte("{\"request_digest\":\"" + expected + "\",\"operation\":\"exec\",\"nested\":{\"b\":2,\"a\":1}}")
	if err := VerifyRequestDigest(DigestProfileRequestExcludingDigest, expected, document); err != nil {
		t.Fatalf("VerifyRequestDigest() error = %v", err)
	}

	changed := []byte("{\"request_digest\":\"" + expected + "\",\"operation\":\"exec\",\"nested\":{\"b\":3,\"a\":1}}")
	if err := VerifyRequestDigest(DigestProfileRequestExcludingDigest, expected, changed); err != ErrRequestDigestMismatch {
		t.Fatalf("changed document error = %v, want %v", err, ErrRequestDigestMismatch)
	}

	wrongEmbedded := []byte("{\"request_digest\":\"" + digestForTest("other") + "\",\"operation\":\"exec\",\"nested\":{\"b\":2,\"a\":1}}")
	if err := VerifyRequestDigest(DigestProfileRequestExcludingDigest, expected, wrongEmbedded); err != ErrRequestDigestMismatch {
		t.Fatalf("wrong embedded digest error = %v, want %v", err, ErrRequestDigestMismatch)
	}
}

func TestVerifyRequestDigestRejectsUnsafeOrMalformedDocuments(t *testing.T) {
	expected := digestForTest("{}")
	tests := []struct {
		name     string
		profile  DigestProfile
		document []byte
	}{
		{name: "duplicate key", profile: DigestProfileFullDocument, document: []byte(`{"a":1,"a":2}`)},
		{name: "unsafe integer", profile: DigestProfileFullDocument, document: []byte(`{"n":9007199254740994}`)},
		{name: "unsafe decimal integer", profile: DigestProfileFullDocument, document: []byte(`{"n":9007199254740992.0}`)},
		{name: "oversized exponent", profile: DigestProfileFullDocument, document: []byte(`{"n":1e-1000000000}`)},
		{name: "lone surrogate", profile: DigestProfileFullDocument, document: []byte(`{"s":"\ud800"}`)},
		{name: "missing request digest", profile: DigestProfileRequestExcludingDigest, document: []byte(`{"operation":"exec"}`)},
		{name: "non object", profile: DigestProfileFullDocument, document: []byte(`[]`)},
		{name: "invalid utf8", profile: DigestProfileFullDocument, document: []byte{'{', '"', 's', '"', ':', '"', 0xff, '"', '}'}},
		{name: "excessive nesting", profile: DigestProfileFullDocument, document: []byte(`{"nested":` + strings.Repeat(`[`, maxAdmissionJSONDepth) + `0` + strings.Repeat(`]`, maxAdmissionJSONDepth) + `}`)},
		{name: "oversized document", profile: DigestProfileFullDocument, document: []byte("{" + strings.Repeat(" ", maxAdmissionDocumentBytes) + "}")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyRequestDigest(test.profile, expected, test.document); err != ErrInvalidRequestDocument {
				t.Fatalf("VerifyRequestDigest() error = %v, want %v", err, ErrInvalidRequestDocument)
			}
		})
	}
}

func digestForTest(canonical string) string {
	digest := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(digest[:])
}
