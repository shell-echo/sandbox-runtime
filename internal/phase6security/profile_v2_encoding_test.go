package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

// This oracle keeps the old two-encoding policy independent of the production
// helpers. Partial fixtures below exercise only that policy, never admission.
func referenceV2Encoding(t *testing.T, p ProfileV2) ([]byte, string, error) {
	t.Helper()
	signed, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	expected := p.ProfileDigest
	p.ProfileDigest = ""
	unsigned, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-security-profile/v2\x00"), unsigned...))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if len(signed) > maxBytes || expected != digest {
		return unsigned, digest, ErrInvalidProfile
	}
	return unsigned, digest, nil
}

func TestProfileV2DocumentSizeBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		want error
	}{{"below", maxBytes - 1, nil}, {"at", maxBytes, nil}, {"above", maxBytes + 1, ErrInvalidProfile}} {
		t.Run(tc.name, func(t *testing.T) {
			p := ProfileV2{ProfileDigest: testDigest("size")}
			base, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			p.Revision = strings.Repeat("x", tc.size-len(base))
			_, p.ProfileDigest, _ = referenceV2Encoding(t, p)
			wire, err := json.Marshal(p)
			if err != nil || len(wire) != tc.size {
				t.Fatalf("incorrect boundary fixture: size %d, error %v", len(wire), err)
			}
			_, _, original := referenceV2Encoding(t, p)
			if original != tc.want || p.validateDocument() != original {
				t.Fatal("signed document size boundary changed")
			}
			if p.Validate() == nil {
				t.Fatal("encoding-only fixture became admitted")
			}
		})
	}
}

func TestProfileV2DocumentDigestEquivalence(t *testing.T) {
	for _, name := range []string{"ordinary", "escaped", "invalid_utf8", "execution", "nil_collections", "empty_collections"} {
		t.Run(name, func(t *testing.T) {
			p := ProfileV2{Protocol: ProtocolIDV2, Version: VersionV2, Revision: "encoding",
				Networks: []Network{{Name: "ordinary"}},
				Principals: []Principal{{Name: "nested", AuthorizationPrincipal: &securityprincipal.Principal{
					ProfileDigest: testDigest("nested"),
				}}},
				SandboxGatewayLimits: map[string]Resources{"z": {CPUMillis: 2}, "a": {CPUMillis: 1}},
			}
			switch name {
			case "escaped":
				p.Revision = "<>&\"\\\n\t\u2028\u2029中文 profile_digest"
			case "invalid_utf8":
				p.Revision = "invalid\xffutf8"
			case "execution":
				p.CodingExecution = &CodingExecutionProfileV3{Protocol: CodingExecutionProfileProtocol}
			case "nil_collections":
				p.Networks = nil
			case "empty_collections":
				p.Networks = []Network{}
			}
			unsigned, expected, _ := referenceV2Encoding(t, p)
			p.ProfileDigest = expected
			before, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.digestDocument()
			if err != nil || !bytes.Equal(got, unsigned) || p.Digest() != expected || p.validateDocument() != nil {
				t.Fatal("digest preimage, domain or encoding policy changed")
			}
			if len(before) != len(got)+len(expected) {
				t.Fatal("restored root digest size differs from signed encoding")
			}
			after, err := json.Marshal(p)
			if err != nil || !bytes.Equal(before, after) || p.Principals[0].AuthorizationPrincipal.ProfileDigest != testDigest("nested") {
				t.Fatal("root digest clearing modified caller or nested digest")
			}
		})
	}
}

func TestProfileV2DocumentRejectsWrongDigest(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"empty", ""}, {"wrong", testDigest("wrong")}, {"uppercase", "sha256:" + strings.Repeat("A", 64)},
		{"escaped", "sha256:\"\\\n<>&"}, {"short", "sha256:0"}, {"long", strings.Repeat("x", 1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ProfileV2{ProfileDigest: tc.value}
			_, expected, original := referenceV2Encoding(t, p)
			if original != ErrInvalidProfile || p.validateDocument() != original || p.Digest() != expected {
				t.Fatal("wrong digest accepted or stored digest entered preimage")
			}
		})
	}
}

func TestProfileV2DocumentDoesNotReuseMutableInput(t *testing.T) {
	p := ProfileV2{Networks: []Network{{Name: "before"}},
		SandboxGatewayLimits: map[string]Resources{"shared": {CPUMillis: 1}}}
	_, p.ProfileDigest, _ = referenceV2Encoding(t, p)
	alias := p
	if p.validateDocument() != nil {
		t.Fatal("initial document rejected")
	}
	alias.Networks[0].Name = "after"
	alias.SandboxGatewayLimits["shared"] = Resources{CPUMillis: 2}
	if p.validateDocument() != ErrInvalidProfile {
		t.Fatal("between-call shared input change reused an old digest")
	}
	_, p.ProfileDigest, _ = referenceV2Encoding(t, p)
	if p.validateDocument() != nil {
		t.Fatal("newly bound document rejected")
	}
}

func TestProfileV2EncodingTypeAssumptions(t *testing.T) {
	root := reflect.TypeFor[ProfileV2]()
	f, ok := root.FieldByName("ProfileDigest")
	if !ok || f.Type != reflect.TypeFor[string]() || f.Tag.Get("json") != "profile_digest" {
		t.Fatal("root digest encoding changed; review the size equation")
	}
	for i := range root.NumField() {
		if root.Field(i).Anonymous || (root.Field(i).Name != "ProfileDigest" && root.Field(i).Tag.Get("json") == "profile_digest") {
			t.Fatal("root digest field may be hidden or duplicated")
		}
	}
	jsonMarshaler := reflect.TypeFor[json.Marshaler]()
	textMarshaler := reflect.TypeFor[encoding.TextMarshaler]()
	seen, active := map[reflect.Type]bool{}, map[reflect.Type]bool{}
	var visit func(reflect.Type)
	visit = func(v reflect.Type) {
		if active[v] {
			t.Fatalf("recursive encoding type needs independent review: %v", v)
		}
		if seen[v] {
			return
		}
		for _, candidate := range []reflect.Type{v, reflect.PointerTo(v)} {
			if candidate.Implements(jsonMarshaler) || candidate.Implements(textMarshaler) {
				t.Fatalf("custom marshaler needs independent review: %v", candidate)
			}
		}
		active[v] = true
		switch v.Kind() {
		case reflect.Struct:
			for i := range v.NumField() {
				field := v.Field(i)
				if field.IsExported() && field.Tag.Get("json") != "-" {
					visit(field.Type)
				}
			}
		case reflect.Pointer, reflect.Array, reflect.Slice:
			visit(v.Elem())
		case reflect.Map:
			if v.Key().Kind() != reflect.String {
				t.Fatalf("non-string map key needs review: %v", v)
			}
			visit(v.Key())
			visit(v.Elem())
		case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		default:
			t.Fatalf("dynamic or unsupported encoding type needs review: %v", v)
		}
		delete(active, v)
		seen[v] = true
	}
	visit(root)
}
