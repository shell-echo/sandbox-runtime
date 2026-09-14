package suitedigest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const placeholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func TestComputeUsesRFC8785WithoutSuiteDigest(t *testing.T) {
	document := []byte(localDocument(placeholderDigest, `["a","b"]`))
	want := "sha256:d0a20aa4a052ea3e549c6cd4becfda64dee4572c6ccae6a7c7d848c4e8453e1c"
	got, err := Compute(document, DigestProfile)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if got != want {
		t.Fatalf("Compute = %q, want %q", got, want)
	}

	reordered := []byte("{\n" +
		`  "suite_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",` + "\n" +
		`  "profiles": [ { "tests": ["a", "b"], "execution_mode": "repository-go-test", "profile_id": "p" } ],` + "\n" +
		`  "suite_digest_profile": "rfc8785-full-document-excluding-suite-digest-v1",` + "\n" +
		`  "suite_version": "1.0.0", "suite_id": "sandbox-provider"` + "\n}")
	equivalent, err := Compute(reordered, DigestProfile)
	if err != nil {
		t.Fatalf("Compute reordered: %v", err)
	}
	if equivalent != want {
		t.Fatalf("Compute reordered = %q, want %q", equivalent, want)
	}

	changed := []byte(localDocument(placeholderDigest, `["b","a"]`))
	changedDigest, err := Compute(changed, DigestProfile)
	if err != nil {
		t.Fatalf("Compute changed: %v", err)
	}
	if changedDigest == want {
		t.Fatal("case order change did not change Suite digest")
	}

	withFalse := strings.Replace(localDocument(placeholderDigest, `["a","b"]`), `"tests"`, `"mutations_performed":false,"tests"`, 1)
	withFalseDigest, err := Compute([]byte(withFalse), DigestProfile)
	if err != nil {
		t.Fatalf("Compute explicit false: %v", err)
	}
	if withFalseDigest == want {
		t.Fatal("explicit mutations_performed=false was omitted from Suite digest")
	}
}

func TestComputeRepositorySuiteGoldenDigests(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			path: "../../contract/conformance/provider-v1/suite.json",
			want: "sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8",
		},
		{
			path: "../../contract/conformance/provider-remote-v1/suite.json",
			want: "sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0",
		},
	}
	for _, test := range tests {
		t.Run(filepath.Base(filepath.Dir(test.path)), func(t *testing.T) {
			document, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Compute(document, DigestProfile)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if got != test.want {
				t.Fatalf("Compute = %q, want %q", got, test.want)
			}
		})
	}
}

func TestVerifyRequiresDeclaredContentDigest(t *testing.T) {
	unsigned := localDocument(placeholderDigest, `["a"]`)
	digest, err := Compute([]byte(unsigned), DigestProfile)
	if err != nil {
		t.Fatal(err)
	}
	signed := strings.Replace(unsigned, placeholderDigest, digest, 1)
	verified, err := Verify([]byte(signed), DigestProfile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.SuiteID != "sandbox-provider" || verified.SuiteVersion != "1.0.0" || verified.SuiteDigestProfile != DigestProfile || verified.SuiteDigest != digest {
		t.Fatalf("verified Suite = %+v", verified)
	}
	profile, err := verified.RequiredProfile("p")
	if err != nil || profile.ExecutionMode != ExecutionModeRepositoryGoTest || profile.MutationsPerformed != nil || len(profile.Tests) != 1 || profile.Tests[0] != "a" {
		t.Fatalf("RequiredProfile = %+v, %v", profile, err)
	}
	profile.Tests[0] = "mutated"
	again, err := verified.RequiredProfile("p")
	if err != nil || again.Tests[0] != "a" {
		t.Fatalf("RequiredProfile defensive copy = %+v, %v", again, err)
	}

	if _, err := Verify([]byte(unsigned), DigestProfile); err == nil || !strings.Contains(err.Error(), "does not match computed digest") {
		t.Fatalf("Verify placeholder = %v", err)
	}
	if _, err := Verify([]byte(signed), "sha256-file-v1"); err == nil || !strings.Contains(err.Error(), "unsupported Suite digest profile") {
		t.Fatalf("Verify unsupported profile = %v", err)
	}
	if _, err := verified.RequiredProfile("missing"); err == nil || !strings.Contains(err.Error(), "missing required profile") {
		t.Fatalf("RequiredProfile missing = %v", err)
	}
}

func TestVerifyRemoteProfilePreservesExplicitFalse(t *testing.T) {
	unsigned := `{"suite_id":"sandbox-provider-remote","suite_version":"1.0.0","suite_digest_profile":"` + DigestProfile + `","profiles":[{"profile_id":"remote","execution_mode":"remote-http-black-box","mutations_performed":false,"tests":["case"]}],"suite_digest":"` + placeholderDigest + `"}`
	digest, err := Compute([]byte(unsigned), DigestProfile)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify([]byte(strings.Replace(unsigned, placeholderDigest, digest, 1)), DigestProfile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	profile, err := verified.RequiredProfile("remote")
	if err != nil || profile.ExecutionMode != ExecutionModeRemoteHTTPBlackBox || profile.MutationsPerformed == nil || *profile.MutationsPerformed {
		t.Fatalf("RequiredProfile = %+v, %v", profile, err)
	}
	*profile.MutationsPerformed = true
	again, err := verified.RequiredProfile("remote")
	if err != nil || again.MutationsPerformed == nil || *again.MutationsPerformed {
		t.Fatalf("RequiredProfile defensive bool copy = %+v, %v", again, err)
	}
}

func TestComputeRejectsInvalidSuiteDocuments(t *testing.T) {
	valid := localDocument(placeholderDigest, `["a"]`)
	tests := []struct {
		name     string
		document []byte
		want     string
	}{
		{name: "empty", want: "size must be"},
		{name: "whitespace", document: []byte(" \n\t"), want: "canonicalize Suite"},
		{name: "invalid UTF-8", document: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, want: "valid UTF-8"},
		{name: "not object", document: []byte(`[]`), want: "JSON object"},
		{name: "null root", document: []byte(`null`), want: "JSON object"},
		{name: "unknown member", document: []byte(strings.Replace(valid, `,"suite_digest"`, `,"unknown":true,"suite_digest"`, 1)), want: "unknown field"},
		{name: "unknown profile member", document: []byte(strings.Replace(valid, `"tests"`, `"unknown":true,"tests"`, 1)), want: "unknown field"},
		{name: "nested suite digest", document: []byte(strings.Replace(valid, `"tests"`, `"suite_digest":"`+placeholderDigest+`","tests"`, 1)), want: "unknown field"},
		{name: "duplicate top-level member", document: []byte(strings.Replace(valid, `"suite_id":"sandbox-provider"`, `"suite_id":"sandbox-provider","suite_id":"other"`, 1)), want: "Duplicate key"},
		{name: "escaped duplicate top-level member", document: []byte(strings.Replace(valid, `"suite_id":"sandbox-provider"`, `"suite_id":"sandbox-provider","suite\u005fid":"other"`, 1)), want: "Duplicate key"},
		{name: "duplicate profile member", document: []byte(strings.Replace(valid, `"profile_id":"p"`, `"profile_id":"p","profile_id":"q"`, 1)), want: "Duplicate key"},
		{name: "trailing JSON", document: []byte(valid + `{}`), want: "canonicalize Suite"},
		{name: "missing digest", document: []byte(strings.Replace(valid, `,"suite_digest":"`+placeholderDigest+`"`, "", 1)), want: "digest must be"},
		{name: "null digest", document: []byte(strings.Replace(valid, `"suite_digest":"`+placeholderDigest+`"`, `"suite_digest":null`, 1)), want: "digest must be"},
		{name: "uppercase digest", document: []byte(strings.Replace(valid, placeholderDigest, "sha256:"+strings.Repeat("A", 64), 1)), want: "lowercase SHA-256"},
		{name: "invalid version", document: []byte(strings.Replace(valid, `"suite_version":"1.0.0"`, `"suite_version":"v1"`, 1)), want: "semantic version"},
		{name: "missing digest profile", document: []byte(strings.Replace(valid, `,"suite_digest_profile":"`+DigestProfile+`"`, "", 1)), want: "digest profile is required"},
		{name: "null digest profile", document: []byte(strings.Replace(valid, `"suite_digest_profile":"`+DigestProfile+`"`, `"suite_digest_profile":null`, 1)), want: "digest profile is required"},
		{name: "mismatched digest profile", document: []byte(strings.Replace(valid, DigestProfile, "other-profile", 1)), want: "does not match requested profile"},
		{name: "empty profiles", document: []byte(strings.Replace(valid, `[{"profile_id":"p","execution_mode":"repository-go-test","tests":["a"]}]`, `[]`, 1)), want: "profiles count"},
		{name: "null profiles", document: []byte(strings.Replace(valid, `[{"profile_id":"p","execution_mode":"repository-go-test","tests":["a"]}]`, `null`, 1)), want: "profiles count"},
		{name: "blank profile", document: []byte(strings.Replace(valid, `"profile_id":"p"`, `"profile_id":" "`, 1)), want: "profile 0 ID"},
		{name: "duplicate profile", document: []byte(strings.Replace(valid, `[{"profile_id":"p","execution_mode":"repository-go-test","tests":["a"]}]`, `[{"profile_id":"p","execution_mode":"repository-go-test","tests":["a"]},{"profile_id":"p","execution_mode":"repository-go-test","tests":["b"]}]`, 1)), want: "duplicate profile"},
		{name: "missing execution mode", document: []byte(strings.Replace(valid, `,"execution_mode":"repository-go-test"`, "", 1)), want: "unsupported execution mode"},
		{name: "unsupported execution mode", document: []byte(strings.Replace(valid, ExecutionModeRepositoryGoTest, "shell-script", 1)), want: "unsupported execution mode"},
		{name: "repository mutations true", document: []byte(strings.Replace(valid, `"tests"`, `"mutations_performed":true,"tests"`, 1)), want: "cannot perform mutations"},
		{name: "remote mutations missing", document: []byte(strings.Replace(valid, ExecutionModeRepositoryGoTest, ExecutionModeRemoteHTTPBlackBox, 1)), want: "requires mutations_performed"},
		{name: "remote mutations null", document: []byte(strings.Replace(strings.Replace(valid, ExecutionModeRepositoryGoTest, ExecutionModeRemoteHTTPBlackBox, 1), `"tests"`, `"mutations_performed":null,"tests"`, 1)), want: "must be a boolean"},
		{name: "remote mutations true", document: []byte(strings.Replace(strings.Replace(valid, ExecutionModeRepositoryGoTest, ExecutionModeRemoteHTTPBlackBox, 1), `"tests"`, `"mutations_performed":true,"tests"`, 1)), want: "must set mutations_performed to false"},
		{name: "empty tests", document: []byte(strings.Replace(valid, `["a"]`, `[]`, 1)), want: "tests count"},
		{name: "null tests", document: []byte(strings.Replace(valid, `["a"]`, `null`, 1)), want: "tests count"},
		{name: "blank case", document: []byte(strings.Replace(valid, `["a"]`, `[" "]`, 1)), want: "test 0 ID"},
		{name: "duplicate case", document: []byte(strings.Replace(valid, `["a"]`, `["a","a"]`, 1)), want: "duplicate case"},
		{name: "lone high surrogate", document: []byte(strings.Replace(valid, "sandbox-provider", `sandbox-\uD800`, 1)), want: "invalid Unicode surrogate"},
		{name: "lone low surrogate", document: []byte(strings.Replace(valid, "sandbox-provider", `sandbox-\uDC00`, 1)), want: "invalid Unicode surrogate"},
		{name: "mismatched surrogate pair", document: []byte(strings.Replace(valid, "sandbox-provider", `sandbox-\uD800\u0041`, 1)), want: "invalid Unicode surrogate"},
		{name: "oversized", document: []byte("{" + strings.Repeat(" ", MaxDocumentBytes) + "}"), want: "size must be"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Compute(test.document, DigestProfile); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Compute = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestComputeAcceptsValidUnicodeAndRepeatedCasesAcrossProfiles(t *testing.T) {
	document := []byte(`{"suite_id":"sandbox-\uD83D\uDE80","suite_version":"1.0.0","suite_digest_profile":"` + DigestProfile + `","profiles":[{"profile_id":"one","execution_mode":"repository-go-test","tests":["same"]},{"profile_id":"two","execution_mode":"repository-go-test","mutations_performed":false,"tests":["same"]}],"suite_digest":"` + placeholderDigest + `"}`)
	if _, err := Compute(document, DigestProfile); err != nil {
		t.Fatalf("Compute: %v", err)
	}
}

func TestLoadRejectsNonRegularOrEmptyFile(t *testing.T) {
	root := t.TempDir()
	if _, err := Load(root, DigestProfile); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load directory = %v", err)
	}
	empty := filepath.Join(root, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(empty, DigestProfile); err == nil || !strings.Contains(err.Error(), "size must be") {
		t.Fatalf("Load empty = %v", err)
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "suite.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link, DigestProfile); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load symlink = %v", err)
	}
}

func localDocument(digest, tests string) string {
	return `{"suite_id":"sandbox-provider","suite_version":"1.0.0","suite_digest_profile":"` + DigestProfile + `","profiles":[{"profile_id":"p","execution_mode":"repository-go-test","tests":` + tests + `}],"suite_digest":"` + digest + `"}`
}
