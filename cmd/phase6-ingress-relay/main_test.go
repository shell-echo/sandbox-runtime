package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestIngressRelayAuthorityIsClosedAndPinned(t *testing.T) {
	valid := authority{Version: 1, SecurityProfilePath: "/run/security/profile.json",
		SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
		RelayPrincipalDigest:  "sha256:" + strings.Repeat("b", 64)}
	document, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := parseAuthority(document); err != nil || parsed != valid {
		t.Fatalf("valid authority: %+v %v", parsed, err)
	}
	for name, candidate := range map[string][]byte{
		"unknown":      bytes.Replace(document, []byte(`"version":1`), []byte(`"version":1,"upstream":"8.8.8.8:443"`), 1),
		"duplicate":    bytes.Replace(document, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"trailing":     append(bytes.Clone(document), []byte("\n")...),
		"relative":     bytes.Replace(document, []byte("/run/security/profile.json"), []byte("profile.json"), 1),
		"wrong digest": bytes.Replace(document, []byte("sha256:"+strings.Repeat("a", 64)), []byte("sha256:bad"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAuthority(candidate); err == nil {
				t.Fatal("unsafe ingress relay authority accepted")
			}
		})
	}
}

func TestIngressRelayCommandRequiresExactArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"serve"}, {"probe", "/tmp/authority.json"}, {"serve", "authority.json"}} {
		if err := run(args); err == nil {
			t.Fatalf("invalid arguments accepted: %#v", args)
		}
	}
}
