package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
)

func TestProductionAuthorityRequiresV2RemoteSigner(t *testing.T) {
	valid := authority{Version: 2, Role: executorprotocol.RoleBrowser, ListenAddress: "127.0.0.1:9443",
		UpstreamURL:         "ws://127.0.0.1:9222/devtools/browser/opaque",
		SecurityProfilePath: "/private/profile.json", SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
		PeerCRLRoleFile: "/private/browser-peer-crl-role.json", PeerCRLRoleDigest: "sha256:" + strings.Repeat("b", 64),
		PeerCRLSourceMappingDigest: "sha256:" + strings.Repeat("c", 64),
		TLSAgentSocket:             "/run/tls/browser-executor-tls-agent/signer.sock", TLSAgentUID: 20001, TLSAgentGID: 30001,
		MaxSessions: 2, OperationTimeoutMillis: 5000}
	document, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := parseAuthority(document)
	if err != nil || validateAuthority(decoded) != nil {
		t.Fatalf("valid v2 authority rejected: %v", err)
	}
	legacy := valid
	legacy.Version = 1
	legacyDocument, _ := json.Marshal(legacy)
	if _, err := parseAuthority(legacyDocument); err == nil {
		t.Fatal("legacy local-key authority accepted")
	}
	for _, unsafe := range [][]byte{
		bytes.Replace(document, []byte(`"version":`), []byte(`"server_private_key_file":"/private/key","version":`), 1),
		bytes.Replace(document, []byte(`"version":`), []byte(`"version":2,"version":`), 1),
	} {
		if _, err := parseAuthority(unsafe); err == nil {
			t.Fatal("unknown or duplicate authority field accepted")
		}
	}
	valid.TLSAgentSocket = "relative.sock"
	if validateAuthority(valid) == nil {
		t.Fatal("relative TLS agent socket accepted")
	}
	valid.TLSAgentSocket = "/run/tls/browser-executor-tls-agent/signer.sock"
	for _, mutate := range []func(*authority){
		func(value *authority) { value.PeerCRLRoleFile = "" },
		func(value *authority) { value.PeerCRLRoleDigest = "" },
		func(value *authority) { value.PeerCRLSourceMappingDigest = "" },
		func(value *authority) { value.PeerCRLRoleDigest = "sha256:bad" },
		func(value *authority) { value.PeerCRLRoleFile = value.SecurityProfilePath },
	} {
		invalid := valid
		mutate(&invalid)
		if validateAuthority(invalid) == nil {
			t.Fatal("incomplete or conflicting peer CRL binding accepted")
		}
	}
}
