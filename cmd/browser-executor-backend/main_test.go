package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestProductionAuthorityRequiresV3ProviderMuxAndRemoteSigner(t *testing.T) {
	valid := authority{Version: 3, Role: executorprotocol.RoleBrowser, ListenAddress: "127.0.0.1:9443",
		MuxSocketPath:    phase6security.BrowserMuxSocketDirectory + "/browser-mux-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock",
		MuxDirectoryMode: 0o710, MuxSocketMode: 0o666, MuxOwnerUID: 20002, MuxDirectoryGID: 30002,
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
		t.Fatalf("valid v3 authority rejected: %v", err)
	}
	legacy := valid
	legacy.Version = 2
	legacyDocument, _ := json.Marshal(legacy)
	if _, err := parseAuthority(legacyDocument); err == nil {
		t.Fatal("legacy local-key authority accepted")
	}
	for _, unsafe := range [][]byte{
		bytes.Replace(document, []byte(`"version":`), []byte(`"server_private_key_file":"/private/key","version":`), 1),
		bytes.Replace(document, []byte(`"version":`), []byte(`"version":3,"version":`), 1),
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
		func(value *authority) { value.UpstreamURL = "ws://127.0.0.1:9222/devtools/browser/old" },
		func(value *authority) { value.MuxSocketPath = "" },
		func(value *authority) { value.MuxSocketPath = "/private/other.sock" },
		func(value *authority) {
			value.MuxSocketPath = "/private/browser-mux-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock"
		},
		func(value *authority) { value.MuxDirectoryMode = 0o777 },
		func(value *authority) { value.MuxOwnerUID = 0 },
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

func TestBrowserMuxProfileBindsExactProviderAndBackendOwners(t *testing.T) {
	profile := phase6security.Profile{Principals: []phase6security.Principal{
		{Name: "provider-browser-runtime", UID: 20002, GID: 30002},
		{Name: "browser-executor-backend", UID: 20003, GID: 30003},
	}}
	value := authority{MuxSocketPath: phase6security.BrowserMuxSocketDirectory + "/browser-mux-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock",
		MuxDirectoryMode: 0o710, MuxSocketMode: 0o666, MuxOwnerUID: 20002, MuxDirectoryGID: 30003}
	if err := validateMuxProfile(profile, value); err != nil {
		t.Fatal(err)
	}
	value.MuxDirectoryGID = 30002
	if validateMuxProfile(profile, value) == nil {
		t.Fatal("Browser backend inherited Provider group ownership")
	}
	value.MuxDirectoryGID = 30003
	value.MuxOwnerUID = 20003
	if validateMuxProfile(profile, value) == nil {
		t.Fatal("Browser backend claimed Provider mux socket ownership")
	}
}
