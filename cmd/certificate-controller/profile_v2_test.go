package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func TestControllerConfigVersionsAndPolicyPurposes(t *testing.T) {
	for _, version := range []string{configProtocol, peerCRLConfigProtocol, profileV2ConfigProtocol} {
		c := configDocument{Protocol: version}
		if version != configProtocol {
			c.PeerCRLSourcesPath = "/run/phase6/config/peer-crl-sources.json"
			c.PeerCRLSourcesDigest = "pinned"
		}
		if !validControllerConfigVersion(c) {
			t.Fatal("known version rejected", version)
		}
		c.Protocol += "-unknown"
		if validControllerConfigVersion(c) {
			t.Fatal("unknown version accepted")
		}
	}
	for _, version := range []string{peerCRLConfigProtocol, profileV2ConfigProtocol} {
		for _, c := range []configDocument{{Protocol: version}, {Protocol: version, PeerCRLSourcesPath: "relative", PeerCRLSourcesDigest: "pinned"}, {Protocol: version, PeerCRLSourcesPath: "/run/sources"}} {
			if validControllerConfigVersion(c) {
				t.Fatal("missing source pin accepted")
			}
		}
	}
	for _, p := range []certificatePolicy{{}, {Purpose: workloadpki.PostgresClientPurpose, Postgres: &postgresClientConfig{}}} {
		if !validCertificatePolicyPurpose(p) {
			t.Fatal("known purpose rejected")
		}
	}
	for _, p := range []certificatePolicy{{Purpose: "unknown"}, {Postgres: &postgresClientConfig{}}, {Purpose: workloadpki.PostgresClientPurpose}} {
		if validCertificatePolicyPurpose(p) {
			t.Fatal("purpose downgrade accepted")
		}
	}
}

// This executes the real command entry in a separate process. Sharing the
// inherited open-file descriptions lets the parent detect any key FD read.
// The draft is intentionally not release evidence or a complete live Profile.
func TestControllerV2RejectsBeforeReadingInheritedKeys(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CONTROLLER_PREFLIGHT_CHILD") == "1" {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "stage security-profile:") {
			t.Fatalf("unexpected command rejection: %v", err)
		}
		return
	}
	directory := t.TempDir()
	profile := phase6security.ProfileV2{Protocol: phase6security.ProtocolIDV2, Version: phase6security.VersionV2, Revision: "command-hold-test"}
	profile.ProfileDigest = profile.Digest()
	document, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, document, 0600); err != nil {
		t.Fatal(err)
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount("certificate-controller")
	if err != nil {
		t.Fatal(err)
	}
	c := configDocument{Protocol: profileV2ConfigProtocol, SecurityProfilePath: profilePath, SecurityProfileDigest: profile.ProfileDigest,
		PeerCRLSourcesPath: filepath.Join(directory, "absent-sources.json"), PeerCRLSourcesDigest: "sha256:" + strings.Repeat("a", 64), LedgerPath: ledgerPath,
		MaximumActiveCertificates: 2, MaximumLedgerAgeSeconds: 3600, ReapIntervalSeconds: 1, VaultClientCertificatePEM: []byte("never consumed"), VaultServerName: "vault.invalid", OperationTimeoutSeconds: 1,
		ManagedVaultTLS: managedTLSConfig{PolicyID: "managed", ControllerSocket: "/run/self/request.sock", CertificateTTLSeconds: 569, RotateAfterSeconds: 300, OverlapSeconds: 30, CheckIntervalMilliseconds: 100, RevocationPollIntervalSeconds: 1, RevocationMaxStalenessSeconds: 10},
		Listeners:       []listenerDocument{{MaxConnections: 1}}, Policies: []certificatePolicy{{ID: "unread"}}}
	input, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var files []*os.File
	for i := 0; i < 4; i++ {
		f, err := os.CreateTemp(directory, "key-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		if _, err := f.Write(bytes.Repeat([]byte{byte(i + 1)}, 64)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestControllerV2RejectsBeforeReadingInheritedKeys$")
	command.Env = append(os.Environ(), "SANDBOX_RUNTIME_CONTROLLER_PREFLIGHT_CHILD=1")
	command.Stdin = bytes.NewReader(input)
	command.ExtraFiles = files
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("command child failed: %v: %s", err, output)
	}
	for i, f := range files {
		offset, err := f.Seek(0, io.SeekCurrent)
		if err != nil || offset != 0 {
			t.Fatalf("FD %d consumed: offset=%d err=%v", i+3, offset, err)
		}
	}
}
