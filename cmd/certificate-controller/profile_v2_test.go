package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestControllerConfigRequiresCRLSourcesAndPolicyPurposes(t *testing.T) {
	for _, version := range []string{peerCRLConfigProtocol, profileV2ConfigProtocol} {
		c := configDocument{Protocol: version, PeerCRLSourcesPath: "/run/phase6/config/peer-crl-sources.json", PeerCRLSourcesDigest: "pinned"}
		if !validControllerConfig(c) {
			t.Fatal("known version rejected", version)
		}
		c.Protocol += "-unknown"
		if validControllerConfig(c) {
			t.Fatal("unknown version accepted")
		}
	}
	for _, version := range []string{peerCRLConfigProtocol, profileV2ConfigProtocol} {
		for _, c := range []configDocument{{Protocol: version}, {Protocol: version, PeerCRLSourcesPath: "relative", PeerCRLSourcesDigest: "pinned"}, {Protocol: version, PeerCRLSourcesPath: "/run/sources"}} {
			if validControllerConfig(c) {
				t.Fatal("missing source pin accepted")
			}
		}
	}
	for _, c := range []configDocument{{Protocol: "sandbox-runtime.certificate-controller-config.v3"},
		{Protocol: "sandbox-runtime.certificate-controller-config.v3", PeerCRLSourcesPath: "/run/sources", PeerCRLSourcesDigest: "pinned"}} {
		if validControllerConfig(c) {
			t.Fatal("retired controller configuration accepted")
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

func TestControllerRequiresCRLStateBeforePolicyAndConstruction(t *testing.T) {
	for _, c := range []configDocument{{Protocol: peerCRLConfigProtocol},
		{Protocol: "sandbox-runtime.certificate-controller-config.v3"}} {
		startup := controllerStartupProfile{v1: &phase6security.Profile{}}
		if err := startup.validatePolicies(c, nil); !errors.Is(err, workloadpki.ErrUnavailable) {
			t.Fatalf("absent CRL authority accepted for policies: %v", err)
		}
		if controller, err := startup.newController(c, workloadpki.ControllerConfig{}); controller != nil || !errors.Is(err, workloadpki.ErrUnavailable) {
			t.Fatalf("absent CRL authority accepted for construction: %v", err)
		}
	}
}

// This executes the real command entry in a separate process. Sharing the
// inherited open-file descriptions lets the parent detect any key FD read.
// The draft is intentionally not release evidence or a complete live Profile.
func TestControllerRejectsUnsafeStartupBeforeReadingInheritedKeys(t *testing.T) {
	if expected := os.Getenv("SANDBOX_RUNTIME_CONTROLLER_PREFLIGHT_CHILD"); expected != "" {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "stage "+expected+":") {
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
	for _, test := range []struct {
		name, stage string
		change      func(*configDocument)
	}{
		{"current-profile-hold", "security-profile", func(*configDocument) {}},
		{"existing-crl-profile", "security-profile", func(c *configDocument) { c.Protocol = peerCRLConfigProtocol }},
		{"retired-with-sources", "config-validate", func(c *configDocument) { c.Protocol = "sandbox-runtime.certificate-controller-config.v3" }},
		{"retired-without-sources", "config-validate", func(c *configDocument) {
			c.Protocol = "sandbox-runtime.certificate-controller-config.v3"
			c.PeerCRLSourcesPath = ""
			c.PeerCRLSourcesDigest = ""
		}},
		{"missing-source-path", "config-validate", func(c *configDocument) { c.PeerCRLSourcesPath = "" }},
		{"relative-source-path", "config-validate", func(c *configDocument) { c.PeerCRLSourcesPath = "relative" }},
		{"missing-source-digest", "config-validate", func(c *configDocument) { c.PeerCRLSourcesDigest = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := c
			test.change(&candidate)
			input, err := json.Marshal(candidate)
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
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestControllerRejectsUnsafeStartupBeforeReadingInheritedKeys$")
			command.Env = append(os.Environ(), "SANDBOX_RUNTIME_CONTROLLER_PREFLIGHT_CHILD="+test.stage)
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
		})
	}
}
