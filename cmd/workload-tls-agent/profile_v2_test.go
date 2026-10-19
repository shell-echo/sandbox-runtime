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

func TestAgentConfigVersionsKeepPurposeAndSourcePins(t *testing.T) {
	for _, version := range []string{peerCRLConfigProtocol, postgresConfigProtocol, profileV2ConfigProtocol, postgresV2ConfigProtocol} {
		c := configDocument{Protocol: version, PeerCRLSourcesPath: "/run/phase6/config/peer-crl-sources.json", PeerCRLSourcesDigest: "pinned"}
		pg := version == postgresConfigProtocol || version == postgresV2ConfigProtocol
		if pg {
			c.Purpose = workloadpki.PostgresClientPurpose
			c.Postgres = &postgresClientConfig{}
		}
		if !validConfigVersion(c) {
			t.Fatal("known version rejected", version)
		}
		for _, change := range []func(*configDocument){
			func(c *configDocument) { c.Protocol += "-unknown" },
			func(c *configDocument) { c.PeerCRLSourcesDigest = "" },
			func(c *configDocument) { c.PeerCRLSourcesPath = "relative" },
			func(c *configDocument) { c.Purpose = "unknown" },
			func(c *configDocument) {
				if pg {
					c.Postgres = nil
				} else {
					c.Postgres = &postgresClientConfig{}
				}
			},
			func(c *configDocument) {
				if pg {
					c.Purpose = ""
					c.Postgres = nil
				} else {
					c.Purpose = workloadpki.PostgresClientPurpose
					c.Postgres = &postgresClientConfig{}
				}
			},
		} {
			copy := c
			change(&copy)
			if validConfigVersion(copy) {
				t.Fatal("version/purpose/source drift accepted", version)
			}
		}
	}
	if !validConfigVersion(configDocument{Protocol: configProtocol}) {
		t.Fatal("legacy v2 rejected")
	}
	if validConfigVersion(configDocument{Protocol: configProtocol, PeerCRLSourcesPath: "/run/sources", PeerCRLSourcesDigest: "pinned"}) {
		t.Fatal("legacy v2 silently enabled sources")
	}
}

func TestAgentV2RejectsBeforeReadingInheritedKey(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_AGENT_PREFLIGHT_CHILD") == "1" {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "stage security-profile-binding:") {
			t.Fatalf("unexpected command rejection: %v", err)
		}
		return
	}
	for _, version := range []string{profileV2ConfigProtocol, postgresV2ConfigProtocol} {
		t.Run(version, func(t *testing.T) {
			directory := t.TempDir()
			profile := phase6security.ProfileV2{Protocol: phase6security.ProtocolIDV2, Version: phase6security.VersionV2, Revision: "command-hold-test"}
			profile.ProfileDigest = profile.Digest()
			data, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			profilePath := filepath.Join(directory, "profile.json")
			if err := os.WriteFile(profilePath, data, 0600); err != nil {
				t.Fatal(err)
			}
			c := configDocument{Protocol: version, SecurityProfilePath: profilePath, SecurityProfileDigest: profile.ProfileDigest,
				PeerCRLSourcesPath: filepath.Join(directory, "absent-sources.json"), PeerCRLSourcesDigest: "sha256:" + strings.Repeat("a", 64),
				MaxTTLSeconds: 600, CertificateTTLSeconds: 569, RotateAfterSeconds: 300, OverlapSeconds: 30, CheckIntervalMilliseconds: 100, RevocationPollIntervalSeconds: 1, RevocationMaxStalenessSeconds: 10,
				OperationTimeoutSeconds: 1, MaxConnections: 1, ReplayCapacity: 16, AgentUID: 20001, AgentGID: 30001, ExpectedRoleUID: 20002, ExpectedRoleGID: 30002, SignerSocketUID: 20001, SignerSocketGID: 30002}
			if version == postgresV2ConfigProtocol {
				c.Purpose = workloadpki.PostgresClientPurpose
				c.Postgres = &postgresClientConfig{}
			}
			input, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.CreateTemp(directory, "key-")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.Write(bytes.Repeat([]byte{1}, 64)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAgentV2RejectsBeforeReadingInheritedKey$")
			command.Env = append(os.Environ(), "SANDBOX_RUNTIME_AGENT_PREFLIGHT_CHILD=1")
			command.Stdin = bytes.NewReader(input)
			command.ExtraFiles = []*os.File{f}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("command child failed: %v: %s", err, output)
			}
			offset, err := f.Seek(0, io.SeekCurrent)
			if err != nil || offset != 0 {
				t.Fatalf("FD 3 consumed: offset=%d err=%v", offset, err)
			}
		})
	}
}

func TestAgentControlBootstrapCommandFixture(t *testing.T) {
	out := os.Getenv("TLS_BOOTSTRAP_COMMAND_FIXTURE")
	if out == "" {
		t.Skip("explicit operator fixture")
	}
	b, e := os.ReadFile(os.Getenv("CONTROL_BOOTSTRAP_PROFILE"))
	if e != nil {
		t.Fatal(e)
	}
	var p phase6security.ProfileV2
	if json.Unmarshal(b, &p) != nil {
		t.Fatal("fixture")
	}
	var a phase6security.TLSAgentBinding
	for _, v := range p.TLSAgentBindings {
		if v.SubjectDeployment == "provider-docker-control" {
			a = v
		}
	}
	c := configDocument{Protocol: profileV2ConfigProtocol, SecurityProfilePath: "/run/phase6/config/profile.json", SecurityProfileDigest: p.ProfileDigest, PeerCRLSourcesPath: "/run/phase6/config/peer-crl-sources.json", PeerCRLSourcesDigest: "sha256:" + strings.Repeat("a", 64), MaxTTLSeconds: 600, CertificateTTLSeconds: 569, RotateAfterSeconds: 300, OverlapSeconds: 30, CheckIntervalMilliseconds: 100, RevocationPollIntervalSeconds: 1, RevocationMaxStalenessSeconds: 10, OperationTimeoutSeconds: 1, MaxConnections: 1, ReplayCapacity: 16, AgentUID: a.AgentUID, AgentGID: a.AgentGID, ExpectedRoleUID: a.SubjectUID, ExpectedRoleGID: a.SubjectGID, SignerSocketUID: a.AgentUID, SignerSocketGID: a.SubjectGID}
	b, e = json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		t.Fatal(e)
	}
}
