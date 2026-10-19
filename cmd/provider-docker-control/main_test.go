package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontroltransport"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestControlStatusConfigRejectsMutationAndNoncanonicalInput(t *testing.T) {
	c := configDocument{Protocol: controlConfigProtocol, OperationTimeoutSeconds: 5}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeConfig(data); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{append(bytes.Clone(data), '\n'), append([]byte(`{"action":"create",`), data[1:]...), append([]byte(`{"protocol":"`+controlConfigProtocol+`",`), data[1:]...), bytes.Repeat([]byte(" "), (256<<10)+1)} {
		if _, err := decodeConfig(body); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}

func TestControlMutationConfigRequiresExplicitBoundedSourceInputs(t *testing.T) {
	i := &codingcontroltransport.CodingMutationInputs{Documents: phase6security.ImageDescriptorDocuments{Index: []byte("index"), Manifest: []byte("manifest"), Config: []byte("config")}, SeccompPolicy: []byte("policy")}
	c := configDocument{Protocol: controlMutationConfigProtocol, OperationTimeoutSeconds: 5, MutationInputs: i}
	data, _ := json.Marshal(c)
	if _, err := decodeConfig(data); err != nil {
		t.Fatal("explicit candidate config rejected", err)
	}
	c.Protocol = controlConfigProtocol
	data, _ = json.Marshal(c)
	if _, err := decodeConfig(data); err == nil {
		t.Fatal("legacy status mode gained mutations")
	}
	c.Protocol, c.MutationInputs = controlMutationConfigProtocol, nil
	data, _ = json.Marshal(c)
	if _, err := decodeConfig(data); err == nil {
		t.Fatal("mutation source omitted")
	}
	c.MutationInputs = i
	i.SeccompPolicy = bytes.Repeat([]byte("x"), (64<<10)+1)
	data, _ = json.Marshal(c)
	if _, err := decodeConfig(data); err == nil {
		t.Fatal("unbounded policy accepted")
	}
}
func TestControlStatusRetainsV2HoldBeforeLedgerOrSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	profile, err := json.Marshal(phase6security.ProfileV2{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, profile, 0600); err != nil {
		t.Fatal(err)
	}
	c := configDocument{Protocol: controlConfigProtocol, SecurityProfilePath: path, OperationTimeoutSeconds: 5, AgentSocket: filepath.Join(dir, "absent.sock")}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if run(context.Background(), bytes.NewReader(data)) == nil {
		t.Fatal("held profile admitted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected preflight changed files")
	}
}

func TestBootstrapProtocolHasNoLegacyOrMutationFallback(t *testing.T) {
	c := configDocument{Protocol: controlBootstrapConfigProtocol, OperationTimeoutSeconds: 5, SecurityProfilePath: "/tmp/profile.json"}
	data, _ := json.Marshal(c)
	if _, e := decodeConfig(data); e != nil {
		t.Fatal(e)
	}
	if run(context.Background(), bytes.NewReader(data)) == nil {
		t.Fatal("non-fixed config path")
	}
	c.MutationInputs = &codingcontroltransport.CodingMutationInputs{}
	data, _ = json.Marshal(c)
	if _, e := decodeConfig(data); e == nil {
		t.Fatal("bootstrap gained mutation dispatch")
	}
}

func TestControlBootstrapCommandFixture(t *testing.T) {
	out := os.Getenv("CONTROL_BOOTSTRAP_COMMAND_FIXTURE")
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
	c := configDocument{Protocol: controlBootstrapConfigProtocol, SecurityProfilePath: phase6security.Slice6PrivateConfigDirectory + "/" + phase6security.Slice6ProfileConfigFile, SecurityProfileDigest: p.ProfileDigest, EnvironmentDigest: p.EnvironmentDigest, PrincipalProfileDigest: p.PrincipalProfileDigest, OperationTimeoutSeconds: 5}
	if p.DockerControl.OperatorBootstrap != nil && phase6security.ControlObservesSource(p.DockerControl.OperatorBootstrap.Target) {
		c.Protocol = controlSourceConfigProtocol
	}
	if p.DockerControl.OperatorBootstrap != nil && p.DockerControl.OperatorBootstrap.Target == phase6security.ControlTrustTarget {
		c.Protocol = controlTrustConfigProtocol
	}
	if p.DockerControl.OperatorBootstrap != nil && p.DockerControl.OperatorBootstrap.Target == phase6security.ControlDeliveryTarget {
		c.Protocol = controlDeliveryConfigProtocol
	}
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
