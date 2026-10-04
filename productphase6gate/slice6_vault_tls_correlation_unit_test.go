//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// The server-line shape was observed from the pinned, uninitialized Vault
// image in a no-issuer diagnostic. The paired client EPIPE is a synthetic
// fixture; it does not reclassify the failed formal E run.
func slice6OldClientTLSFixture() slice6OldClientTLSInput {
	runID := strings.Repeat("1", 32)
	serverID := strings.Repeat("2", 64)
	probeID := strings.Repeat("3", 64)
	networkID := strings.Repeat("4", 64)
	imageID := strings.Split(slice6VaultTestImage, "@")[1]
	server := slice6TLSContainerSnapshot{ID: serverID, Image: imageID,
		ImageRef: slice6VaultTestImage, RunLabel: runID,
		StartedAt: "2026-10-04T16:50:00Z", Running: true, PID: 741,
		Networks: map[string]slice6TLSNetworkEndpoint{
			"controller": {NetworkID: networkID, IPAddress: "172.31.25.3",
				EndpointID: strings.Repeat("5", 64)}}}
	probe := slice6TLSContainerSnapshot{ID: probeID, Image: imageID,
		ImageRef: slice6VaultTestImage, RunLabel: runID,
		StartedAt: "2026-10-04T16:51:23Z", FinishedAt: "2026-10-04T16:51:24Z",
		ExitCode: 1, Command: slice6OldClientTLSExpectedCommand("172.31.25.3",
			"server-ca.pem", "bootstrap-client.pem", "bootstrap-client-key.pem"),
		Networks: map[string]slice6TLSNetworkEndpoint{
			"controller": {NetworkID: networkID, IPAMConfig: &struct{ IPv4Address string }{
				IPv4Address: "172.31.25.2"}}},
		Mounts: []struct {
			Type, Source, Destination string
			RW                        bool
		}{{Type: "bind", Source: "/private/certificates", Destination: "/probe"}}}
	return slice6OldClientTLSInput{RunID: runID, ServerID: serverID,
		ProbeID: probeID, NetworkID: networkID, ControllerIP: "172.31.25.2",
		VaultIP: "172.31.25.3", Attempt: 0,
		CertificateDigest:    "sha256:" + strings.Repeat("a", 64),
		CertificateDirectory: "/private/certificates",
		ExpectedProbeCommand: probe.Command,
		BeforeServer:         server, AfterServer: server, Probe: probe,
		ClientOutput: []byte("Error checking seal status: write tcp 172.31.25.2:50984->172.31.25.3:8200: write: broken pipe"),
		ServerLog:    []byte("2026-10-04T16:51:23.961Z 2026-10-04T16:51:23.960Z [INFO]  http: TLS handshake error from 172.31.25.2:50984: tls: failed to verify certificate: x509: certificate signed by unknown authority\n")}
}

func TestSlice6OldClientTLSCorrelationNoIssuer(t *testing.T) {
	input := slice6OldClientTLSFixture()
	record, err := slice6EvaluateOldClientTLS(input)
	if err != nil || record.Decision != "attributable_server_rejection" ||
		record.Direction != "old-client-denied" ||
		record.SourceSocket != "172.31.25.2:50984" {
		t.Fatalf("exact old-client server rejection lost: %+v %v", record, err)
	}
	if raw, digest, err := slice6OldClientTLSRecordDigest(record); err != nil ||
		!strings.Contains(raw, "old_client_x509_unknown_authority") ||
		!guestRevokeFixtureDigestGate(digest) {
		t.Fatal("closed diagnostic record lacks reproducible canonical digest")
	}
}

func TestSlice6OldClientTLSCorrelationRejectsDriftNoIssuer(t *testing.T) {
	tests := []struct {
		name   string
		change func(*slice6OldClientTLSInput)
	}{
		{"wrong run", func(v *slice6OldClientTLSInput) { v.Probe.RunLabel = strings.Repeat("9", 32) }},
		{"wrong server", func(v *slice6OldClientTLSInput) { v.BeforeServer.ID = strings.Repeat("9", 64) }},
		{"wrong probe", func(v *slice6OldClientTLSInput) { v.Probe.ID = strings.Repeat("9", 64) }},
		{"wrong network", func(v *slice6OldClientTLSInput) { v.NetworkID = strings.Repeat("9", 64) }},
		{"wrong source IP", func(v *slice6OldClientTLSInput) {
			v.ClientOutput = []byte("write tcp 172.31.25.9:50984->172.31.25.3:8200: write: broken pipe")
		}},
		{"wrong source port", func(v *slice6OldClientTLSInput) {
			v.ClientOutput = []byte("write tcp 172.31.25.2:50985->172.31.25.3:8200: write: broken pipe")
		}},
		{"correct IPAM wrong CLI source", func(v *slice6OldClientTLSInput) {
			v.ClientOutput = []byte("write tcp 172.31.25.9:50984->172.31.25.3:8200: write: broken pipe")
		}},
		{"correct CLI wrong IPAM", func(v *slice6OldClientTLSInput) {
			endpoint := v.Probe.Networks["controller"]
			endpoint.IPAMConfig = &struct{ IPv4Address string }{IPv4Address: "172.31.25.9"}
			v.Probe.Networks = map[string]slice6TLSNetworkEndpoint{"controller": endpoint}
		}},
		{"stopped probe claims live endpoint", func(v *slice6OldClientTLSInput) {
			endpoint := v.Probe.Networks["controller"]
			endpoint.IPAddress = "172.31.25.2"
			v.Probe.Networks = map[string]slice6TLSNetworkEndpoint{"controller": endpoint}
		}},
		{"server actual endpoint missing", func(v *slice6OldClientTLSInput) {
			endpoint := v.AfterServer.Networks["controller"]
			endpoint.IPAddress = ""
			v.AfterServer.Networks = map[string]slice6TLSNetworkEndpoint{"controller": endpoint}
		}},
		{"wrong target IP", func(v *slice6OldClientTLSInput) {
			v.ClientOutput = []byte("write tcp 172.31.25.2:50984->172.31.25.9:8200: write: broken pipe")
		}},
		{"wrong target port", func(v *slice6OldClientTLSInput) {
			v.ClientOutput = []byte("write tcp 172.31.25.2:50984->172.31.25.3:8201: write: broken pipe")
		}},
		{"bare disconnect", func(v *slice6OldClientTLSInput) { v.ClientOutput = []byte("EOF") }},
		{"duplicate endpoint", func(v *slice6OldClientTLSInput) {
			v.ClientOutput = append(bytes.Clone(v.ClientOutput), v.ClientOutput...)
		}},
		{"server restart", func(v *slice6OldClientTLSInput) { v.AfterServer.PID++ }},
		{"server start changed", func(v *slice6OldClientTLSInput) {
			v.AfterServer.StartedAt = "2026-10-04T16:50:01Z"
		}},
		{"wrong image", func(v *slice6OldClientTLSInput) { v.Probe.Image = "sha256:" + strings.Repeat("9", 64) }},
		{"wrong cert direction", func(v *slice6OldClientTLSInput) {
			v.ExpectedProbeCommand = slice6OldClientTLSExpectedCommand("172.31.25.3",
				"bootstrap-server-ca.pem", "client.pem", "client-key.pem")
			v.Probe.Command = v.ExpectedProbeCommand
		}},
		{"wrong public cert", func(v *slice6OldClientTLSInput) { v.CertificateDigest = "" }},
		{"wrong certificate mount", func(v *slice6OldClientTLSInput) {
			v.CertificateDirectory = "/private/other"
		}},
		{"probe killed", func(v *slice6OldClientTLSInput) { v.Probe.ExitCode = 137 }},
		{"probe OOM", func(v *slice6OldClientTLSInput) { v.Probe.OOMKilled = true }},
		{"CLI success", func(v *slice6OldClientTLSInput) {
			v.ClientOutput = append(v.ClientOutput, []byte(" Sealed          false")...)
		}},
		{"missing start", func(v *slice6OldClientTLSInput) { v.Probe.StartedAt = "" }},
		{"inverted window", func(v *slice6OldClientTLSInput) {
			v.Probe.FinishedAt = "2026-10-04T16:51:22Z"
		}},
		{"expired log", func(v *slice6OldClientTLSInput) {
			v.Probe.FinishedAt = "2026-10-04T16:51:23.500Z"
		}},
		{"boundary old log", func(v *slice6OldClientTLSInput) {
			v.Probe.StartedAt = "2026-10-04T16:51:23.961000001Z"
		}},
		{"no x509", func(v *slice6OldClientTLSInput) {
			v.ServerLog = bytes.ReplaceAll(v.ServerLog,
				[]byte("x509: certificate signed by unknown authority"), []byte("connection reset by peer"))
		}},
		{"wrong log direction", func(v *slice6OldClientTLSInput) {
			v.ServerLog = bytes.ReplaceAll(v.ServerLog,
				[]byte("failed to verify certificate"), []byte("remote error: tls: bad certificate"))
		}},
		{"duplicate log", func(v *slice6OldClientTLSInput) {
			v.ServerLog = append(bytes.Clone(v.ServerLog), v.ServerLog...)
		}},
		{"truncated log", func(v *slice6OldClientTLSInput) {
			v.ServerLog = bytes.TrimSuffix(v.ServerLog, []byte("\n"))
		}},
		{"overflow log", func(v *slice6OldClientTLSInput) {
			v.ServerLog = bytes.Repeat([]byte("2026-10-04T16:51:23Z noise\n"), 2500)
		}},
		{"missing daemon time", func(v *slice6OldClientTLSInput) {
			v.ServerLog = bytes.Replace(v.ServerLog, []byte("2026-10-04T16:51:23.961Z "), nil, 1)
		}},
		{"missing application time", func(v *slice6OldClientTLSInput) {
			v.ServerLog = bytes.Replace(v.ServerLog, []byte("2026-10-04T16:51:23.960Z "), nil, 1)
		}},
		{"application after daemon", func(v *slice6OldClientTLSInput) {
			v.ServerLog = bytes.Replace(v.ServerLog, []byte("2026-10-04T16:51:23.960Z"),
				[]byte("2026-10-04T16:51:23.962Z"), 1)
		}},
		{"same peer conflicting log", func(v *slice6OldClientTLSInput) {
			v.ServerLog = append(v.ServerLog,
				[]byte("2026-10-04T16:51:23.970Z 2026-10-04T16:51:23.969Z [INFO]  http: TLS handshake error from 172.31.25.2:50984: remote error: tls: bad certificate\n")...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := slice6OldClientTLSFixture()
			test.change(&input)
			if record, err := slice6EvaluateOldClientTLS(input); err == nil ||
				record.Decision == "attributable_server_rejection" {
				t.Fatalf("drift accepted: %+v %v", record, err)
			}
		})
	}
}

func TestSlice6OldClientTLSCanceledCaptureNoIssuer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := slice6CaptureOldClientTLS(ctx, slice6OldClientTLSFixture(), "/not/a/certificate"); err == nil {
		t.Fatal("canceled diagnostic reached Docker or accepted")
	}
}

// Replays one actual pinned, uninitialized Vault server/probe pair. The
// server, probe and internal network are operator-owned no-issuer diagnostic
// resources supplied outside this test; the test only reads exact identities
// and bounded logs. A post-probe snapshot here tests the parser/capture path,
// not the formal E runner's independent pre-probe process freeze.
func TestSlice6OldClientTLSActualNoIssuerReplay(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_NOISSUER_REPLAY") != "1" {
		t.Skip("set exact no-issuer Vault server/probe identities for bounded replay")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	serverID := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_SERVER_ID")
	before, err := slice6InspectTLSContainer(ctx, serverID)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_CERT_DIR")
	certDigest, err := slice6ReadTLSPublicCertificateDigest(
		directory + "/bootstrap-client.pem")
	if err != nil {
		t.Fatal(err)
	}
	vaultIP := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_VAULT_IP")
	record, err := slice6CaptureOldClientTLS(ctx, slice6OldClientTLSInput{
		RunID:        os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_RUN_ID"),
		ServerID:     serverID,
		ProbeID:      os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_PROBE_ID"),
		NetworkID:    os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_NETWORK_ID"),
		ControllerIP: os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_CONTROLLER_IP"),
		VaultIP:      vaultIP, CertificateDigest: certDigest,
		CertificateDirectory: directory,
		ExpectedProbeCommand: slice6OldClientTLSExpectedCommand(vaultIP,
			"server-ca.pem", "bootstrap-client.pem", "bootstrap-client-key.pem"),
		BeforeServer: before,
		ClientOutput: []byte(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TLS_CLIENT_OUTPUT")),
	}, directory+"/bootstrap-client.pem")
	if err != nil || record.Decision != "attributable_server_rejection" {
		t.Fatalf("actual no-issuer pinned Vault correlation unavailable: %v", err)
	}
	t.Logf("actual no-issuer pinned Vault CLI/server pair correlation passed: run=%s probe=%s socket=%s", record.RunID, record.ProbeID, record.SourceSocket)
}
