//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const slice6OldClientTLSClass = "old_client_x509_unknown_authority"

var slice6TCPEndpointPattern = regexp.MustCompile(`(?:read|write) tcp ([0-9.]+):([0-9]+)->([0-9.]+):([0-9]+)`)

type slice6TLSNetworkEndpoint struct {
	NetworkID  string
	IPAddress  string
	EndpointID string
	IPAMConfig *struct{ IPv4Address string }
}

type slice6TLSContainerSnapshot struct {
	ID, Image, ImageRef, RunLabel, Error string
	Command                              []string
	StartedAt, FinishedAt                string
	Running, OOMKilled                   bool
	ExitCode, PID                        int
	Networks                             map[string]slice6TLSNetworkEndpoint
	Mounts                               []struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}
}

type slice6OldClientTLSInput struct {
	RunID, ServerID, ProbeID, NetworkID, ControllerIP, VaultIP string
	Attempt                                                    int
	CertificateDigest                                          string
	CertificateDirectory                                       string
	ExpectedProbeCommand                                       []string
	BeforeServer, AfterServer, Probe                           slice6TLSContainerSnapshot
	ClientOutput                                               []byte
	ServerLog                                                  []byte
}

// Only closed fields may be retained; raw Vault logs and CLI text are never
// retained in the diagnostic record.
type slice6OldClientTLSRecord struct {
	Protocol, RunID, Direction, ErrorClass                   string
	Attempt                                                  int
	ServerID, ProbeID, NetworkID, ServerProcessStartedAt     string
	CertificateDigest, SourceSocket, TargetSocket            string
	ProbeStartedAt, ProbeFinishedAt, LogAt, ApplicationLogAt string
	Decision                                                 string
}

func slice6ReadTLSPublicCertificateDigest(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("TLS public certificate path invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 32<<10 {
		return "", errors.New("TLS public certificate unavailable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("TLS public certificate unavailable")
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("TLS public certificate framing invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", errors.New("TLS public certificate invalid")
	}
	digest := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func slice6InspectTLSContainer(ctx context.Context, id string) (slice6TLSContainerSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return slice6TLSContainerSnapshot{}, errors.New("TLS Docker target invalid")
	}
	const format = `{"ID":{{json .Id}},"Image":{{json .Image}},"ImageRef":{{json .Config.Image}},"RunLabel":{{json (index .Config.Labels "io.github.shell-echo.sandbox-runtime.phase6-slice6-run")}},"Command":{{json .Config.Cmd}},"StartedAt":{{json .State.StartedAt}},"FinishedAt":{{json .State.FinishedAt}},"Running":{{json .State.Running}},"OOMKilled":{{json .State.OOMKilled}},"ExitCode":{{json .State.ExitCode}},"PID":{{json .State.Pid}},"Error":{{json .State.Error}},"Networks":{{json .NetworkSettings.Networks}},"Mounts":{{json .Mounts}}}`
	raw, commandErr, overflow := slice6DockerBounded(ctx, 16<<10, nil,
		"inspect", "--format", format, id)
	defer clear(raw)
	if commandErr != nil || overflow || ctx.Err() != nil || len(raw) < 2 {
		return slice6TLSContainerSnapshot{}, errors.New("TLS Docker identity unavailable")
	}
	var result slice6TLSContainerSnapshot
	if json.Unmarshal(raw, &result) != nil || result.ID != id {
		return slice6TLSContainerSnapshot{}, errors.New("TLS Docker identity malformed")
	}
	return result, nil
}

func slice6TCPEndpoints(raw []byte, sourceIP, targetIP string) (string, string, error) {
	if len(raw) < 1 || len(raw) > 4096 {
		return "", "", errors.New("TLS CLI endpoint unavailable")
	}
	matches := slice6TCPEndpointPattern.FindAllSubmatch(raw, -1)
	if len(matches) != 1 {
		return "", "", errors.New("TLS CLI endpoint not unique")
	}
	source := string(matches[0][1]) + ":" + string(matches[0][2])
	target := string(matches[0][3]) + ":" + string(matches[0][4])
	src, srcErr := netip.ParseAddrPort(source)
	dst, dstErr := netip.ParseAddrPort(target)
	if srcErr != nil || dstErr != nil || !src.Addr().Is4() || !dst.Addr().Is4() ||
		src.Addr().String() != sourceIP || dst.Addr().String() != targetIP || dst.Port() != 8200 {
		return "", "", errors.New("TLS CLI endpoint drifted")
	}
	return src.String(), dst.String(), nil
}

func slice6ParseTLSWindow(startRaw, finishRaw string) (time.Time, time.Time, error) {
	start, startErr := time.Parse(time.RFC3339Nano, startRaw)
	finish, finishErr := time.Parse(time.RFC3339Nano, finishRaw)
	if startErr != nil || finishErr != nil || start.IsZero() || !finish.After(start) {
		return time.Time{}, time.Time{}, errors.New("TLS probe clock window unavailable")
	}
	return start, finish, nil
}

func slice6ReadUniqueTLSHandshake(log []byte, sourceSocket string,
	start, finish time.Time) (time.Time, time.Time, error) {
	if len(log) < 2 || len(log) > 64<<10 || log[len(log)-1] != '\n' ||
		bytes.ContainsRune(log, '\x00') || bytes.ContainsRune(log, '\r') {
		return time.Time{}, time.Time{}, errors.New("TLS server log incomplete")
	}
	const denied = ": tls: failed to verify certificate: x509: certificate signed by unknown authority"
	needle := "http: TLS handshake error from " + sourceSocket
	var daemonTime, applicationTime time.Time
	matches := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(log), "\n"), "\n") {
		outer, message, ok := strings.Cut(line, " ")
		if !ok {
			return time.Time{}, time.Time{}, errors.New("TLS server log timestamp missing")
		}
		daemon, err := time.Parse(time.RFC3339Nano, outer)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("TLS server daemon timestamp invalid")
		}
		if !strings.Contains(message, "TLS handshake error from "+sourceSocket) {
			continue
		}
		matches++
		inner, event, ok := strings.Cut(message, " ")
		if !ok {
			return time.Time{}, time.Time{}, errors.New("TLS server application timestamp missing")
		}
		app, err := time.Parse(time.RFC3339Nano, inner)
		if err != nil || app.After(daemon) || app.Before(start) || app.After(finish) ||
			daemon.Before(start) || daemon.After(finish) || event != "[INFO]  "+needle+denied {
			return time.Time{}, time.Time{}, errors.New("TLS server rejection not attributable")
		}
		daemonTime, applicationTime = daemon, app
	}
	if matches != 1 {
		return time.Time{}, time.Time{}, errors.New("TLS server rejection not unique")
	}
	return daemonTime, applicationTime, nil
}

func slice6EvaluateOldClientTLS(input slice6OldClientTLSInput) (slice6OldClientTLSRecord, error) {
	record := slice6OldClientTLSRecord{Protocol: "sandbox-runtime.phase6-old-client-tls-correlation.v1",
		RunID: input.RunID, Direction: "old-client-denied", Attempt: input.Attempt,
		ServerID: input.ServerID, ProbeID: input.ProbeID, NetworkID: input.NetworkID,
		CertificateDigest: input.CertificateDigest, ErrorClass: slice6OldClientTLSClass,
		Decision: "rejected"}
	imageParts := strings.Split(slice6VaultTestImage, "@")
	if len(imageParts) != 2 || !guestRevokeFixtureDigestGate(imageParts[1]) {
		return record, errors.New("TLS pinned image identity invalid")
	}
	if len(input.RunID) != 32 || !lowerHexSlice6(input.RunID) ||
		len(input.ServerID) != 64 || !lowerHexSlice6(input.ServerID) ||
		len(input.ProbeID) != 64 || !lowerHexSlice6(input.ProbeID) ||
		len(input.NetworkID) != 64 || !lowerHexSlice6(input.NetworkID) ||
		input.Attempt < 0 || input.Attempt >= 3 ||
		!guestRevokeFixtureDigestGate(input.CertificateDigest) ||
		input.BeforeServer.ID != input.ServerID || input.AfterServer.ID != input.ServerID ||
		input.Probe.ID != input.ProbeID ||
		input.BeforeServer.RunLabel != input.RunID ||
		input.AfterServer.RunLabel != input.RunID || input.Probe.RunLabel != input.RunID ||
		input.BeforeServer.ImageRef != slice6VaultTestImage ||
		input.AfterServer.ImageRef != slice6VaultTestImage ||
		input.Probe.ImageRef != slice6VaultTestImage ||
		input.BeforeServer.Image != imageParts[1] ||
		input.AfterServer.Image != input.BeforeServer.Image ||
		input.Probe.Image != input.BeforeServer.Image ||
		!input.BeforeServer.Running || !input.AfterServer.Running ||
		input.BeforeServer.PID < 1 || input.AfterServer.PID != input.BeforeServer.PID ||
		input.BeforeServer.StartedAt != input.AfterServer.StartedAt ||
		input.BeforeServer.Error != "" || input.AfterServer.Error != "" ||
		input.Probe.Running || input.Probe.ExitCode != 1 || input.Probe.OOMKilled ||
		input.Probe.Error != "" ||
		!equalSlice6Strings(input.ExpectedProbeCommand,
			slice6OldClientTLSExpectedCommand(input.VaultIP,
				"server-ca.pem", "bootstrap-client.pem", "bootstrap-client-key.pem")) ||
		!equalSlice6Strings(input.Probe.Command, input.ExpectedProbeCommand) ||
		!slice6TLSProbeCertificateMount(input.Probe, input.CertificateDirectory) ||
		!slice6TLSNetworkMember(input.BeforeServer, input.NetworkID, input.VaultIP, false) ||
		!slice6TLSNetworkMember(input.AfterServer, input.NetworkID, input.VaultIP, false) ||
		!slice6TLSNetworkMember(input.Probe, input.NetworkID, input.ControllerIP, true) ||
		bytes.Contains(input.ClientOutput, []byte("Sealed          false")) {
		return record, errors.New("TLS exact run/process/network or command drift")
	}
	serverStarted, err := time.Parse(time.RFC3339Nano, input.BeforeServer.StartedAt)
	start, finish, windowErr := slice6ParseTLSWindow(input.Probe.StartedAt, input.Probe.FinishedAt)
	if err != nil || windowErr != nil || !serverStarted.Before(start) {
		return record, errors.New("TLS server/probe process window unavailable")
	}
	source, target, err := slice6TCPEndpoints(input.ClientOutput, input.ControllerIP, input.VaultIP)
	if err != nil {
		return record, err
	}
	daemon, app, err := slice6ReadUniqueTLSHandshake(input.ServerLog, source, start, finish)
	if err != nil {
		return record, err
	}
	record.ServerProcessStartedAt = input.BeforeServer.StartedAt
	record.SourceSocket, record.TargetSocket = source, target
	record.ProbeStartedAt, record.ProbeFinishedAt = input.Probe.StartedAt, input.Probe.FinishedAt
	record.LogAt, record.ApplicationLogAt = daemon.UTC().Format(time.RFC3339Nano), app.UTC().Format(time.RFC3339Nano)
	record.Decision = "attributable_server_rejection"
	return record, nil
}

func slice6TLSProbeCertificateMount(probe slice6TLSContainerSnapshot, directory string) bool {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return false
	}
	found := 0
	for _, mount := range probe.Mounts {
		if mount.Destination == "/probe" {
			if mount.Type != "bind" || mount.Source != directory || mount.RW {
				return false
			}
			found++
		}
	}
	return found == 1
}

func slice6TLSNetworkMember(snapshot slice6TLSContainerSnapshot, networkID, address string, exclusive bool) bool {
	if exclusive && len(snapshot.Networks) != 1 {
		return false
	}
	if len(snapshot.Networks) < 1 || networkID == "" || address == "" {
		return false
	}
	for _, endpoint := range snapshot.Networks {
		if endpoint.NetworkID != networkID {
			continue
		}
		if exclusive {
			return !snapshot.Running && endpoint.IPAddress == "" &&
				endpoint.EndpointID == "" && endpoint.IPAMConfig != nil &&
				endpoint.IPAMConfig.IPv4Address == address
		}
		return snapshot.Running && endpoint.IPAddress == address &&
			endpoint.EndpointID != ""
	}
	return false
}

func equalSlice6Strings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func slice6CaptureOldClientTLS(ctx context.Context, input slice6OldClientTLSInput,
	certificatePath string) (slice6OldClientTLSRecord, error) {
	if ctx == nil || ctx.Err() != nil {
		return slice6OldClientTLSRecord{}, errors.New("TLS diagnostic context unavailable")
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	beforeDigest, err := slice6ReadTLSPublicCertificateDigest(certificatePath)
	if err != nil || beforeDigest != input.CertificateDigest {
		return slice6OldClientTLSRecord{}, errors.New("TLS old client public certificate drifted")
	}
	input.Probe, err = slice6InspectTLSContainer(check, input.ProbeID)
	if err != nil {
		return slice6OldClientTLSRecord{}, err
	}
	input.AfterServer, err = slice6InspectTLSContainer(check, input.ServerID)
	if err != nil {
		return slice6OldClientTLSRecord{}, err
	}
	middleServer := input.AfterServer
	afterDigest, err := slice6ReadTLSPublicCertificateDigest(certificatePath)
	if err != nil || afterDigest != beforeDigest {
		return slice6OldClientTLSRecord{}, errors.New("TLS old client public certificate changed")
	}
	start, finish, err := slice6ParseTLSWindow(input.Probe.StartedAt, input.Probe.FinishedAt)
	if err != nil {
		return slice6OldClientTLSRecord{}, err
	}
	log, commandErr, overflow := slice6DockerBounded(check, 64<<10, nil,
		"logs", "--timestamps", "--since", start.UTC().Format(time.RFC3339Nano),
		"--until", finish.UTC().Format(time.RFC3339Nano), input.ServerID)
	defer clear(log)
	if commandErr != nil || overflow || check.Err() != nil {
		return slice6OldClientTLSRecord{}, errors.New("TLS server log unavailable or incomplete")
	}
	input.AfterServer, err = slice6InspectTLSContainer(check, input.ServerID)
	if err != nil || middleServer.PID != input.AfterServer.PID ||
		middleServer.StartedAt != input.AfterServer.StartedAt ||
		!middleServer.Running || !input.AfterServer.Running {
		return slice6OldClientTLSRecord{}, errors.New("TLS server process changed during log capture")
	}
	input.ServerLog = log
	return slice6EvaluateOldClientTLS(input)
}

func slice6OldClientTLSRecordDigest(record slice6OldClientTLSRecord) (string, string, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(raw)
	return string(raw), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func slice6OldClientTLSExpectedCommand(vaultIP, serverCA, clientCert, clientKey string) []string {
	return []string{"status", "-address=https://" + vaultIP + ":8200",
		"-ca-cert=/probe/" + serverCA, "-client-cert=/probe/" + clientCert,
		"-client-key=/probe/" + clientKey, "-tls-server-name=vault.sandbox-runtime.test"}
}

func slice6OldClientTLSReason(err error) string {
	if err == nil {
		return "attributable_server_rejection"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "diagnostic_timeout"
	}
	return "not_attributable"
}
