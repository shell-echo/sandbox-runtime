//go:build phase5desktopgate

package productphase5gate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/rtp"
	"github.com/shell-echo/sandbox-runtime/internal/productphase5evidence"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopgateway "github.com/shell-echo/sandbox-runtime/provider/desktop/gateway"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

type desktopSnapshot struct {
	Digest      string `json:"digest"`
	SizeBytes   int64  `json:"size_bytes"`
	X           int    `json:"x"`
	Y           int    `json:"y"`
	ImageDigest string `json:"image_digest"`
}

func runDesktopNode(config nodeConfig) error {
	if err := startDesktopRuntime(config.DesktopContainer); err != nil {
		return err
	}
	defer removeDesktopRuntime(config.DesktopContainer)
	resolver := &networkDesktopResolver{origin: "http://" + config.DesktopProviderAddress, client: &http.Client{Timeout: time.Second}, gateKey: config.GateKey, container: config.DesktopContainer}
	handler, err := desktopgateway.New(desktopgateway.Options{
		Resolver: resolver, Media: &desktopRuntimeMedia{container: config.DesktopContainer},
		PeerAuthorizer: desktopgateway.PeerAuthorizerFunc(func(_ context.Context, state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != "phase5-gateway" {
				return providerdesktop.ErrDesktopUnsupported
			}
			return nil
		}),
		MaxSessions: 4, MaxSessionsPerDesktop: 1, AuthorityPollInterval: 25 * time.Millisecond, OperationTimeout: 2 * time.Second,
	})
	if err != nil {
		return err
	}
	privateMux := http.NewServeMux()
	privateMux.Handle("/", handler)
	privateMux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || brokerProbe(config.DesktopContainer) != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	controlMux := http.NewServeMux()
	controlMux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || brokerProbe(config.DesktopContainer) != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	controlMux.HandleFunc("/gate/display", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("X-Gate-Key") != config.GateKey {
			http.NotFound(writer, request)
			return
		}
		snapshot, snapshotErr := captureDesktop(config.DesktopContainer)
		if snapshotErr != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusOK, snapshot)
	})
	tlsConfig, err := serverTLS(config.DesktopCertificate, config.DesktopKey, config.CACertificate, true)
	if err != nil {
		return err
	}
	return serveDesktopPair(config.DesktopPrivateAddress, privateMux, tlsConfig, config.DesktopControlAddress, controlMux)
}

func startDesktopRuntime(container string) error {
	if container == "" {
		return errors.New("Desktop container name is empty")
	}
	_ = exec.Command("docker", "rm", "-f", container).Run()
	command := exec.Command("docker", "run", "-d", "--name", container,
		"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=512m", "--cpus=1", "--network=none",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--tmpfs", "/workspace:rw,nosuid,nodev,size=64m", productphase5evidence.DesktopImage)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("start locked Desktop runtime: %w: %s", err, output)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if brokerProbe(container) == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	removeDesktopRuntime(container)
	return errors.New("locked Desktop broker did not become ready")
}

func removeDesktopRuntime(container string) {
	if container != "" {
		_ = exec.Command("docker", "rm", "-f", container).Run()
	}
}

func brokerProbe(container string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "exec", container, "/usr/local/libexec/sandbox-runtime/desktop-broker", "probe").Run()
}

func captureDesktop(container string) (desktopSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "exec", container, "sh", "-lc", `DISPLAY=:99 xwd -root -silent -out /tmp/phase5-root.xwd && wc -c < /tmp/phase5-root.xwd && sha256sum /tmp/phase5-root.xwd && DISPLAY=:99 xdotool getmouselocation --shell`)
	output, err := command.Output()
	if err != nil {
		return desktopSnapshot{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 6 {
		return desktopSnapshot{}, errors.New("invalid Desktop capture output")
	}
	size, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	fields := strings.Fields(lines[1])
	if err != nil || size < 1024 || len(fields) < 1 || len(fields[0]) != 64 {
		return desktopSnapshot{}, errors.New("invalid Desktop capture")
	}
	values := make(map[string]int)
	for _, line := range lines[2:] {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value, parseErr := strconv.Atoi(parts[1])
		if parseErr == nil {
			values[parts[0]] = value
		}
	}
	return desktopSnapshot{Digest: "sha256:" + fields[0], SizeBytes: size, X: values["X"], Y: values["Y"], ImageDigest: productphase5evidence.DesktopImageDigest}, nil
}

type networkDesktopResolver struct {
	origin, gateKey, container string
	client                     *http.Client
}

func (r *networkDesktopResolver) Resolve(ctx context.Context, reference string) (desktopreference.Endpoint, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.origin+"/gate/desktop/resolve?reference="+url.QueryEscape(reference), nil)
	if err != nil {
		return desktopreference.Endpoint{}, desktopreference.ErrUnavailable
	}
	request.Header.Set("X-Gate-Key", r.gateKey)
	response, err := r.client.Do(request)
	if err != nil {
		return desktopreference.Endpoint{}, desktopreference.ErrUnavailable
	}
	defer response.Body.Close()
	var resolution privateDesktopResolution
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<16))
	decoder.DisallowUnknownFields()
	if response.StatusCode != http.StatusOK || decoder.Decode(&resolution) != nil || resolution.Reference != reference || resolution.Generation < 1 || !resolution.ExpiresAt.After(time.Now().UTC()) {
		return desktopreference.Endpoint{}, desktopreference.ErrRevoked
	}
	return desktopreference.Endpoint{Reference: reference, SandboxID: resolution.SandboxID, DesktopSessionID: resolution.SessionID,
		CapabilityProfileID: providerdesktop.CapabilityProfileID, ConnectionGeneration: resolution.Generation, ExpiresAt: resolution.ExpiresAt,
		Attach: func(attachCtx context.Context) (providerdesktop.Attachment, error) {
			if err := brokerProbe(r.container); err != nil || attachCtx.Err() != nil {
				return providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
			}
			return providerdesktop.Attachment{DesktopSessionID: resolution.SessionID, ConnectionGeneration: resolution.Generation,
				MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID,
				DisplayReference: "ref:desktop-display:primary", Width: 1280, Height: 720, Depth: 24,
				PrivateInputModes: []string{"keyboard", "pointer"}, AttachedAt: time.Now().UTC()}, nil
		}}, nil
}

type desktopRuntimeMedia struct{ container string }

func (m *desktopRuntimeMedia) Open(ctx context.Context, _ desktopreference.Endpoint, _ providerdesktop.Attachment, _ desktopgateway.MediaPolicy) (desktopgateway.Session, error) {
	if ctx.Err() != nil || brokerProbe(m.container) != nil {
		return nil, providerdesktop.ErrDesktopNotFound
	}
	return &desktopRuntimeSession{container: m.container, stop: make(chan struct{})}, nil
}

type desktopRuntimeSession struct {
	container string
	stop      chan struct{}
	closeOnce sync.Once
	sequence  atomic.Uint32
	timestamp atomic.Uint32
}

func (s *desktopRuntimeSession) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	timer := time.NewTimer(35 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.stop:
		return nil, io.EOF
	case <-timer.C:
	}
	packet := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: uint16(s.sequence.Add(1)), Timestamp: s.timestamp.Add(3000), SSRC: 0x50354731, Marker: true}, Payload: []byte{0x10, 0x00, 0x01}}
	return packet.Marshal()
}

func (s *desktopRuntimeSession) ReadAudioRTP(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.stop:
		return nil, io.EOF
	}
}

func (s *desktopRuntimeSession) HandleInput(ctx context.Context, input desktopgateway.Input) (desktopgateway.InputResult, error) {
	var args []string
	switch input.Kind {
	case "pointer":
		switch input.Event {
		case "move":
			args = []string{"mousemove", "--sync", strconv.Itoa(input.X), strconv.Itoa(input.Y)}
		case "down":
			args = []string{"mousedown", strconv.Itoa(input.Button + 1)}
		case "up":
			args = []string{"mouseup", strconv.Itoa(input.Button + 1)}
		case "wheel":
			button := "4"
			if input.DeltaY > 0 {
				button = "5"
			}
			args = []string{"click", button}
		}
	case "keyboard":
		method := "keydown"
		if input.Event == "up" {
			method = "keyup"
		}
		args = []string{method, input.Key}
	default:
		return desktopgateway.InputResult{}, providerdesktop.ErrDesktopUnsupported
	}
	commandArgs := append([]string{"exec", "-e", "DISPLAY=:99", s.container, "xdotool"}, args...)
	command := exec.CommandContext(ctx, "docker", commandArgs...)
	if output, err := command.CombinedOutput(); err != nil {
		return desktopgateway.InputResult{}, fmt.Errorf("Desktop input failed: %w: %s", err, output)
	}
	return desktopgateway.InputResult{}, nil
}

func (*desktopRuntimeSession) UpdateStream(context.Context, desktopgateway.DisplayPolicy, string) error {
	return nil
}
func (*desktopRuntimeSession) Resynchronize(context.Context) error   { return nil }
func (*desktopRuntimeSession) RequestKeyframe(context.Context) error { return nil }
func (s *desktopRuntimeSession) Close() error {
	s.closeOnce.Do(func() { close(s.stop) })
	return nil
}

func serveDesktopPair(privateAddress string, private http.Handler, tlsConfig *tls.Config, controlAddress string, control http.Handler) error {
	privateListener, err := net.Listen("tcp", privateAddress)
	if err != nil {
		return err
	}
	defer privateListener.Close()
	privateListener = tls.NewListener(privateListener, tlsConfig)
	controlListener, err := net.Listen("tcp", controlAddress)
	if err != nil {
		return err
	}
	defer controlListener.Close()
	servers := []*http.Server{{Handler: private, ReadHeaderTimeout: 2 * time.Second}, {Handler: control, ReadHeaderTimeout: 2 * time.Second}}
	done := make(chan error, 2)
	go func() { done <- servers[0].Serve(privateListener) }()
	go func() { done <- servers[1].Serve(controlListener) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case serveErr := <-done:
		return serveErr
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, server := range servers {
			if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
				return shutdownErr
			}
		}
		return nil
	}
}

var (
	_ desktopgateway.Resolver    = (*networkDesktopResolver)(nil)
	_ desktopgateway.MediaSource = (*desktopRuntimeMedia)(nil)
	_ desktopgateway.Session     = (*desktopRuntimeSession)(nil)
)
