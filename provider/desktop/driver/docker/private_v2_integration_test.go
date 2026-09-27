//go:build integration

package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopgateway "github.com/shell-echo/sandbox-runtime/provider/desktop/gateway"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

// This is a local-candidate diagnostic bridge, not the distinct-process
// Product/WebRTC release gate. The actual Docker broker and executor backend
// are reached through the Product private v2 client and Provider v2 handler.
type realPrivateV2Authority struct {
	mu         sync.Mutex
	binding    *desktophandoff.Binding
	media      providerdesktop.MediaRuntime
	authority  providerdesktop.MediaAuthority
	attachment providerdesktop.Attachment
	receipt    providerdesktop.AllocationReceipt
	opens      atomic.Int32
	closes     atomic.Int32
}

func (a *realPrivateV2Authority) BindHandoff(_ context.Context, binding desktophandoff.Binding) error {
	if binding.Validate(time.Now().UTC()) != nil || binding.HandoffReference != a.authority.HandoffReference {
		return providerdesktop.ErrDesktopUnsupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.binding != nil {
		return providerdesktop.ErrDesktopUnsupported
	}
	a.binding = &binding
	return nil
}

func (a *realPrivateV2Authority) Resolve(_ context.Context, reference string) (desktopreference.Endpoint, error) {
	a.mu.Lock()
	if reference != a.authority.HandoffReference || a.binding == nil {
		a.mu.Unlock()
		return desktopreference.Endpoint{}, providerdesktop.ErrDesktopNotFound
	}
	binding := *a.binding
	a.mu.Unlock()
	return desktopreference.Endpoint{
		Reference: reference, ProviderRevisionID: a.authority.ProviderRevisionID,
		SandboxID: a.authority.SandboxID, DesktopSessionID: a.authority.DesktopSessionID,
		CapabilityProfileID:  providerdesktop.CapabilityProfileID,
		ConnectionGeneration: a.authority.ConnectionGeneration,
		TenantBindingDigest:  a.authority.TenantBindingDigest,
		ExpiresAt:            a.receipt.ExpiresAt, AllocationReference: a.receipt.Reference,
		Binding: &binding,
		Attach: func(context.Context) (providerdesktop.Attachment, error) {
			return a.attachment, nil
		},
	}, nil
}

func (a *realPrivateV2Authority) OpenBound(ctx context.Context, open desktophandoff.OpenRequest,
	endpoint desktopreference.Endpoint, attachment providerdesktop.Attachment) (desktopgateway.Session, error) {
	if open.Validate(time.Now().UTC()) != nil || endpoint.Reference != a.authority.HandoffReference ||
		endpoint.AllocationReference != a.receipt.Reference || attachment.DesktopSessionID != a.attachment.DesktopSessionID ||
		attachment.ConnectionGeneration != a.attachment.ConnectionGeneration {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	authorityExpiry, err := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	if err != nil {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	authority := a.authority
	authority.AuthorityDigest, authority.RequestDigest = open.AuthorityDigest, open.RequestDigest
	authority.AuthorityExpiresAt = authorityExpiry
	session, err := a.media.OpenMedia(ctx, authority, attachment, open.MediaPolicy)
	if err != nil {
		return nil, err
	}
	a.opens.Add(1)
	return &realPrivateV2Session{MediaSession: session, closed: &a.closes}, nil
}

type realPrivateV2Session struct {
	providerdesktop.MediaSession
	closed *atomic.Int32
	once   sync.Once
}

func (s *realPrivateV2Session) Close() error {
	var err error
	s.once.Do(func() {
		err = s.MediaSession.Close()
		s.closed.Add(1)
	})
	return err
}

func runRealPrivateV2Bridge(t *testing.T, ctx context.Context, runtime providerdesktop.MediaRuntime,
	authority providerdesktop.MediaAuthority, attachment providerdesktop.Attachment,
	receipt providerdesktop.AllocationReceipt, container string) {
	t.Helper()
	fixture := &realPrivateV2Authority{media: runtime, authority: authority, attachment: attachment, receipt: receipt}
	handler, err := desktopgateway.New(desktopgateway.Options{
		Resolver: fixture, BoundMedia: fixture, BindingRegistrar: fixture,
		MaxSessions: 1, MaxSessionsPerDesktop: 1, AuthorityPollInterval: 100 * time.Millisecond,
		OperationTimeout: 20 * time.Second, AllowInsecureHTTPForTests: true, RequireActivationV2: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	source, err := productgateway.NewPrivateDesktopMediaSource(productgateway.PrivateDesktopMediaOptions{
		Origin: strings.Replace(server.URL, "http://", "ws://", 1), HTTPClient: server.Client(),
		AllowHTTPForTests: true, ExpectedProviderID: authority.ProviderRevisionID, OpenTimeout: 15 * time.Second,
		TenantBindingDigest: func(context.Context, product.GatewayBinding) (string, error) {
			return authority.TenantBindingDigest, nil
		},
		ControllerFence: func(context.Context, product.GatewayBinding) (string, error) {
			return authority.ControllerFence, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := product.GatewayBinding{
		ConnectionID: authority.ConnectionEpoch, TenantID: "tenant-real-v2",
		SessionID: authority.DesktopSessionID, ProtocolProfile: product.SessionProfileDesktop,
		ExpiresAt: authority.AuthorityExpiresAt, ProviderRevisionID: authority.ProviderRevisionID,
		SandboxID: authority.SandboxID, HandoffReference: authority.HandoffReference,
		ConnectionGeneration: authority.ConnectionGeneration, HandoffExpiresAt: receipt.ExpiresAt,
		RecordingPolicy: "metadata_only",
	}
	policy := productgateway.DesktopLiveMediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720,
		MaxFPS: 30, MaxVideoBitrateKbps: 2000}
	media, err := source.Open(ctx, binding, policy)
	if err != nil {
		t.Fatalf("Product private v2 prepare: %v", err)
	}
	defer media.Close()
	if err := media.Resynchronize(ctx); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("real pre-start control admitted: %v", err)
	}
	time.Sleep(750 * time.Millisecond)
	if fixture.opens.Load() != 0 {
		t.Fatal("real executor media opened before Product activation")
	}
	frameCtx, cancelFrame := context.WithTimeout(ctx, 30*time.Second)
	defer cancelFrame()
	type frameResult struct {
		frame []byte
		err   error
	}
	frames := make(chan frameResult, 1)
	go func() {
		frame, readErr := readPrivateVP8Keyframe(frameCtx, media)
		frames <- frameResult{frame: frame, err: readErr}
	}()
	activator, ok := media.(productgateway.DesktopLiveMediaActivator)
	if !ok {
		t.Fatal("Product private source omitted v2 activation")
	}
	if err := activator.Activate(frameCtx); err != nil {
		t.Fatalf("real Product→Provider v2 start: %v", err)
	}
	var result frameResult
	select {
	case result = <-frames:
	case <-frameCtx.Done():
		t.Fatal("real Product private v2 first keyframe timed out")
	}
	if result.err != nil {
		t.Fatalf("real Product private v2 keyframe: %v", result.err)
	}
	decodeRealPrivateVP8(t, frameCtx, container, result.frame)
	inputCtx, cancelInput := context.WithTimeout(ctx, 10*time.Second)
	defer cancelInput()
	_, err = media.HandleInput(inputCtx, productgateway.DesktopLiveInput{
		Sequence: 1, Kind: "pointer", Event: "move", X: 123, Y: 234,
		ControlLeaseID: "lease-real-v2", ControlFence: 1,
	})
	if err != nil {
		t.Fatalf("real Product private v2 input: %v", err)
	}
	if err := media.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for fixture.closes.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fixture.opens.Load() != 1 || fixture.closes.Load() != 1 {
		t.Fatalf("real v2 media cleanup: opens=%d closes=%d", fixture.opens.Load(), fixture.closes.Load())
	}
}

func readPrivateVP8Keyframe(ctx context.Context, media productgateway.DesktopLiveMediaSession) ([]byte, error) {
	var frame []byte
	var timestamp uint32
	collecting := false
	for {
		document, err := media.ReadVideoRTP(ctx)
		if err != nil {
			return nil, err
		}
		var packet rtp.Packet
		if packet.Unmarshal(document) != nil {
			continue
		}
		var vp8 codecs.VP8Packet
		payload, err := vp8.Unmarshal(packet.Payload)
		if err != nil || len(payload) == 0 {
			continue
		}
		if vp8.S == 1 && vp8.PID == 0 {
			collecting, timestamp, frame = true, packet.Timestamp, frame[:0]
		}
		if !collecting || packet.Timestamp != timestamp || len(frame)+len(payload) > 8<<20 {
			collecting = false
			continue
		}
		frame = append(frame, payload...)
		if packet.Marker {
			if len(frame) > 0 && frame[0]&1 == 0 {
				return frame, nil
			}
			collecting = false
		}
	}
}

func decodeRealPrivateVP8(t *testing.T, ctx context.Context, container string, frame []byte) {
	t.Helper()
	if len(frame) == 0 || len(frame) > 8<<20 {
		t.Fatal("invalid Product private VP8 keyframe")
	}
	ivf := make([]byte, 32+12+len(frame))
	copy(ivf[:4], "DKIF")
	binary.LittleEndian.PutUint16(ivf[6:8], 32)
	copy(ivf[8:12], "VP80")
	binary.LittleEndian.PutUint16(ivf[12:14], 1280)
	binary.LittleEndian.PutUint16(ivf[14:16], 720)
	binary.LittleEndian.PutUint32(ivf[16:20], 30)
	binary.LittleEndian.PutUint32(ivf[20:24], 1)
	binary.LittleEndian.PutUint32(ivf[24:28], 1)
	binary.LittleEndian.PutUint32(ivf[32:36], uint32(len(frame)))
	copy(ivf[44:], frame)
	command := exec.CommandContext(ctx, "docker", "exec", "-i", container, "/usr/bin/ffmpeg",
		"-hide_banner", "-loglevel", "error", "-xerror", "-i", "pipe:0",
		"-frames:v", "1", "-an", "-pix_fmt", "rgb24", "-f", "rawvideo", "-")
	command.Stdin = bytes.NewReader(ivf)
	decoded, err := command.Output()
	if err != nil || len(decoded) != 1280*720*3 {
		t.Fatalf("real Product private v2 keyframe undecodable: bytes=%d err=%v", len(decoded), err)
	}
}
