package productgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/product"
)

const defaultPrivateDesktopMessageBytes = int64(64 << 10)

type PrivateDesktopMediaOptions struct {
	Origin              string
	HTTPClient          *http.Client
	MaxMessageBytes     int64
	OpenTimeout         time.Duration
	AllowHTTPForTests   bool
	ExpectedProviderID  string
	TenantBindingDigest func(context.Context, product.GatewayBinding) (string, error)
	ControllerFence     func(context.Context, product.GatewayBinding) (string, error)
}

// PrivateDesktopMediaSource adapts the Product Gateway media port to the
// private Provider Desktop bridge. It carries only an already-consumed Product
// binding and never exposes the Provider handoff to the public WebRTC peer.
type PrivateDesktopMediaSource struct {
	origin          *url.URL
	httpClient      *http.Client
	maxMessageBytes int64
	openTimeout     time.Duration
	providerID      string
	tenantDigest    func(context.Context, product.GatewayBinding) (string, error)
	controllerFence func(context.Context, product.GatewayBinding) (string, error)
}

func NewPrivateDesktopMediaSource(options PrivateDesktopMediaOptions) (*PrivateDesktopMediaSource, error) {
	origin, err := url.Parse(options.Origin)
	limit := options.MaxMessageBytes
	if limit == 0 {
		limit = defaultPrivateDesktopMessageBytes
	}
	openTimeout := options.OpenTimeout
	if openTimeout == 0 {
		openTimeout = 10 * time.Second
	}
	validScheme := err == nil && origin != nil && (origin.Scheme == "wss" || options.AllowHTTPForTests && origin.Scheme == "ws")
	if !validScheme || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") || options.HTTPClient == nil || limit < 1024 || limit > 256<<10 ||
		openTimeout < time.Second || openTimeout > 30*time.Second || options.ExpectedProviderID == "" ||
		strings.ContainsAny(options.ExpectedProviderID, " \r\n\t") {
		return nil, product.ErrInvalid
	}
	copyClient := *options.HTTPClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &PrivateDesktopMediaSource{origin: origin, httpClient: &copyClient, maxMessageBytes: limit, openTimeout: openTimeout, providerID: options.ExpectedProviderID, tenantDigest: options.TenantBindingDigest, controllerFence: options.ControllerFence}, nil
}

func (s *PrivateDesktopMediaSource) Open(ctx context.Context, binding product.GatewayBinding, policy DesktopLiveMediaPolicy) (DesktopLiveMediaSession, error) {
	now := time.Now().UTC()
	if s == nil || ctx == nil || binding.ProviderRevisionID != s.providerID || binding.SandboxID == "" || binding.SessionID == "" ||
		binding.ProtocolProfile != product.SessionProfileDesktop || binding.HandoffReference == "" || binding.ConnectionGeneration < 1 ||
		binding.ConnectionID == "" || binding.ExpiresAt.IsZero() || !binding.ExpiresAt.After(now) ||
		binding.HandoffExpiresAt.IsZero() || !binding.HandoffExpiresAt.After(now) {
		return nil, product.ErrForbidden
	}
	recordingMode := binding.RecordingPolicy
	if recordingMode == "" {
		// Legacy in-memory gateway fixtures predate the closed recording field;
		// durable Product bindings always carry one of the three explicit modes.
		recordingMode = "metadata_only"
	}
	privatePolicy := desktopmedia.MediaPolicy{VideoCodec: policy.VideoCodec, Width: policy.Width, Height: policy.Height,
		MaxFPS: policy.MaxFPS, MaxVideoBitrateKbps: policy.MaxVideoBitrateKbps, AudioCodec: policy.AudioCodec,
		MaxAudioBitrateKbps: policy.MaxAudioBitrateKbps, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames,
		MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes,
		RecordingMode: recordingMode}
	if recordingMode == "required" {
		privatePolicy.MaxRecordingBytes = desktopmedia.DefaultMaxRecordingBytes
	}
	if s.tenantDigest != nil || s.controllerFence != nil {
		if s.tenantDigest == nil || s.controllerFence == nil {
			return nil, product.ErrForbidden
		}
		return s.openClosed(ctx, binding, privatePolicy)
	}
	policyDocument, err := json.Marshal(privatePolicy)
	if err != nil {
		return nil, product.ErrInvalid
	}
	header := http.Header{}
	header.Set("X-Sandbox-Desktop-Reference", binding.HandoffReference)
	header.Set("X-Sandbox-ID", binding.SandboxID)
	header.Set("X-Sandbox-Desktop-Session", binding.SessionID)
	header.Set("X-Sandbox-Desktop-Profile", product.DesktopCapabilityProfile)
	header.Set("X-Sandbox-Connection-Generation", strconv.FormatInt(binding.ConnectionGeneration, 10))
	header.Set("X-Sandbox-Authority-Expires-At", binding.HandoffExpiresAt.UTC().Format(time.RFC3339Nano))
	header.Set("X-Sandbox-Desktop-Media-Policy", string(policyDocument))
	openCtx, cancel := context.WithTimeout(ctx, s.openTimeout)
	defer cancel()
	connection, response, err := websocket.Dial(openCtx, s.origin.String(), &websocket.DialOptions{
		HTTPClient: s.httpClient, HTTPHeader: header, Subprotocols: []string{desktopmedia.Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil || connection.Subprotocol() != desktopmedia.Subprotocol {
		if connection != nil {
			_ = connection.CloseNow()
		}
		return nil, product.ErrStoreUnavailable
	}
	connection.SetReadLimit(s.maxMessageBytes)
	session := &privateDesktopMediaSession{
		connection: connection, maxMessageBytes: s.maxMessageBytes,
		video: make(chan []byte, 32), audio: make(chan []byte, 64),
		results: make(map[int64]chan desktopgatewayResult), done: make(chan struct{}),
	}
	go session.read()
	return session, nil
}

func (s *PrivateDesktopMediaSource) openClosed(ctx context.Context, binding product.GatewayBinding, policy desktopmedia.MediaPolicy) (DesktopLiveMediaSession, error) {
	digest, err := s.tenantDigest(ctx, binding)
	if err != nil || handoff.ValidateTenantBindingDigest(digest) != nil {
		return nil, product.ErrForbidden
	}
	fence, err := s.controllerFence(ctx, binding)
	if err != nil || len(fence) < handoff.MinFenceBytes || strings.ContainsAny(fence, "\r\n\x00") {
		return nil, product.ErrForbidden
	}
	requestID, err := randomRequestID()
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	authorityExpires := binding.ExpiresAt.UTC()
	if binding.HandoffExpiresAt.Before(authorityExpires) {
		authorityExpires = binding.HandoffExpiresAt.UTC()
	}
	open := desktophandoff.OpenRequest{BindingVersion: desktophandoff.BindingVersion, BindingIssuer: desktophandoff.BindingIssuer, Protocol: desktophandoff.ProtocolID, RequestID: requestID, Resource: desktophandoff.ResourceDesktop,
		TenantBindingDigest: digest, ProviderRevisionID: binding.ProviderRevisionID, SandboxID: binding.SandboxID,
		DesktopSessionID: binding.SessionID, CapabilityProfileID: product.DesktopCapabilityProfile,
		MediaProfileID: desktophandoff.MediaProfileID, ControlProfileID: desktophandoff.ControlProfileID,
		HandoffReference: binding.HandoffReference, HandoffDigest: desktophandoff.ReferenceDigest(binding.HandoffReference),
		ConnectionGeneration: binding.ConnectionGeneration, ConnectionEpoch: binding.ConnectionID,
		AuthorityExpiresAt: authorityExpires.Format(time.RFC3339Nano), HandoffExpiresAt: binding.HandoffExpiresAt.UTC().Format(time.RFC3339Nano),
		ControllerFence: fence, MediaPolicy: policy}
	open.AuthorityDigest = desktophandoff.AuthorityDigest(open)
	open.RequestDigest = desktophandoff.RequestDigest(open)
	if open.Validate(time.Now().UTC()) != nil {
		return nil, product.ErrForbidden
	}
	openCtx, cancel := context.WithTimeout(ctx, s.openTimeout)
	defer cancel()
	connection, response, err := websocket.Dial(openCtx, s.origin.String(), &websocket.DialOptions{HTTPClient: s.httpClient, Subprotocols: []string{desktophandoff.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil || connection.Subprotocol() != desktophandoff.ProtocolID {
		if connection != nil {
			_ = connection.CloseNow()
		}
		return nil, product.ErrStoreUnavailable
	}
	connection.SetReadLimit(s.maxMessageBytes)
	document, err := handoff.Encode(open)
	if err != nil || connection.Write(openCtx, websocket.MessageText, document) != nil {
		_ = connection.CloseNow()
		return nil, product.ErrStoreUnavailable
	}
	kind, responseDocument, err := connection.Read(openCtx)
	var accepted desktophandoff.OpenResponse
	if err != nil || kind != websocket.MessageText || handoff.Decode(responseDocument, &accepted) != nil || accepted.Validate() != nil || accepted.RequestID != requestID || accepted.Status != desktophandoff.StatusAccepted {
		_ = connection.CloseNow()
		return nil, product.ErrStoreUnavailable
	}
	return newPrivateDesktopMediaSession(connection, s.maxMessageBytes), nil
}

func newPrivateDesktopMediaSession(connection *websocket.Conn, maxMessageBytes int64) *privateDesktopMediaSession {
	session := &privateDesktopMediaSession{connection: connection, maxMessageBytes: maxMessageBytes, video: make(chan []byte, 32), audio: make(chan []byte, 64), results: make(map[int64]chan desktopgatewayResult), done: make(chan struct{})}
	go session.read()
	return session
}

type desktopgatewayResult = desktopmedia.Result
type desktopgatewayCommand = desktopmedia.Command

type privateDesktopMediaSession struct {
	connection      *websocket.Conn
	maxMessageBytes int64
	video           chan []byte
	audio           chan []byte
	done            chan struct{}
	closeOnce       sync.Once
	writeMu         sync.Mutex
	resultMu        sync.Mutex
	results         map[int64]chan desktopgatewayResult
	nextRequest     atomic.Int64
}

func (s *privateDesktopMediaSession) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	return s.readPacket(ctx, s.video)
}

func (s *privateDesktopMediaSession) ReadAudioRTP(ctx context.Context) ([]byte, error) {
	return s.readPacket(ctx, s.audio)
}

func (s *privateDesktopMediaSession) readPacket(ctx context.Context, packets <-chan []byte) ([]byte, error) {
	select {
	case packet := <-packets:
		if len(packet) == 0 {
			return nil, product.ErrStoreUnavailable
		}
		return append([]byte(nil), packet...), nil
	case <-s.done:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *privateDesktopMediaSession) HandleInput(ctx context.Context, input DesktopLiveInput) (DesktopLiveInputResult, error) {
	privateInput := desktopmedia.Input{Sequence: input.Sequence, Kind: input.Kind, Event: input.Event, Code: input.Code, Key: input.Key,
		Modifiers: append([]string(nil), input.Modifiers...), X: input.X, Y: input.Y, Button: input.Button, DeltaX: input.DeltaX,
		DeltaY: input.DeltaY, Text: input.Action.Text, ControlLeaseID: input.ControlLeaseID, ControlFence: input.ControlFence}
	privateInput.Touches = make([]desktopmedia.TouchPoint, len(input.Touches))
	for index, point := range input.Touches {
		privateInput.Touches[index] = desktopmedia.TouchPoint{ID: point.ID, X: point.X, Y: point.Y}
	}
	privateInput.Files = make([]desktopmedia.TransferFile, len(input.Action.Files))
	for index, file := range input.Action.Files {
		privateInput.Files[index] = desktopmedia.TransferFile{TransferID: file.TransferID, Path: file.Path, MediaType: file.MediaType, Digest: file.Digest, SizeBytes: file.SizeBytes}
	}
	response, err := s.command(ctx, desktopgatewayCommand{Type: "input", Input: &privateInput})
	return DesktopLiveInputResult{Text: response.Text}, err
}

func (s *privateDesktopMediaSession) UpdateStream(ctx context.Context, display DesktopLiveDisplayPolicy, audioDevice string) error {
	privateDisplay := desktopmedia.DisplayPolicy{Width: display.Width, Height: display.Height, MaxFPS: display.MaxFPS}
	_, err := s.command(ctx, desktopgatewayCommand{Type: "stream.configure", Display: &privateDisplay, AudioDevice: audioDevice})
	return err
}

func (s *privateDesktopMediaSession) Resynchronize(ctx context.Context) error {
	_, err := s.command(ctx, desktopgatewayCommand{Type: "stream.resync"})
	return err
}

func (s *privateDesktopMediaSession) RequestKeyframe(ctx context.Context) error {
	_, err := s.command(ctx, desktopgatewayCommand{Type: "keyframe"})
	return err
}

func (s *privateDesktopMediaSession) command(ctx context.Context, command desktopgatewayCommand) (desktopgatewayResult, error) {
	if s == nil || ctx == nil {
		return desktopgatewayResult{}, product.ErrStoreUnavailable
	}
	command.RequestID = s.nextRequest.Add(1)
	response := make(chan desktopgatewayResult, 1)
	s.resultMu.Lock()
	s.results[command.RequestID] = response
	s.resultMu.Unlock()
	defer func() {
		s.resultMu.Lock()
		delete(s.results, command.RequestID)
		s.resultMu.Unlock()
	}()
	payload, err := json.Marshal(command)
	if err != nil || int64(len(payload)) > s.maxMessageBytes {
		return desktopgatewayResult{}, product.ErrInvalid
	}
	s.writeMu.Lock()
	err = s.connection.Write(ctx, websocket.MessageText, payload)
	s.writeMu.Unlock()
	if err != nil {
		s.close()
		return desktopgatewayResult{}, product.ErrStoreUnavailable
	}
	select {
	case result := <-response:
		if !result.OK || result.Type != "result" || result.RequestID != command.RequestID {
			return desktopgatewayResult{}, product.ErrStoreUnavailable
		}
		return result, nil
	case <-s.done:
		return desktopgatewayResult{}, product.ErrStoreUnavailable
	case <-ctx.Done():
		return desktopgatewayResult{}, ctx.Err()
	}
}

func (s *privateDesktopMediaSession) read() {
	defer s.close()
	for {
		kind, payload, err := s.connection.Read(context.Background())
		if err != nil || int64(len(payload)) > s.maxMessageBytes {
			return
		}
		switch kind {
		case websocket.MessageBinary:
			if len(payload) < 2 {
				return
			}
			var target chan []byte
			switch payload[0] {
			case 1:
				target = s.video
			case 2:
				target = s.audio
			default:
				return
			}
			packet := append([]byte(nil), payload[1:]...)
			select {
			case target <- packet:
			default:
				return
			}
		case websocket.MessageText:
			decoder := json.NewDecoder(bytes.NewReader(payload))
			decoder.DisallowUnknownFields()
			var result desktopgatewayResult
			if decoder.Decode(&result) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || result.Type != "result" || result.RequestID < 1 {
				return
			}
			s.resultMu.Lock()
			waiter := s.results[result.RequestID]
			s.resultMu.Unlock()
			if waiter == nil {
				return
			}
			select {
			case waiter <- result:
			default:
				return
			}
		default:
			return
		}
	}
}

func (s *privateDesktopMediaSession) Close() error {
	if s == nil {
		return nil
	}
	s.close()
	return nil
}

func (s *privateDesktopMediaSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.connection.CloseNow()
	})
}

var (
	_ DesktopLiveMediaSource  = (*PrivateDesktopMediaSource)(nil)
	_ DesktopLiveMediaSession = (*privateDesktopMediaSession)(nil)
)
