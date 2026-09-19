package productgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
)

const desktopLiveRecordingFlushBytes = 48 << 10

type ProductDesktopLiveRecorder struct {
	Service          *product.RecordingService
	RetentionSeconds int64
}

func NewProductDesktopLiveRecorder(service *product.RecordingService, retentionSeconds int64) (*ProductDesktopLiveRecorder, error) {
	if service == nil || retentionSeconds < 60 || retentionSeconds > 30*24*3600 {
		return nil, product.ErrInvalid
	}
	return &ProductDesktopLiveRecorder{Service: service, RetentionSeconds: retentionSeconds}, nil
}

func (r *ProductDesktopLiveRecorder) Start(ctx context.Context, binding product.GatewayBinding, consentReference string, media DesktopLiveMediaPolicy) (DesktopLiveRecordingSession, error) {
	if r == nil || r.Service == nil || ctx == nil || binding.RecordingPolicy != "required" || binding.ProtocolProfile != product.SessionProfileDesktop || !validDesktopConsentReference(consentReference) || !validDesktopLiveMediaPolicy(media) {
		return nil, product.ErrInvalid
	}
	recording, err := r.Service.Start(ctx, binding.TenantID, binding.Actor, binding.WorkspaceID, product.StartRecordingRequest{
		SessionID: binding.SessionID, RecordingType: "media", ConsentReference: consentReference, RetentionSeconds: r.RetentionSeconds,
	})
	if err != nil {
		return nil, err
	}
	session := &productDesktopLiveRecordingSession{service: r.Service, binding: binding, recordingID: recording.ID, media: media}
	if err := session.appendAndFlush(ctx, desktopLiveRecordedEvent{Type: "stream.start", At: time.Now().UTC(), Media: &media}); err != nil {
		_ = r.Service.Fail(ctx, binding.TenantID, binding.Actor, recording.ID)
		return nil, err
	}
	return session, nil
}

type desktopLiveRecordedEvent struct {
	Type        string                    `json:"type"`
	At          time.Time                 `json:"at"`
	Payload     []byte                    `json:"payload,omitempty"`
	Sequence    int64                     `json:"sequence,omitempty"`
	ActionKind  string                    `json:"action_kind,omitempty"`
	Event       string                    `json:"event,omitempty"`
	TouchPoints int                       `json:"touch_points,omitempty"`
	Media       *DesktopLiveMediaPolicy   `json:"media,omitempty"`
	Display     *DesktopLiveDisplayPolicy `json:"display,omitempty"`
	AudioDevice string                    `json:"audio_device,omitempty"`
}

type productDesktopLiveRecordingSession struct {
	service     *product.RecordingService
	binding     product.GatewayBinding
	recordingID string
	media       DesktopLiveMediaPolicy
	mu          sync.Mutex
	buffer      bytes.Buffer
	lastAt      time.Time
	closed      bool
}

func (s *productDesktopLiveRecordingSession) RecordMedia(ctx context.Context, at time.Time, kind string, payload []byte) error {
	limit := 0
	switch kind {
	case "video.rtp":
		limit = maxDesktopVideoRTPPacketBytes
	case "audio.rtp":
		limit = maxDesktopAudioRTPPacketBytes
	default:
		return product.ErrInvalid
	}
	if len(payload) < 1 || len(payload) > limit {
		return product.ErrInvalid
	}
	return s.append(ctx, desktopLiveRecordedEvent{Type: kind, At: at.UTC(), Payload: append([]byte(nil), payload...)})
}

func (s *productDesktopLiveRecordingSession) RecordControl(ctx context.Context, at time.Time, kind string, sequence int64, input DesktopLiveInput, display DesktopLiveDisplayPolicy, audioDevice string) error {
	if sequence < 1 || sequence > maxAutomationSequence {
		return product.ErrInvalid
	}
	event := desktopLiveRecordedEvent{Type: kind, At: at.UTC(), Sequence: sequence}
	switch kind {
	case "input":
		if !validDesktopRecordedInput(input) {
			return product.ErrInvalid
		}
		event.ActionKind, event.Event, event.TouchPoints = input.Action.Kind, input.Event, len(input.Touches)
	case "stream.resync":
	case "stream.configure":
		if !validDesktopDisplayPolicy(display) || !validDesktopAudioDevice(audioDevice, s.media) {
			return product.ErrInvalid
		}
		event.Display, event.AudioDevice = &display, audioDevice
	default:
		return product.ErrInvalid
	}
	return s.append(ctx, event)
}

func validDesktopRecordedInput(input DesktopLiveInput) bool {
	switch input.Action.Kind {
	case product.DesktopActionKeyboard:
		return input.Event == "down" || input.Event == "up"
	case product.DesktopActionPointer:
		return input.Event == "move" || input.Event == "down" || input.Event == "up" || input.Event == "wheel"
	case product.DesktopActionTouch:
		return (input.Event == "start" || input.Event == "move" || input.Event == "end") && len(input.Touches) >= 1 && len(input.Touches) <= 10
	case product.DesktopActionClipboardRead, product.DesktopActionClipboardWrite, product.DesktopActionUpload, product.DesktopActionDownload:
		return input.Event == ""
	default:
		return false
	}
}

func (s *productDesktopLiveRecordingSession) append(ctx context.Context, event desktopLiveRecordedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx == nil || ctx.Err() != nil {
		return product.ErrControlStale
	}
	return s.appendLocked(ctx, event, false)
}

func (s *productDesktopLiveRecordingSession) appendAndFlush(ctx context.Context, event desktopLiveRecordedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(ctx, event, true)
}

func (s *productDesktopLiveRecordingSession) appendLocked(ctx context.Context, event desktopLiveRecordedEvent, force bool) error {
	if event.At.IsZero() {
		return product.ErrInvalid
	}
	if !s.lastAt.IsZero() && event.At.Before(s.lastAt) {
		event.At = s.lastAt
	}
	s.lastAt = event.At
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded)+1 > product.MaxRecordingSegmentBytes {
		return product.ErrInvalid
	}
	if s.buffer.Len() > 0 && s.buffer.Len()+len(encoded)+1 > desktopLiveRecordingFlushBytes {
		if err := s.flushLocked(ctx); err != nil {
			return err
		}
	}
	_, _ = s.buffer.Write(encoded)
	_ = s.buffer.WriteByte('\n')
	if force || s.buffer.Len() >= desktopLiveRecordingFlushBytes {
		return s.flushLocked(ctx)
	}
	return nil
}

func (s *productDesktopLiveRecordingSession) flushLocked(ctx context.Context) error {
	if s.buffer.Len() == 0 {
		return nil
	}
	payload := append([]byte(nil), s.buffer.Bytes()...)
	if _, err := s.service.Append(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID, payload); err != nil {
		return err
	}
	s.buffer.Reset()
	return nil
}

func (s *productDesktopLiveRecordingSession) Close(ctx context.Context, failed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if failed {
		return s.service.Fail(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
	}
	if err := s.appendLocked(ctx, desktopLiveRecordedEvent{Type: "stream.end", At: time.Now().UTC()}, true); err != nil {
		_ = s.service.Fail(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
		return err
	}
	_, err := s.service.Finalize(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
	if err != nil {
		_ = s.service.Fail(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
	}
	return err
}

var _ DesktopLiveRecorder = (*ProductDesktopLiveRecorder)(nil)
var _ DesktopLiveRecordingSession = (*productDesktopLiveRecordingSession)(nil)
