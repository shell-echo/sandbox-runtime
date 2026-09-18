package productgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
)

const browserLiveRecordingFlushBytes = 48 << 10

type ProductBrowserLiveRecorder struct {
	Service          *product.RecordingService
	RetentionSeconds int64
}

func NewProductBrowserLiveRecorder(service *product.RecordingService, retentionSeconds int64) (*ProductBrowserLiveRecorder, error) {
	if service == nil || retentionSeconds < 60 || retentionSeconds > 30*24*3600 {
		return nil, product.ErrInvalid
	}
	return &ProductBrowserLiveRecorder{Service: service, RetentionSeconds: retentionSeconds}, nil
}

func (r *ProductBrowserLiveRecorder) Start(ctx context.Context, binding product.GatewayBinding, consentReference string, video BrowserLiveVideoPolicy) (BrowserLiveRecordingSession, error) {
	if r == nil || r.Service == nil || ctx == nil || binding.RecordingPolicy != "required" || binding.ProtocolProfile != product.SessionProfileBrowserLive || !validBrowserConsentReference(consentReference) || !validBrowserLiveVideoPolicy(video) {
		return nil, product.ErrInvalid
	}
	recording, err := r.Service.Start(ctx, binding.TenantID, binding.Actor, binding.WorkspaceID, product.StartRecordingRequest{
		SessionID: binding.SessionID, RecordingType: "media", ConsentReference: consentReference, RetentionSeconds: r.RetentionSeconds,
	})
	if err != nil {
		return nil, err
	}
	session := &productBrowserLiveRecordingSession{service: r.Service, binding: binding, recordingID: recording.ID}
	header := browserLiveRecordedEvent{Type: "stream.start", At: time.Now().UTC(), Video: &video}
	if err := session.appendAndFlush(ctx, header); err != nil {
		_ = r.Service.Fail(ctx, binding.TenantID, binding.Actor, recording.ID)
		return nil, err
	}
	return session, nil
}

type browserLiveRecordedEvent struct {
	Type        string                  `json:"type"`
	At          time.Time               `json:"at"`
	Payload     []byte                  `json:"payload,omitempty"`
	Sequence    int64                   `json:"sequence,omitempty"`
	ActionKind  string                  `json:"action_kind,omitempty"`
	Event       string                  `json:"event,omitempty"`
	TouchPoints int                     `json:"touch_points,omitempty"`
	Video       *BrowserLiveVideoPolicy `json:"video,omitempty"`
}

type productBrowserLiveRecordingSession struct {
	service     *product.RecordingService
	binding     product.GatewayBinding
	recordingID string
	mu          sync.Mutex
	buffer      bytes.Buffer
	closed      bool
}

func (s *productBrowserLiveRecordingSession) RecordMedia(ctx context.Context, at time.Time, payload []byte) error {
	if len(payload) < 1 || len(payload) > maxLiveRTPPacketBytes {
		return product.ErrInvalid
	}
	return s.append(ctx, browserLiveRecordedEvent{Type: "media.rtp", At: at.UTC(), Payload: append([]byte(nil), payload...)})
}

func (s *productBrowserLiveRecordingSession) RecordControl(ctx context.Context, at time.Time, kind string, input BrowserLiveInput, video BrowserLiveVideoPolicy) error {
	event := browserLiveRecordedEvent{Type: kind, At: at.UTC(), Sequence: input.Sequence, ActionKind: input.Action.Kind, Event: input.Event, TouchPoints: len(input.Touches)}
	if kind == "stream.resize" {
		event.Video = &video
	}
	return s.append(ctx, event)
}

func (s *productBrowserLiveRecordingSession) append(ctx context.Context, event browserLiveRecordedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx == nil || ctx.Err() != nil {
		return product.ErrControlStale
	}
	return s.appendLocked(ctx, event, false)
}

func (s *productBrowserLiveRecordingSession) appendAndFlush(ctx context.Context, event browserLiveRecordedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(ctx, event, true)
}

func (s *productBrowserLiveRecordingSession) appendLocked(ctx context.Context, event browserLiveRecordedEvent, force bool) error {
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded)+1 > product.MaxRecordingSegmentBytes {
		return product.ErrInvalid
	}
	if s.buffer.Len() > 0 && s.buffer.Len()+len(encoded)+1 > browserLiveRecordingFlushBytes {
		if err := s.flushLocked(ctx); err != nil {
			return err
		}
	}
	_, _ = s.buffer.Write(encoded)
	_ = s.buffer.WriteByte('\n')
	if force || s.buffer.Len() >= browserLiveRecordingFlushBytes {
		return s.flushLocked(ctx)
	}
	return nil
}

func (s *productBrowserLiveRecordingSession) flushLocked(ctx context.Context) error {
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

func (s *productBrowserLiveRecordingSession) Close(ctx context.Context, failed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if failed {
		return s.service.Fail(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
	}
	if err := s.appendLocked(ctx, browserLiveRecordedEvent{Type: "stream.end", At: time.Now().UTC()}, true); err != nil {
		_ = s.service.Fail(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
		return err
	}
	_, err := s.service.Finalize(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
	if err != nil {
		_ = s.service.Fail(ctx, s.binding.TenantID, s.binding.Actor, s.recordingID)
	}
	return err
}

var _ BrowserLiveRecorder = (*ProductBrowserLiveRecorder)(nil)
var _ BrowserLiveRecordingSession = (*productBrowserLiveRecordingSession)(nil)
