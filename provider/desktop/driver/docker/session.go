package docker

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
)

var mediaReferencePattern = regexp.MustCompile(`^ref:desktop-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

func (d *Driver) OpenMedia(ctx context.Context, authority providerdesktop.MediaAuthority, attachment providerdesktop.Attachment, policy desktopmedia.MediaPolicy) (providerdesktop.MediaSession, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	binding := desktophandoff.Binding{Version: desktophandoff.BindingVersion, Issuer: desktophandoff.BindingIssuer,
		TenantBindingDigest: authority.TenantBindingDigest, ProviderRevisionID: authority.ProviderRevisionID, SandboxID: authority.SandboxID,
		DesktopSessionID: authority.DesktopSessionID, HandoffReference: authority.HandoffReference, ConnectionGeneration: authority.ConnectionGeneration,
		ConnectionEpoch: authority.ConnectionEpoch, ControllerFence: authority.ControllerFence, AuthorityExpiresAt: authority.AuthorityExpiresAt,
		HandoffExpiresAt: authority.HandoffExpiresAt, AuthorityDigest: authority.AuthorityDigest, RequestDigest: authority.RequestDigest, MediaPolicy: policy}
	if d == nil || d.engine == nil || binding.Validate(d.options.Clock.Now().UTC()) != nil ||
		!mediaReferencePattern.MatchString(authority.AllocationReference) ||
		attachment.DesktopSessionID != authority.DesktopSessionID || attachment.ConnectionGeneration != authority.ConnectionGeneration {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	directory, statePath, err := d.stateLocation(authority.SandboxID, authority.DesktopSessionID)
	if err != nil {
		return nil, err
	}
	_ = directory
	state, err := loadDesktopState(statePath, d.options.NetworkPolicyReference)
	if err != nil || state.Receipt.Reference != authority.AllocationReference || state.Receipt.ConnectionGeneration != authority.ConnectionGeneration || !state.Receipt.ExpiresAt.Equal(authority.HandoffExpiresAt) {
		return nil, providerdesktop.ErrDesktopNotFound
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		return nil, err
	}
	if !found || !info.running || info.paused || info.restarting || info.dead {
		return nil, providerdesktop.ErrAllocationUnknown
	}
	backend, ok := d.engine.(sessionEngine)
	if !ok {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	stream, err := backend.openSession(operationCtx, info.id)
	if err != nil {
		return nil, allocationUnknown(operationCtx, err)
	}
	session := &brokerSession{stream: stream, reader: bufio.NewReaderSize(stream, desktopbroker.SessionMaxDocument), frames: make(chan []byte, desktopbroker.SessionMaxQueue), results: make(map[string]chan desktopbroker.SessionMessage), done: make(chan struct{})}
	requestID, err := randomSessionID()
	if err != nil {
		_ = stream.Close()
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	open := desktopbroker.SessionOpen{BindingVersion: desktophandoff.BindingVersion, BindingIssuer: desktophandoff.BindingIssuer, Protocol: desktopbroker.SessionProtocolID, RequestID: requestID, Method: desktopbroker.SessionMethod,
		TenantBindingDigest: authority.TenantBindingDigest, ProviderRevisionID: authority.ProviderRevisionID, SandboxID: authority.SandboxID, DesktopSessionID: authority.DesktopSessionID,
		CapabilityProfileID: providerdesktop.CapabilityProfileID, MediaProfileID: authority.MediaProfileID, ControlProfileID: authority.ControlProfileID,
		HandoffReference: authority.HandoffReference, HandoffReferenceDigest: authority.HandoffReferenceDigest, AllocationReference: authority.AllocationReference,
		ConnectionGeneration: authority.ConnectionGeneration, ConnectionEpoch: authority.ConnectionEpoch, Fence: authority.ControllerFence,
		AuthorityExpiresAt: authority.AuthorityExpiresAt.UTC().Format(time.RFC3339Nano), HandoffExpiresAt: authority.HandoffExpiresAt.UTC().Format(time.RFC3339Nano),
		AuthorityDigest: authority.AuthorityDigest, RequestDigest: authority.RequestDigest, MediaPolicy: policy}
	document, err := desktopbroker.EncodeSession(open)
	if err != nil {
		_ = stream.Close()
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	if written, writeErr := stream.Write(document); writeErr != nil || written != len(document) {
		_ = stream.Close()
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	line, err := session.reader.ReadBytes('\n')
	if err != nil {
		_ = stream.Close()
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	var accepted desktopbroker.SessionMessage
	if desktopbroker.DecodeSession(line, &accepted) != nil || accepted.Type != desktopbroker.SessionAcceptedType || accepted.RequestID != requestID || accepted.Validate() != nil {
		_ = stream.Close()
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	go session.readLoop()
	return session, nil
}

type brokerSession struct {
	stream    io.ReadWriteCloser
	reader    *bufio.Reader
	frames    chan []byte
	done      chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex
	resultMu  sync.Mutex
	results   map[string]chan desktopbroker.SessionMessage
	sequence  atomic.Int64
}

func (s *brokerSession) readLoop() {
	defer close(s.done)
	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var message desktopbroker.SessionMessage
		if desktopbroker.DecodeSession(line, &message) != nil || message.Validate() != nil {
			return
		}
		if message.Type == desktopbroker.SessionFrameType {
			payload, err := base64.StdEncoding.DecodeString(message.Payload)
			if err != nil {
				return
			}
			select {
			case s.frames <- payload:
			default:
				return
			}
			continue
		}
		if message.Type == desktopbroker.SessionResultType {
			s.resultMu.Lock()
			result := s.results[message.RequestID]
			s.resultMu.Unlock()
			if result != nil {
				select {
				case result <- message:
				default:
				}
			}
		}
	}
}

func (s *brokerSession) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	return readSessionFrame(ctx, s.frames, s.done)
}
func (s *brokerSession) ReadAudioRTP(context.Context) ([]byte, error) {
	return nil, providerdesktop.ErrDesktopUnsupported
}

func (s *brokerSession) HandleInput(ctx context.Context, input desktopmedia.Input) (desktopmedia.InputResult, error) {
	result, err := s.command(ctx, "input", &input, nil)
	return desktopmedia.InputResult{Text: result.Text}, err
}
func (s *brokerSession) UpdateStream(ctx context.Context, display desktopmedia.DisplayPolicy, _ string) error {
	_, err := s.command(ctx, "stream.configure", nil, &display)
	return err
}
func (s *brokerSession) Resynchronize(ctx context.Context) error {
	_, err := s.command(ctx, "stream.resync", nil, nil)
	return err
}
func (s *brokerSession) RequestKeyframe(ctx context.Context) error {
	_, err := s.command(ctx, "keyframe", nil, nil)
	return err
}

func (s *brokerSession) command(ctx context.Context, kind string, input *desktopmedia.Input, display *desktopmedia.DisplayPolicy) (desktopbroker.SessionMessage, error) {
	if s == nil || ctx == nil {
		return desktopbroker.SessionMessage{}, providerdesktop.ErrDesktopUnsupported
	}
	sequence := s.sequence.Add(1)
	requestID, err := randomSessionID()
	if err != nil {
		return desktopbroker.SessionMessage{}, providerdesktop.ErrDesktopUnsupported
	}
	command := desktopbroker.SessionCommand{Protocol: desktopbroker.SessionProtocolID, Type: kind, RequestID: requestID, Sequence: sequence, Input: input, Display: display}
	document, err := desktopbroker.EncodeSession(command)
	if err != nil {
		return desktopbroker.SessionMessage{}, err
	}
	response := make(chan desktopbroker.SessionMessage, 1)
	s.resultMu.Lock()
	s.results[requestID] = response
	s.resultMu.Unlock()
	defer func() { s.resultMu.Lock(); delete(s.results, requestID); s.resultMu.Unlock() }()
	s.writeMu.Lock()
	_, err = s.stream.Write(document)
	s.writeMu.Unlock()
	if err != nil {
		return desktopbroker.SessionMessage{}, providerdesktop.ErrDesktopUnsupported
	}
	select {
	case result := <-response:
		if !result.OK {
			return result, errors.New(result.ErrorCode)
		}
		return result, nil
	case <-s.done:
		return desktopbroker.SessionMessage{}, providerdesktop.ErrDesktopUnsupported
	case <-ctx.Done():
		return desktopbroker.SessionMessage{}, ctx.Err()
	}
}

func (s *brokerSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { _ = s.stream.Close() })
	return nil
}

func readSessionFrame(ctx context.Context, frames <-chan []byte, done <-chan struct{}) ([]byte, error) {
	select {
	case frame := <-frames:
		if len(frame) == 0 {
			return nil, providerdesktop.ErrDesktopUnsupported
		}
		return append([]byte(nil), frame...), nil
	case <-done:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func randomSessionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var result strings.Builder
	for _, value := range value {
		result.WriteByte(alphabet[int(value)&31])
	}
	return "session-" + result.String(), nil
}

var _ providerdesktop.MediaRuntime = (*Driver)(nil)
