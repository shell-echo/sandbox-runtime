package desktopbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
)

func validSessionOpen() SessionOpen {
	now := time.Now().UTC()
	open := desktophandoff.OpenRequest{BindingVersion: desktophandoff.BindingVersion, BindingIssuer: desktophandoff.BindingIssuer, Protocol: desktophandoff.ProtocolID, RequestID: "open-1", Resource: desktophandoff.ResourceDesktop,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", DesktopSessionID: "desktop-1",
		CapabilityProfileID: "desktop-v1", MediaProfileID: desktophandoff.MediaProfileID, ControlProfileID: desktophandoff.ControlProfileID, HandoffReference: "ref:desktop-session:opaque-1",
		HandoffDigest: desktophandoff.ReferenceDigest("ref:desktop-session:opaque-1"), ConnectionGeneration: 2, ConnectionEpoch: "connection-1", AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), ControllerFence: strings.Repeat("b", handoff.MinFenceBytes), MediaPolicy: desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}}
	open.AuthorityDigest = desktophandoff.AuthorityDigest(open)
	open.RequestDigest = desktophandoff.RequestDigest(open)
	value := SessionOpen{
		BindingVersion: open.BindingVersion, BindingIssuer: open.BindingIssuer, Protocol: SessionProtocolID, RequestID: open.RequestID, Method: SessionMethod,
		TenantBindingDigest: open.TenantBindingDigest, ProviderRevisionID: open.ProviderRevisionID, SandboxID: open.SandboxID, DesktopSessionID: open.DesktopSessionID, CapabilityProfileID: open.CapabilityProfileID, MediaProfileID: open.MediaProfileID, ControlProfileID: open.ControlProfileID,
		HandoffReference: open.HandoffReference, HandoffReferenceDigest: open.HandoffDigest, AllocationReference: "ref:desktop/11111111111111111111111111111111", ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch, Fence: open.ControllerFence,
		AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt, AuthorityDigest: open.AuthorityDigest, RequestDigest: open.RequestDigest, MediaPolicy: open.MediaPolicy,
	}
	return value
}

func TestSessionOpenAndMessagesAreClosedAndBound(t *testing.T) {
	open := validSessionOpen()
	if err := open.Validate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SessionOpen){
		"wrong protocol": func(value *SessionOpen) { value.Protocol = ProtocolID },
		"wrong digest":   func(value *SessionOpen) { value.TenantBindingDigest = "sha256:" + strings.Repeat("a", 64) },
		"expired": func(value *SessionOpen) {
			value.AuthorityExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
		},
		"private reference": func(value *SessionOpen) { value.HandoffReference = "/tmp/socket" },
		"invalid policy":    func(value *SessionOpen) { value.MediaPolicy.VideoCodec = "video/H264" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := open
			mutate(&candidate)
			if candidate.Validate(time.Now().UTC()) == nil {
				t.Fatal("invalid session open accepted")
			}
		})
	}
	accepted := SessionMessage{Protocol: SessionProtocolID, Type: SessionAcceptedType, RequestID: open.RequestID, OK: true}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	frame := SessionMessage{Protocol: SessionProtocolID, Type: SessionFrameType, Sequence: 1, Timestamp: time.Now().UnixNano(), Payload: "gICAgICAgICAgICAgAA="}
	if err := frame.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionJSONRejectsDuplicateUnknownAndTrailingMembers(t *testing.T) {
	open := validSessionOpen()
	encoded, err := json.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(append(encoded, '\n'))
	var decoded SessionOpen
	if err := decodeSession([]byte(valid), &decoded); err != nil {
		t.Fatalf("valid session open rejected: %v", err)
	}
	for index, document := range []string{
		strings.Replace(valid, `"method":"session"`, `"method":"session","method":"session"`, 1),
		strings.Replace(valid, `"method":"session"`, `"unknown":true,"method":"session"`, 1),
		valid + `{}`,
	} {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			if err := decodeSession([]byte(document), &decoded); err == nil {
				t.Fatal("unsafe session document accepted")
			}
		})
	}
}

func TestSessionCommandRequiresStrictMonotonicSequence(t *testing.T) {
	policy := validSessionOpen().MediaPolicy
	input := desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 10, Y: 10, ControlLeaseID: "lease-1", ControlFence: 1}
	command := SessionCommand{Protocol: SessionProtocolID, Type: "input", RequestID: "input-1", Sequence: 1, Input: &input}
	if err := command.Validate(policy, 0); err != nil {
		t.Fatal(err)
	}
	if err := command.Validate(policy, 1); err == nil {
		t.Fatal("replayed sequence accepted")
	}
	command.Sequence = 2
	if err := command.Validate(policy, 1); err != nil {
		t.Fatal(err)
	}
	command.Input.Sequence = 7
	command.Sequence = 3
	if err := command.Validate(policy, 2); err != nil {
		t.Fatalf("controller event sequence must remain independent across executor reconnects: %v", err)
	}
}

func TestPointerMovesUseFixedArgumentsAndAllowRepeatedCoordinates(t *testing.T) {
	policy := validSessionOpen().MediaPolicy
	inputs := []desktopmedia.Input{
		{Sequence: 1, Kind: "pointer", Event: "move", X: 123, Y: 234, ControlLeaseID: "lease-1", ControlFence: 1},
		{Sequence: 2, Kind: "pointer", Event: "move", X: 123, Y: 234, ControlLeaseID: "lease-1", ControlFence: 2},
		{Sequence: 3, Kind: "pointer", Event: "move", X: 456, Y: 345, ControlLeaseID: "lease-1", ControlFence: 3},
		{Sequence: 4, Kind: "pointer", Event: "move", X: 0, Y: 0, ControlLeaseID: "lease-1", ControlFence: 4},
		{Sequence: 5, Kind: "pointer", Event: "move", X: policy.Width - 1, Y: policy.Height - 1, ControlLeaseID: "lease-1", ControlFence: 5},
	}
	want := [][]string{
		{"mousemove", "123", "234"},
		{"mousemove", "123", "234"},
		{"mousemove", "456", "345"},
		{"mousemove", "0", "0"},
		{"mousemove", "1279", "719"},
	}
	calls := make(chan []string, len(inputs))
	run := func(_ context.Context, args []string) error {
		calls <- append([]string(nil), args...)
		return nil
	}
	for index, input := range inputs {
		if err := executeInputWithRunner(context.Background(), input, policy, run); err != nil {
			t.Fatalf("pointer move %d: %v", index, err)
		}
	}
	close(calls)
	index := 0
	for args := range calls {
		if !reflect.DeepEqual(args, want[index]) {
			t.Fatalf("pointer arguments %d = %#v, want %#v", index, args, want[index])
		}
		index++
	}
}

func TestInputRunnerCancellationIsBounded(t *testing.T) {
	policy := validSessionOpen().MediaPolicy
	input := desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 1, Y: 2, ControlLeaseID: "lease-1", ControlFence: 1}
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- executeInputWithRunner(ctx, input, policy, func(commandContext context.Context, _ []string) error {
			close(started)
			<-commandContext.Done()
			return commandContext.Err()
		})
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("cancelled input = %v", err)
	}
}

func TestInputRunnerTimeoutAndNonzeroExitFailClosed(t *testing.T) {
	policy := validSessionOpen().MediaPolicy
	input := desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 1, Y: 2, ControlLeaseID: "lease-1", ControlFence: 1}
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	if err := executeInputWithRunner(expired, input, policy, func(commandContext context.Context, _ []string) error {
		<-commandContext.Done()
		return commandContext.Err()
	}); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("timed out input = %v", err)
	}
	if err := executeInputWithRunner(context.Background(), input, policy, func(context.Context, []string) error {
		return errInputNonzeroExit
	}); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("nonzero input command = %v", err)
	}
}

func TestInputFailureClassificationIsClosed(t *testing.T) {
	for _, test := range []struct {
		err   error
		cause sessiontermination.Cause
	}{
		{errInputTimeout, sessiontermination.CauseInputTimeout},
		{errInputNonzeroExit, sessiontermination.CauseInputNonzeroExit},
		{errInputStartFailure, sessiontermination.CauseInputStartFailure},
	} {
		if got := inputTerminationCause(test.err); got != test.cause {
			t.Fatalf("input failure %v = %s, want %s", test.err, got, test.cause)
		}
	}
}
