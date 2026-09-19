package desktopmedia

import (
	"strings"
	"testing"
)

func TestMediaPolicyAndInputProtocolAreClosedAndBounded(t *testing.T) {
	policy := MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000}
	if !policy.Validate() {
		t.Fatal("valid private Desktop media policy rejected")
	}
	for _, invalid := range []MediaPolicy{
		{},
		{VideoCodec: "video/H264", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000},
		{VideoCodec: "video/VP8", Width: 1281, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000},
		{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, AudioCodec: "audio/opus"},
	} {
		if invalid.Validate() {
			t.Fatalf("invalid policy accepted: %#v", invalid)
		}
	}
	base := Input{Sequence: 1, ControlLeaseID: "ctl-desktop-private", ControlFence: 3}
	valid := []Input{
		func() Input {
			value := base
			value.Kind, value.Event, value.Code, value.Key = "keyboard", "down", "KeyA", "a"
			return value
		}(),
		func() Input {
			value := base
			value.Kind, value.Event, value.X, value.Y = "pointer", "move", 100, 120
			return value
		}(),
		func() Input {
			value := base
			value.Kind, value.Event, value.Touches = "touch", "start", []TouchPoint{{ID: 1, X: 100, Y: 120}}
			return value
		}(),
		func() Input { value := base; value.Kind = "clipboard.read"; return value }(),
		func() Input { value := base; value.Kind, value.Text = "clipboard.write", "hello"; return value }(),
		func() Input {
			value := base
			value.Kind = "transfer.upload"
			value.Files = []TransferFile{{TransferID: "xfer-private", Path: "/workspace/file.txt", MediaType: "text/plain", Digest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 5}}
			return value
		}(),
	}
	for _, input := range valid {
		if !ValidInput(input, policy) {
			t.Fatalf("valid input rejected: %#v", input)
		}
	}
	invalid := []Input{
		{},
		func() Input { value := base; value.Kind = "microphone"; return value }(),
		func() Input { value := base; value.Kind, value.Event, value.X = "pointer", "move", 1280; return value }(),
		func() Input {
			value := base
			value.Kind, value.Event, value.Code, value.Key = "keyboard", "down", "bad code", "a"
			return value
		}(),
		func() Input {
			value := base
			value.Kind, value.Text = "clipboard.write", strings.Repeat("x", 16<<10+1)
			return value
		}(),
		func() Input {
			value := base
			value.Kind = "transfer.download"
			value.Files = []TransferFile{{TransferID: "xfer-private", Path: "/workspace/../secret", MediaType: "text/plain", Digest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 5}}
			return value
		}(),
	}
	for _, input := range invalid {
		if ValidInput(input, policy) {
			t.Fatalf("invalid input accepted: %#v", input)
		}
	}
}
