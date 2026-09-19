// Package desktopmedia owns the closed repository-private wire shapes shared
// by the Provider Desktop ingress and the Product Gateway network adapter. It
// contains no Product or Provider business authority.
package desktopmedia

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	Subprotocol = "sandbox-desktop-private-media.v1"
	VideoPacket = byte(1)
	AudioPacket = byte(2)
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	keyCodePattern    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type MediaPolicy struct {
	VideoCodec          string `json:"video_codec"`
	Width               int    `json:"width"`
	Height              int    `json:"height"`
	MaxFPS              int    `json:"max_fps"`
	MaxVideoBitrateKbps int    `json:"max_video_bitrate_kbps"`
	AudioCodec          string `json:"audio_codec,omitempty"`
	MaxAudioBitrateKbps int    `json:"max_audio_bitrate_kbps,omitempty"`
}

func (p MediaPolicy) Validate() bool {
	if p.VideoCodec != "video/VP8" || p.Width < 320 || p.Width > 1280 || p.Height < 240 || p.Height > 720 ||
		p.MaxFPS < 1 || p.MaxFPS > 60 || p.MaxVideoBitrateKbps < 128 || p.MaxVideoBitrateKbps > 8000 {
		return false
	}
	return (p.AudioCodec == "" && p.MaxAudioBitrateKbps == 0) ||
		(p.AudioCodec == "audio/opus" && p.MaxAudioBitrateKbps >= 16 && p.MaxAudioBitrateKbps <= 256)
}

type DisplayPolicy struct {
	Width  int `json:"width"`
	Height int `json:"height"`
	MaxFPS int `json:"max_fps"`
}

type TouchPoint struct {
	ID int `json:"id"`
	X  int `json:"x"`
	Y  int `json:"y"`
}

type TransferFile struct {
	TransferID string `json:"transfer_id"`
	Path       string `json:"path"`
	MediaType  string `json:"media_type"`
	Digest     string `json:"digest"`
	SizeBytes  int64  `json:"size_bytes"`
}

type Input struct {
	Sequence       int64          `json:"sequence"`
	Kind           string         `json:"kind"`
	Event          string         `json:"event,omitempty"`
	Code           string         `json:"code,omitempty"`
	Key            string         `json:"key,omitempty"`
	Modifiers      []string       `json:"modifiers,omitempty"`
	X              int            `json:"x,omitempty"`
	Y              int            `json:"y,omitempty"`
	Button         int            `json:"button,omitempty"`
	DeltaX         int            `json:"delta_x,omitempty"`
	DeltaY         int            `json:"delta_y,omitempty"`
	Touches        []TouchPoint   `json:"touches,omitempty"`
	Text           string         `json:"text,omitempty"`
	Files          []TransferFile `json:"files,omitempty"`
	ControlLeaseID string         `json:"control_lease_id"`
	ControlFence   int64          `json:"control_fence"`
}

type InputResult struct {
	Text string `json:"text,omitempty"`
}

type Command struct {
	Type        string         `json:"type"`
	RequestID   int64          `json:"request_id"`
	Input       *Input         `json:"input,omitempty"`
	Display     *DisplayPolicy `json:"display,omitempty"`
	AudioDevice string         `json:"audio_device,omitempty"`
}

type Result struct {
	Type      string `json:"type"`
	RequestID int64  `json:"request_id"`
	OK        bool   `json:"ok"`
	Text      string `json:"text,omitempty"`
}

func ValidInput(input Input, policy MediaPolicy) bool { //nolint:cyclop
	if input.Sequence < 1 || input.Sequence > 1<<53-1 || !identifierPattern.MatchString(input.ControlLeaseID) || input.ControlFence < 1 {
		return false
	}
	noPointer := input.X == 0 && input.Y == 0 && input.Button == 0 && input.DeltaX == 0 && input.DeltaY == 0
	noKeyboard := input.Code == "" && input.Key == "" && len(input.Modifiers) == 0
	noPayload := input.Text == "" && len(input.Files) == 0
	switch input.Kind {
	case "keyboard":
		if (input.Event != "down" && input.Event != "up") || !keyCodePattern.MatchString(input.Code) || !utf8.ValidString(input.Key) || utf8.RuneCountInString(input.Key) < 1 || utf8.RuneCountInString(input.Key) > 16 || !noPointer || len(input.Touches) != 0 || !noPayload {
			return false
		}
		previous := ""
		for _, modifier := range input.Modifiers {
			if !slices.Contains([]string{"alt", "control", "meta", "shift"}, modifier) || modifier <= previous {
				return false
			}
			previous = modifier
		}
		return len(input.Modifiers) <= 4
	case "pointer":
		return slices.Contains([]string{"move", "down", "up", "wheel"}, input.Event) && noKeyboard && len(input.Touches) == 0 && noPayload &&
			input.X >= 0 && input.X < policy.Width && input.Y >= 0 && input.Y < policy.Height && input.Button >= 0 && input.Button <= 4 &&
			input.DeltaX >= -4096 && input.DeltaX <= 4096 && input.DeltaY >= -4096 && input.DeltaY <= 4096 &&
			(input.Event == "wheel" || input.DeltaX == 0 && input.DeltaY == 0)
	case "touch":
		if !slices.Contains([]string{"start", "move", "end"}, input.Event) || !noKeyboard || !noPointer || !noPayload || len(input.Touches) < 1 || len(input.Touches) > 10 {
			return false
		}
		seen := make(map[int]struct{}, len(input.Touches))
		for _, point := range input.Touches {
			if point.ID < 0 || point.ID > 31 || point.X < 0 || point.X >= policy.Width || point.Y < 0 || point.Y >= policy.Height {
				return false
			}
			if _, duplicate := seen[point.ID]; duplicate {
				return false
			}
			seen[point.ID] = struct{}{}
		}
		return true
	case "clipboard.read":
		return input.Event == "" && noKeyboard && noPointer && len(input.Touches) == 0 && noPayload
	case "clipboard.write":
		return input.Event == "" && noKeyboard && noPointer && len(input.Touches) == 0 && len(input.Files) == 0 && utf8.ValidString(input.Text) && len(input.Text) <= 16<<10
	case "transfer.upload", "transfer.download":
		if input.Event != "" || !noKeyboard || !noPointer || len(input.Touches) != 0 || input.Text != "" || len(input.Files) < 1 || len(input.Files) > 16 {
			return false
		}
		var total int64
		for _, file := range input.Files {
			if !identifierPattern.MatchString(file.TransferID) || !strings.HasPrefix(file.Path, "/workspace/") || len(file.Path) > 1024 || strings.Contains(file.Path, "..") || file.MediaType == "" || len(file.MediaType) > 127 || !digestPattern.MatchString(file.Digest) || file.SizeBytes < 0 || file.SizeBytes > 1<<30 {
				return false
			}
			total += file.SizeBytes
			if total > 1<<30 {
				return false
			}
		}
		return true
	default:
		return false
	}
}
