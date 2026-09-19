package productgateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/product"
)

var desktopKeyCodePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)

type desktopLiveActionKind struct {
	Kind string `json:"kind"`
}

type desktopLiveKeyboardAction struct {
	Kind      string   `json:"kind"`
	Event     string   `json:"event"`
	Code      string   `json:"code"`
	Key       string   `json:"key"`
	Modifiers []string `json:"modifiers"`
}

type desktopLivePointerAction struct {
	Kind   string `json:"kind"`
	Event  string `json:"event"`
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Button int    `json:"button"`
	DeltaX int    `json:"delta_x"`
	DeltaY int    `json:"delta_y"`
}

type desktopLiveTouchAction struct {
	Kind   string                  `json:"kind"`
	Event  string                  `json:"event"`
	Points []DesktopLiveTouchPoint `json:"points"`
}

func decodeDesktopLiveInput(payload []byte, media DesktopLiveMediaPolicy, binding product.GatewayBinding) (DesktopLiveInput, error) {
	if len(payload) == 0 || rejectDuplicateAutomationMembers(payload) != nil {
		return DesktopLiveInput{}, product.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope desktopLiveControlEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return DesktopLiveInput{}, product.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || envelope.Type != "input" || envelope.Sequence < 1 || envelope.Sequence > maxAutomationSequence || len(envelope.Action) < 2 || binding.ControlLeaseID == "" || binding.ControlFence < 1 {
		return DesktopLiveInput{}, product.ErrInvalid
	}
	input := DesktopLiveInput{Sequence: envelope.Sequence, ControlLeaseID: binding.ControlLeaseID, ControlFence: binding.ControlFence}
	var discriminator desktopLiveActionKind
	if err := json.Unmarshal(envelope.Action, &discriminator); err != nil {
		return DesktopLiveInput{}, product.ErrInvalid
	}
	switch discriminator.Kind {
	case "keyboard":
		var action desktopLiveKeyboardAction
		if decodeStrictRaw(envelope.Action, &action) != nil || (action.Event != "down" && action.Event != "up") || !desktopKeyCodePattern.MatchString(action.Code) || !utf8.ValidString(action.Key) || utf8.RuneCountInString(action.Key) < 1 || utf8.RuneCountInString(action.Key) > 16 || !validDesktopModifiers(action.Modifiers) {
			return DesktopLiveInput{}, product.ErrInvalid
		}
		input.Kind, input.Event, input.Code, input.Key, input.Modifiers = action.Kind, action.Event, action.Code, action.Key, append([]string(nil), action.Modifiers...)
	case "pointer":
		var action desktopLivePointerAction
		if decodeStrictRaw(envelope.Action, &action) != nil || !slices.Contains([]string{"move", "down", "up", "wheel"}, action.Event) || action.X < 0 || action.X >= media.Width || action.Y < 0 || action.Y >= media.Height || action.Button < 0 || action.Button > 4 || action.DeltaX < -4096 || action.DeltaX > 4096 || action.DeltaY < -4096 || action.DeltaY > 4096 || (action.Event != "wheel" && (action.DeltaX != 0 || action.DeltaY != 0)) {
			return DesktopLiveInput{}, product.ErrInvalid
		}
		input.Kind, input.Event, input.X, input.Y, input.Button, input.DeltaX, input.DeltaY = action.Kind, action.Event, action.X, action.Y, action.Button, action.DeltaX, action.DeltaY
	case "touch":
		var action desktopLiveTouchAction
		if decodeStrictRaw(envelope.Action, &action) != nil || !slices.Contains([]string{"start", "move", "end"}, action.Event) || len(action.Points) < 1 || len(action.Points) > 10 || !validDesktopTouchPoints(action.Points, media) {
			return DesktopLiveInput{}, product.ErrInvalid
		}
		input.Kind, input.Event, input.Touches = action.Kind, action.Event, append([]DesktopLiveTouchPoint(nil), action.Points...)
	default:
		return DesktopLiveInput{}, product.ErrInvalid
	}
	return input, nil
}

func validDesktopModifiers(modifiers []string) bool {
	if len(modifiers) > 4 {
		return false
	}
	previous := ""
	for _, modifier := range modifiers {
		if !slices.Contains([]string{"alt", "control", "meta", "shift"}, modifier) || modifier <= previous {
			return false
		}
		previous = modifier
	}
	return true
}

func validDesktopTouchPoints(points []DesktopLiveTouchPoint, media DesktopLiveMediaPolicy) bool {
	seen := make(map[int]struct{}, len(points))
	for _, point := range points {
		if point.ID < 0 || point.ID > 31 || point.X < 0 || point.X >= media.Width || point.Y < 0 || point.Y >= media.Height {
			return false
		}
		if _, duplicate := seen[point.ID]; duplicate {
			return false
		}
		seen[point.ID] = struct{}{}
	}
	return true
}
