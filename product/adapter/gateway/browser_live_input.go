package productgateway

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/product"
)

var browserKeyCodePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)

type browserLiveActionKind struct {
	Kind string `json:"kind"`
}

type browserLiveKeyboardAction struct {
	Kind              string   `json:"kind"`
	Event             string   `json:"event"`
	Code              string   `json:"code"`
	Key               string   `json:"key"`
	Modifiers         []string `json:"modifiers"`
	HasUserActivation bool     `json:"user_activation"`
}

type browserLivePointerAction struct {
	Kind              string `json:"kind"`
	Event             string `json:"event"`
	X                 int    `json:"x"`
	Y                 int    `json:"y"`
	Button            int    `json:"button"`
	DeltaX            int    `json:"delta_x"`
	DeltaY            int    `json:"delta_y"`
	HasUserActivation bool   `json:"user_activation"`
}

type browserLiveTouchAction struct {
	Kind              string                  `json:"kind"`
	Event             string                  `json:"event"`
	Points            []BrowserLiveTouchPoint `json:"points"`
	HasUserActivation bool                    `json:"user_activation"`
}

type browserLiveClipboardReadAction struct {
	Kind              string `json:"kind"`
	HasUserActivation bool   `json:"user_activation"`
	Consent           bool   `json:"consent"`
}

type browserLiveClipboardWriteAction struct {
	Kind              string `json:"kind"`
	Text              string `json:"text"`
	HasUserActivation bool   `json:"user_activation"`
	Consent           bool   `json:"consent"`
}

type browserLiveTransferAction struct {
	Kind              string                        `json:"kind"`
	Files             []product.BrowserTransferFile `json:"files"`
	HasUserActivation bool                          `json:"user_activation"`
	Consent           bool                          `json:"consent"`
}

type browserLiveNavigationAction struct {
	Kind              string `json:"kind"`
	SourceOrigin      string `json:"source_origin"`
	TargetURL         string `json:"target_url"`
	HasUserActivation bool   `json:"user_activation"`
}

type browserLivePopupAction struct {
	Kind              string `json:"kind"`
	SourceOrigin      string `json:"source_origin"`
	TargetURL         string `json:"target_url"`
	OpenPopupCount    int    `json:"open_popup_count"`
	HasUserActivation bool   `json:"user_activation"`
}

type browserLivePermissionAction struct {
	Kind              string `json:"kind"`
	Permission        string `json:"permission"`
	HasUserActivation bool   `json:"user_activation"`
	Consent           bool   `json:"consent"`
}

func decodeBrowserLiveAction(document json.RawMessage, video BrowserLiveVideoPolicy, input *BrowserLiveInput) error { //nolint:cyclop
	var discriminator browserLiveActionKind
	if err := json.Unmarshal(document, &discriminator); err != nil || input == nil {
		return product.ErrInvalid
	}
	switch discriminator.Kind {
	case "keyboard":
		var action browserLiveKeyboardAction
		if decodeStrictRaw(document, &action) != nil || (action.Event != "down" && action.Event != "up") || !browserKeyCodePattern.MatchString(action.Code) || !utf8.ValidString(action.Key) || utf8.RuneCountInString(action.Key) < 1 || utf8.RuneCountInString(action.Key) > 16 || !validBrowserModifiers(action.Modifiers) {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: product.BrowserActionKeyboard, HasUserActivation: action.HasUserActivation}
		input.Event, input.Code, input.Key, input.Modifiers = action.Event, action.Code, action.Key, append([]string(nil), action.Modifiers...)
	case "pointer":
		var action browserLivePointerAction
		if decodeStrictRaw(document, &action) != nil || !slices.Contains([]string{"move", "down", "up", "wheel"}, action.Event) || action.X < 0 || action.X >= video.Width || action.Y < 0 || action.Y >= video.Height || action.Button < 0 || action.Button > 4 || action.DeltaX < -4096 || action.DeltaX > 4096 || action.DeltaY < -4096 || action.DeltaY > 4096 || (action.Event != "wheel" && (action.DeltaX != 0 || action.DeltaY != 0)) {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: product.BrowserActionPointer, HasUserActivation: action.HasUserActivation}
		input.Event, input.X, input.Y, input.Button, input.DeltaX, input.DeltaY = action.Event, action.X, action.Y, action.Button, action.DeltaX, action.DeltaY
	case "touch":
		var action browserLiveTouchAction
		if decodeStrictRaw(document, &action) != nil || !slices.Contains([]string{"start", "move", "end"}, action.Event) || len(action.Points) < 1 || len(action.Points) > 10 || !validBrowserTouchPoints(action.Points, video) {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: product.BrowserActionTouch, TouchPoints: len(action.Points), HasUserActivation: action.HasUserActivation}
		input.Event, input.Touches = action.Event, append([]BrowserLiveTouchPoint(nil), action.Points...)
	case product.BrowserActionClipboardRead:
		var action browserLiveClipboardReadAction
		if decodeStrictRaw(document, &action) != nil {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: action.Kind, HasUserActivation: action.HasUserActivation, Consent: action.Consent}
	case product.BrowserActionClipboardWrite:
		var action browserLiveClipboardWriteAction
		if decodeStrictRaw(document, &action) != nil || !utf8.ValidString(action.Text) {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: action.Kind, Text: action.Text, HasUserActivation: action.HasUserActivation, Consent: action.Consent}
	case product.BrowserActionUpload, product.BrowserActionDownload:
		var action browserLiveTransferAction
		if decodeStrictRaw(document, &action) != nil || len(action.Files) > product.MaxBrowserTransferFiles {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: action.Kind, Files: append([]product.BrowserTransferFile(nil), action.Files...), HasUserActivation: action.HasUserActivation, Consent: action.Consent}
	case product.BrowserActionNavigate:
		var action browserLiveNavigationAction
		if decodeStrictRaw(document, &action) != nil {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: action.Kind, SourceOrigin: action.SourceOrigin, TargetURL: action.TargetURL, HasUserActivation: action.HasUserActivation}
	case product.BrowserActionPopup:
		var action browserLivePopupAction
		if decodeStrictRaw(document, &action) != nil {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: action.Kind, SourceOrigin: action.SourceOrigin, TargetURL: action.TargetURL, OpenPopupCount: action.OpenPopupCount, HasUserActivation: action.HasUserActivation}
	case product.BrowserActionPermission:
		var action browserLivePermissionAction
		if decodeStrictRaw(document, &action) != nil {
			return product.ErrInvalid
		}
		input.Action = product.BrowserPolicyAction{Kind: action.Kind, Permission: action.Permission, HasUserActivation: action.HasUserActivation, Consent: action.Consent}
	default:
		return product.ErrInvalid
	}
	return nil
}

func validBrowserModifiers(modifiers []string) bool {
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

func validBrowserTouchPoints(points []BrowserLiveTouchPoint, video BrowserLiveVideoPolicy) bool {
	seen := make(map[int]struct{}, len(points))
	for _, point := range points {
		if point.ID < 0 || point.ID > 31 || point.X < 0 || point.X >= video.Width || point.Y < 0 || point.Y >= video.Height {
			return false
		}
		if _, duplicate := seen[point.ID]; duplicate {
			return false
		}
		seen[point.ID] = struct{}{}
	}
	return true
}

// ProductTransferBrowserAuthority binds transfer metadata in a Browser input
// to an already authorized Product transfer. It never returns object references.
type ProductTransferBrowserAuthority struct {
	Store BrowserTransferRecordStore
}

type BrowserTransferRecordStore interface {
	GetTransfer(context.Context, string, product.ActorRef, string) (product.TransferRecord, error)
}

func (a *ProductTransferBrowserAuthority) AuthorizeBrowserTransfer(ctx context.Context, binding product.GatewayBinding, action product.BrowserPolicyAction) error {
	if a == nil || nilInterface(a.Store) || (action.Kind != product.BrowserActionUpload && action.Kind != product.BrowserActionDownload) {
		return product.ErrForbidden
	}
	direction := "upload"
	if action.Kind == product.BrowserActionDownload {
		direction = "download"
	}
	for _, file := range action.Files {
		record, err := a.Store.GetTransfer(ctx, binding.TenantID, binding.Actor, file.TransferID)
		if err != nil || record.WorkspaceID != binding.WorkspaceID || record.Direction != direction || record.State != "complete" || record.Digest != file.Digest || record.SizeBytes != file.SizeBytes {
			return product.ErrForbidden
		}
	}
	return nil
}

type denyBrowserTransferAuthority struct{}

func (denyBrowserTransferAuthority) AuthorizeBrowserTransfer(context.Context, product.GatewayBinding, product.BrowserPolicyAction) error {
	return product.ErrForbidden
}

var _ BrowserLiveTransferAuthority = (*ProductTransferBrowserAuthority)(nil)
var _ BrowserLiveTransferAuthority = denyBrowserTransferAuthority{}
