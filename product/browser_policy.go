package product

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	BrowserActionKeyboard        = "keyboard"
	BrowserActionPointer         = "pointer"
	BrowserActionTouch           = "touch"
	BrowserActionClipboardRead   = "clipboard.read"
	BrowserActionClipboardWrite  = "clipboard.write"
	BrowserActionUpload          = "upload"
	BrowserActionDownload        = "download"
	BrowserActionNavigate        = "navigate"
	BrowserActionPopup           = "popup"
	BrowserActionPermission      = "permission"
	MaxBrowserClipboardBytes     = 64 << 10
	MaxBrowserTransferFiles      = 16
	MaxBrowserPolicyTransferByte = int64(1 << 30)
)

var browserPermissions = []string{
	"camera", "clipboard-read", "clipboard-write", "geolocation", "microphone", "notifications",
}

type BrowserInputPolicy struct {
	Keyboard bool
	Pointer  bool
	Touch    bool
}

type BrowserClipboardPolicy struct {
	Read, Write       bool
	MaxBytes          int
	RequireActivation bool
	RequireConsent    bool
}

type BrowserTransferPolicy struct {
	Enabled           bool
	MaxFiles          int
	MaxFileBytes      int64
	MaxTotalBytes     int64
	AllowedMediaTypes []string
	RequireActivation bool
	RequireConsent    bool
}

type BrowserNavigationPolicy struct {
	AllowedOrigins   []string
	AllowCrossOrigin bool
}

type BrowserPopupPolicy struct {
	Enabled           bool
	MaxOpen           int
	RequireActivation bool
}

type BrowserPermissionPolicy struct {
	Allowed           []string
	RequireActivation bool
	RequireConsent    bool
}

// BrowserPolicy is an immutable, versioned Product policy snapshot. Its zero
// value denies every Browser mutation.
type BrowserPolicy struct {
	Revision    int64
	Input       BrowserInputPolicy
	Clipboard   BrowserClipboardPolicy
	Upload      BrowserTransferPolicy
	Download    BrowserTransferPolicy
	Navigation  BrowserNavigationPolicy
	Popup       BrowserPopupPolicy
	Permissions BrowserPermissionPolicy
}

type BrowserTransferFile struct {
	TransferID string `json:"transfer_id"`
	Name       string `json:"name"`
	MediaType  string `json:"media_type"`
	Digest     string `json:"digest"`
	SizeBytes  int64  `json:"size_bytes"`
}

type BrowserPolicyAction struct {
	Kind              string
	SourceOrigin      string
	TargetURL         string
	Text              string
	Permission        string
	TouchPoints       int
	OpenPopupCount    int
	HasUserActivation bool
	Consent           bool
	Files             []BrowserTransferFile
}

type BrowserPolicySource interface {
	CurrentBrowserPolicy(context.Context, GatewayBinding) (BrowserPolicy, error)
}

func (p BrowserPolicy) Validate() error {
	if p.Revision < 1 || p.Clipboard.MaxBytes < 0 || p.Clipboard.MaxBytes > MaxBrowserClipboardBytes {
		return ErrInvalid
	}
	if err := validateBrowserTransferPolicy(p.Upload); err != nil {
		return err
	}
	if err := validateBrowserTransferPolicy(p.Download); err != nil {
		return err
	}
	if len(p.Navigation.AllowedOrigins) > 64 || p.Popup.MaxOpen < 0 || p.Popup.MaxOpen > 16 || len(p.Permissions.Allowed) > len(browserPermissions) {
		return ErrInvalid
	}
	previous := ""
	for _, origin := range p.Navigation.AllowedOrigins {
		if canonicalBrowserOrigin(origin) != origin || origin <= previous {
			return ErrInvalid
		}
		previous = origin
	}
	previous = ""
	for _, permission := range p.Permissions.Allowed {
		if !slices.Contains(browserPermissions, permission) || permission <= previous {
			return ErrInvalid
		}
		previous = permission
	}
	return nil
}

func validateBrowserTransferPolicy(policy BrowserTransferPolicy) error {
	if policy.MaxFiles < 0 || policy.MaxFiles > MaxBrowserTransferFiles || policy.MaxFileBytes < 0 || policy.MaxFileBytes > MaxBrowserPolicyTransferByte || policy.MaxTotalBytes < 0 || policy.MaxTotalBytes > MaxBrowserPolicyTransferByte || len(policy.AllowedMediaTypes) > 32 {
		return ErrInvalid
	}
	previous := ""
	for _, mediaType := range policy.AllowedMediaTypes {
		if !validBrowserMediaType(mediaType) || mediaType <= previous {
			return ErrInvalid
		}
		previous = mediaType
	}
	return nil
}

func (p BrowserPolicy) Authorize(action BrowserPolicyAction) error { //nolint:cyclop
	if p.Validate() != nil {
		return ErrForbidden
	}
	switch action.Kind {
	case BrowserActionKeyboard:
		if p.Input.Keyboard {
			return nil
		}
	case BrowserActionPointer:
		if p.Input.Pointer {
			return nil
		}
	case BrowserActionTouch:
		if p.Input.Touch && action.TouchPoints >= 1 && action.TouchPoints <= 10 {
			return nil
		}
	case BrowserActionClipboardRead:
		if p.Clipboard.Read && action.Text == "" && browserActivationConsent(p.Clipboard.RequireActivation, p.Clipboard.RequireConsent, action) {
			return nil
		}
	case BrowserActionClipboardWrite:
		if p.Clipboard.Write && utf8.ValidString(action.Text) && len(action.Text) <= p.Clipboard.MaxBytes && browserActivationConsent(p.Clipboard.RequireActivation, p.Clipboard.RequireConsent, action) {
			return nil
		}
	case BrowserActionUpload:
		return authorizeBrowserTransfer(p.Upload, action)
	case BrowserActionDownload:
		return authorizeBrowserTransfer(p.Download, action)
	case BrowserActionNavigate:
		if authorizeBrowserNavigation(p.Navigation, action.SourceOrigin, action.TargetURL) == nil {
			return nil
		}
	case BrowserActionPopup:
		if p.Popup.Enabled && action.OpenPopupCount >= 0 && action.OpenPopupCount < p.Popup.MaxOpen && (!p.Popup.RequireActivation || action.HasUserActivation) && authorizeBrowserNavigation(p.Navigation, action.SourceOrigin, action.TargetURL) == nil {
			return nil
		}
	case BrowserActionPermission:
		if slices.Contains(p.Permissions.Allowed, action.Permission) && browserActivationConsent(p.Permissions.RequireActivation, p.Permissions.RequireConsent, action) {
			return nil
		}
	}
	return ErrForbidden
}

func browserActivationConsent(requireActivation, requireConsent bool, action BrowserPolicyAction) bool {
	return (!requireActivation || action.HasUserActivation) && (!requireConsent || action.Consent)
}

func authorizeBrowserTransfer(policy BrowserTransferPolicy, action BrowserPolicyAction) error {
	if !policy.Enabled || !browserActivationConsent(policy.RequireActivation, policy.RequireConsent, action) || len(action.Files) < 1 || len(action.Files) > policy.MaxFiles {
		return ErrForbidden
	}
	var total int64
	seenNames := make(map[string]struct{}, len(action.Files))
	for _, file := range action.Files {
		if !validIdentifier(file.TransferID) || !validBrowserFilename(file.Name) || !slices.Contains(policy.AllowedMediaTypes, file.MediaType) || !validDigest(file.Digest) || file.SizeBytes < 0 || file.SizeBytes > policy.MaxFileBytes {
			return ErrForbidden
		}
		if _, duplicate := seenNames[file.Name]; duplicate {
			return ErrForbidden
		}
		seenNames[file.Name] = struct{}{}
		total += file.SizeBytes
		if total < 0 || total > policy.MaxTotalBytes {
			return ErrForbidden
		}
	}
	return nil
}

func authorizeBrowserNavigation(policy BrowserNavigationPolicy, sourceOrigin, targetURL string) error {
	source := canonicalBrowserOrigin(sourceOrigin)
	target := browserURLOrigin(targetURL)
	if source == "" || target == "" || !slices.Contains(policy.AllowedOrigins, target) || (!policy.AllowCrossOrigin && source != target) {
		return ErrForbidden
	}
	return nil
}

func canonicalBrowserOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func browserURLOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || len(value) > 2048 {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func validBrowserFilename(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= 255 && value != "." && value != ".." && !strings.ContainsAny(value, "/\\\x00\r\n")
}

func validBrowserMediaType(value string) bool {
	if len(value) < 3 || len(value) > 127 || strings.Count(value, "/") != 1 || strings.ContainsAny(value, " ;\t\r\n") {
		return false
	}
	parts := strings.Split(value, "/")
	return parts[0] != "" && parts[1] != ""
}
