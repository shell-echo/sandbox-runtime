package product

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	DesktopActionKeyboard       = "keyboard"
	DesktopActionPointer        = "pointer"
	DesktopActionTouch          = "touch"
	DesktopActionClipboardRead  = "clipboard.read"
	DesktopActionClipboardWrite = "clipboard.write"
	DesktopActionUpload         = "transfer.upload"
	DesktopActionDownload       = "transfer.download"
	DesktopActionMicrophone     = "microphone"
	DesktopActionCamera         = "camera"
	DesktopActionDevice         = "device"

	MaxDesktopClipboardBytes     = 16 << 10
	MaxDesktopTransferFiles      = 16
	MaxDesktopPolicyTransferByte = int64(1 << 30)
	MaxDesktopTransferPathBytes  = 1024
)

type DesktopInputPolicy struct {
	Keyboard          bool `json:"keyboard"`
	Pointer           bool `json:"pointer"`
	Touch             bool `json:"touch"`
	RequireActivation bool `json:"require_activation"`
}

type DesktopClipboardPolicy struct {
	Read              bool `json:"read"`
	Write             bool `json:"write"`
	MaxBytes          int  `json:"max_bytes"`
	RequireActivation bool `json:"require_activation"`
	RequireConsent    bool `json:"require_consent"`
}

type DesktopTransferPolicy struct {
	Enabled           bool     `json:"enabled"`
	MaxFiles          int      `json:"max_files"`
	MaxFileBytes      int64    `json:"max_file_bytes"`
	MaxTotalBytes     int64    `json:"max_total_bytes"`
	AllowedMediaTypes []string `json:"allowed_media_types"`
	RequireActivation bool     `json:"require_activation"`
	RequireConsent    bool     `json:"require_consent"`
}

// DesktopPolicy is an immutable Product policy snapshot. Its zero-value
// permissions deny every Desktop mutation; a persisted snapshot has a
// positive revision so an established connection can fail closed on change.
type DesktopPolicy struct {
	Revision  int64                  `json:"revision"`
	Input     DesktopInputPolicy     `json:"input"`
	Clipboard DesktopClipboardPolicy `json:"clipboard"`
	Upload    DesktopTransferPolicy  `json:"upload"`
	Download  DesktopTransferPolicy  `json:"download"`
}

type DesktopTransferFile struct {
	TransferID string `json:"transfer_id"`
	Path       string `json:"path"`
	MediaType  string `json:"media_type"`
	Digest     string `json:"digest"`
	SizeBytes  int64  `json:"size_bytes"`
}

type DesktopPolicyAction struct {
	Kind              string
	Text              string
	TouchPoints       int
	HasUserActivation bool
	Consent           bool
	Files             []DesktopTransferFile
}

type DesktopPolicySource interface {
	CurrentDesktopPolicy(context.Context, GatewayBinding) (DesktopPolicy, error)
}

type DesktopPolicyCommand struct {
	TenantID, WorkspaceID, IdempotencyKey, Path, AuditID string
	Actor                                                ActorRef
	ExpectedRevision                                     int64
	RequestDigest                                        [32]byte
	Policy                                               DesktopPolicy
}

type DesktopPolicyStore interface {
	PutDesktopPolicy(context.Context, DesktopPolicyCommand) (DesktopPolicy, bool, error)
	DesktopPolicySource
}

type DesktopPolicyService struct {
	store DesktopPolicyStore
	ids   IDGenerator
}

func NewDesktopPolicyService(store DesktopPolicyStore, ids IDGenerator) (*DesktopPolicyService, error) {
	if nilInterface(store) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &DesktopPolicyService{store: store, ids: ids}, nil
}

func (s *DesktopPolicyService) Put(ctx context.Context, tenantID string, actor ActorRef, workspaceID, idempotencyKey string, expectedRevision int64, policy DesktopPolicy) (DesktopPolicy, bool, error) {
	if s == nil || nilInterface(s.store) || nilInterface(s.ids) {
		return DesktopPolicy{}, false, ErrStoreUnavailable
	}
	if ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdempotencyKey(idempotencyKey) || expectedRevision < 0 || policy.Revision != expectedRevision+1 || policy.Validate() != nil {
		return DesktopPolicy{}, false, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return DesktopPolicy{}, false, err
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return DesktopPolicy{}, false, ErrStoreUnavailable
	}
	document, err := json.Marshal(policy)
	if err != nil {
		return DesktopPolicy{}, false, ErrInvalid
	}
	return s.store.PutDesktopPolicy(ctx, DesktopPolicyCommand{
		TenantID: tenantID, WorkspaceID: workspaceID, Actor: actor,
		IdempotencyKey: idempotencyKey, Path: "/internal/workspaces/" + workspaceID + "/desktop-policy",
		AuditID: auditID, ExpectedRevision: expectedRevision, RequestDigest: sha256.Sum256(document), Policy: policy,
	})
}

func (p DesktopPolicy) Validate() error {
	if p.Revision < 1 || p.Clipboard.MaxBytes < 0 || p.Clipboard.MaxBytes > MaxDesktopClipboardBytes {
		return ErrInvalid
	}
	if err := validateDesktopTransferPolicy(p.Upload); err != nil {
		return err
	}
	return validateDesktopTransferPolicy(p.Download)
}

func validateDesktopTransferPolicy(policy DesktopTransferPolicy) error {
	if policy.MaxFiles < 0 || policy.MaxFiles > MaxDesktopTransferFiles || policy.MaxFileBytes < 0 || policy.MaxFileBytes > MaxDesktopPolicyTransferByte || policy.MaxTotalBytes < 0 || policy.MaxTotalBytes > MaxDesktopPolicyTransferByte || len(policy.AllowedMediaTypes) > 32 {
		return ErrInvalid
	}
	previous := ""
	for _, mediaType := range policy.AllowedMediaTypes {
		if !validDesktopMediaType(mediaType) || mediaType <= previous {
			return ErrInvalid
		}
		previous = mediaType
	}
	return nil
}

func (p DesktopPolicy) Authorize(action DesktopPolicyAction) error { //nolint:cyclop
	if p.Validate() != nil {
		return ErrForbidden
	}
	switch action.Kind {
	case DesktopActionKeyboard:
		if p.Input.Keyboard && (!p.Input.RequireActivation || action.HasUserActivation) {
			return nil
		}
	case DesktopActionPointer:
		if p.Input.Pointer && (!p.Input.RequireActivation || action.HasUserActivation) {
			return nil
		}
	case DesktopActionTouch:
		if p.Input.Touch && action.TouchPoints >= 1 && action.TouchPoints <= 10 && (!p.Input.RequireActivation || action.HasUserActivation) {
			return nil
		}
	case DesktopActionClipboardRead:
		if p.Clipboard.Read && action.Text == "" && desktopActivationConsent(p.Clipboard.RequireActivation, p.Clipboard.RequireConsent, action) {
			return nil
		}
	case DesktopActionClipboardWrite:
		if p.Clipboard.Write && utf8.ValidString(action.Text) && len(action.Text) <= p.Clipboard.MaxBytes && desktopActivationConsent(p.Clipboard.RequireActivation, p.Clipboard.RequireConsent, action) {
			return nil
		}
	case DesktopActionUpload:
		return authorizeDesktopTransfer(p.Upload, action)
	case DesktopActionDownload:
		return authorizeDesktopTransfer(p.Download, action)
	case DesktopActionMicrophone, DesktopActionCamera, DesktopActionDevice:
		return ErrForbidden
	}
	return ErrForbidden
}

func desktopActivationConsent(requireActivation, requireConsent bool, action DesktopPolicyAction) bool {
	return (!requireActivation || action.HasUserActivation) && (!requireConsent || action.Consent)
}

func authorizeDesktopTransfer(policy DesktopTransferPolicy, action DesktopPolicyAction) error {
	if !policy.Enabled || !desktopActivationConsent(policy.RequireActivation, policy.RequireConsent, action) || len(action.Files) < 1 || len(action.Files) > policy.MaxFiles {
		return ErrForbidden
	}
	var total int64
	seenIDs := make(map[string]struct{}, len(action.Files))
	seenPaths := make(map[string]struct{}, len(action.Files))
	for _, file := range action.Files {
		if !validIdentifier(file.TransferID) || !validDesktopTransferPath(file.Path) || !slices.Contains(policy.AllowedMediaTypes, file.MediaType) || !validDigest(file.Digest) || file.SizeBytes < 0 || file.SizeBytes > policy.MaxFileBytes {
			return ErrForbidden
		}
		if _, duplicate := seenIDs[file.TransferID]; duplicate {
			return ErrForbidden
		}
		if _, duplicate := seenPaths[file.Path]; duplicate {
			return ErrForbidden
		}
		seenIDs[file.TransferID] = struct{}{}
		seenPaths[file.Path] = struct{}{}
		total += file.SizeBytes
		if total < 0 || total > policy.MaxTotalBytes {
			return ErrForbidden
		}
	}
	return nil
}

func validDesktopTransferPath(value string) bool {
	if !utf8.ValidString(value) || len(value) < len("/workspace/a") || len(value) > MaxDesktopTransferPathBytes || !strings.HasPrefix(value, "/workspace/") || strings.ContainsAny(value, "\\\x00\r\n") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, "/workspace/"), "/") {
		if component == "" || component == "." || component == ".." || utf8.RuneCountInString(component) > 255 {
			return false
		}
	}
	return true
}

func validDesktopMediaType(value string) bool {
	if len(value) < 3 || len(value) > 127 || strings.Count(value, "/") != 1 || strings.ContainsAny(value, " ;\t\r\n") {
		return false
	}
	parts := strings.Split(value, "/")
	return parts[0] != "" && parts[1] != ""
}
