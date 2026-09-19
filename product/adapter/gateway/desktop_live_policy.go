package productgateway

import (
	"context"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/product"
)

// ProductTransferDesktopAuthority binds every public Desktop transfer
// descriptor to an already authorized, complete Product transfer. Object
// references and storage coordinates never cross this boundary.
type ProductTransferDesktopAuthority struct {
	Store DesktopTransferRecordStore
}

type DesktopTransferRecordStore interface {
	GetTransfer(context.Context, string, product.ActorRef, string) (product.TransferRecord, error)
}

func (a *ProductTransferDesktopAuthority) AuthorizeDesktopTransfer(ctx context.Context, binding product.GatewayBinding, action product.DesktopPolicyAction) error {
	if a == nil || nilInterface(a.Store) || (action.Kind != product.DesktopActionUpload && action.Kind != product.DesktopActionDownload) || len(action.Files) < 1 || len(action.Files) > product.MaxDesktopTransferFiles {
		return product.ErrForbidden
	}
	direction := "upload"
	if action.Kind == product.DesktopActionDownload {
		direction = "download"
	}
	for _, file := range action.Files {
		record, err := a.Store.GetTransfer(ctx, binding.TenantID, binding.Actor, file.TransferID)
		if err != nil || record.ID != file.TransferID || record.TenantID != binding.TenantID || record.Actor != binding.Actor || record.WorkspaceID != binding.WorkspaceID || record.Direction != direction || record.State != "complete" || record.Digest != file.Digest || record.SizeBytes != file.SizeBytes {
			return product.ErrForbidden
		}
	}
	return nil
}

type denyDesktopTransferAuthority struct{}

func (denyDesktopTransferAuthority) AuthorizeDesktopTransfer(context.Context, product.GatewayBinding, product.DesktopPolicyAction) error {
	return product.ErrForbidden
}

func validDesktopLiveInputResult(policy product.DesktopPolicy, action product.DesktopPolicyAction, result DesktopLiveInputResult) bool {
	if action.Kind == product.DesktopActionClipboardRead {
		return utf8.ValidString(result.Text) && len(result.Text) <= policy.Clipboard.MaxBytes
	}
	return result.Text == ""
}

var _ DesktopLiveTransferAuthority = (*ProductTransferDesktopAuthority)(nil)
var _ DesktopLiveTransferAuthority = denyDesktopTransferAuthority{}
