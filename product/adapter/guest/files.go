package productguest

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestfiles "github.com/shell-echo/sandbox-runtime/guestagent/files"
	"github.com/shell-echo/sandbox-runtime/product"
)

type FileClient struct {
	hub     *guestagent.Hub
	timeout time.Duration
}

func NewFileClient(hub *guestagent.Hub, timeout time.Duration) (*FileClient, error) {
	if hub == nil || timeout < time.Second || timeout > 30*time.Second {
		return nil, product.ErrInvalid
	}
	return &FileClient{hub: hub, timeout: timeout}, nil
}

func (c *FileClient) List(ctx context.Context, tenantID, workspaceID, slotKey, guestPath, after string, limit int) (product.FilePage, product.FileAuthority, error) {
	callCtx, cancel := bounded(ctx, c.timeout)
	defer cancel()
	document, identity, err := c.hub.CallWithIdentity(callCtx, tenantID, workspaceID, slotKey, guestfiles.CapabilityList, guestfiles.ListRequest{Path: guestPath, AfterName: after, Limit: limit})
	if err != nil {
		return product.FilePage{}, product.FileAuthority{}, fileCallError(err)
	}
	var response guestfiles.ListResponse
	if guestagent.DecodeStrict(document, &response) != nil || len(response.Items) > limit {
		return product.FilePage{}, product.FileAuthority{}, product.ErrStoreUnavailable
	}
	items, err := projectEntries(response.Items)
	return product.FilePage{Items: items, NextAfter: response.NextAfter}, fileAuthority(identity), err
}

func (c *FileClient) Stat(ctx context.Context, tenantID, workspaceID, slotKey, guestPath string) (product.FileEntry, product.FileAuthority, error) {
	callCtx, cancel := bounded(ctx, c.timeout)
	defer cancel()
	document, identity, err := c.hub.CallWithIdentity(callCtx, tenantID, workspaceID, slotKey, guestfiles.CapabilityStat, guestfiles.StatRequest{Path: guestPath})
	if err != nil {
		return product.FileEntry{}, product.FileAuthority{}, fileCallError(err)
	}
	var response guestfiles.Entry
	if guestagent.DecodeStrict(document, &response) != nil {
		return product.FileEntry{}, product.FileAuthority{}, product.ErrStoreUnavailable
	}
	entry, err := projectEntry(response)
	return entry, fileAuthority(identity), err
}

func (c *FileClient) Snapshot(ctx context.Context, tenantID, workspaceID, slotKey, guestPath string) (product.FileSnapshot, error) {
	callCtx, cancel := bounded(ctx, c.timeout)
	defer cancel()
	document, identity, err := c.hub.CallWithIdentity(callCtx, tenantID, workspaceID, slotKey, guestfiles.CapabilitySnapshot, guestfiles.SnapshotRequest{Path: guestPath})
	if err != nil {
		return product.FileSnapshot{}, fileCallError(err)
	}
	var response guestfiles.SnapshotResponse
	if guestagent.DecodeStrict(document, &response) != nil || len(response.Entries) > guestfiles.MaxSnapshotEntries {
		return product.FileSnapshot{}, product.ErrStoreUnavailable
	}
	entries, err := projectEntries(response.Entries)
	if err != nil {
		return product.FileSnapshot{}, err
	}
	return product.FileSnapshot{Authority: fileAuthority(identity), Entries: entries}, nil
}

func projectEntries(values []guestfiles.Entry) ([]product.FileEntry, error) {
	entries := make([]product.FileEntry, 0, len(values))
	for _, value := range values {
		entry, err := projectEntry(value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func projectEntry(value guestfiles.Entry) (product.FileEntry, error) {
	modified, err := time.Parse(time.RFC3339Nano, value.ModifiedAt)
	if err != nil || (value.Type != "file" && value.Type != "directory" && value.Type != "symlink" && value.Type != "special") {
		return product.FileEntry{}, product.ErrStoreUnavailable
	}
	return product.FileEntry{Path: value.Path, Name: value.Name, Type: value.Type, Mode: value.Mode, SizeBytes: value.SizeBytes, ModifiedAt: modified, Revision: value.Revision}, nil
}

func fileAuthority(identity guestagent.Identity) product.FileAuthority {
	return product.FileAuthority{TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID, SlotKey: identity.SlotKey, GuestID: identity.GuestID, SlotGeneration: identity.SlotGeneration, BindingGeneration: identity.BindingGeneration}
}

func bounded(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) <= duration {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, duration)
}

func fileCallError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, guestagent.ErrCapabilityMissing) {
		return product.ErrCapabilityUnsupported
	}
	return product.ErrStoreUnavailable
}

var _ product.FileGuest = (*FileClient)(nil)
