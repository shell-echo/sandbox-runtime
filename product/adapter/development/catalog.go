// Package development owns the repository-locked Product development
// template catalog. It selects immutable runtime publications; it does not
// expose registry credentials or Provider runtime coordinates.
package development

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/shell-echo/sandbox-runtime/product"
	codingshellimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

type LockedCatalog struct{}

func (LockedCatalog) Get(ctx context.Context, templateID string) (product.DevelopmentTemplate, error) {
	if ctx == nil || ctx.Err() != nil || templateID != product.DevelopmentTemplateID {
		return product.DevelopmentTemplate{}, product.ErrNotFound
	}
	publication := codingshellimage.LockedPublication()
	if publication.Validate() != nil {
		return product.DevelopmentTemplate{}, product.ErrCapabilityUnsupported
	}
	descriptor := struct {
		ID, RuntimeProfileID, Image string
		Mounts                      []product.DevelopmentMount
		Toolchains                  []product.DevelopmentToolchain
	}{
		ID: templateID, RuntimeProfileID: publication.RuntimeProfileID, Image: publication.Image(),
		Mounts: []product.DevelopmentMount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}},
		Toolchains: []product.DevelopmentToolchain{{
			ID: "posix-shell", Version: "alpine-3.23", Digest: publication.Digest, Executable: "/bin/sh",
		}},
	}
	document, _ := json.Marshal(descriptor)
	digest := sha256.Sum256(document)
	template := product.DevelopmentTemplate{
		ID: descriptor.ID, Revision: "sha256:" + hex.EncodeToString(digest[:]), RuntimeProfileID: descriptor.RuntimeProfileID,
		Image: descriptor.Image, Mounts: append([]product.DevelopmentMount(nil), descriptor.Mounts...),
		Toolchains: append([]product.DevelopmentToolchain(nil), descriptor.Toolchains...),
	}
	if template.Validate() != nil {
		return product.DevelopmentTemplate{}, product.ErrCapabilityUnsupported
	}
	return template, nil
}

var _ product.DevelopmentTemplateCatalog = LockedCatalog{}
