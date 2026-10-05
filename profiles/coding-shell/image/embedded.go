package image

import _ "embed"

//go:embed manifest.json
var embeddedManifest []byte

// LockedManifest gives runtime composition the same validated source manifest
// as the image build without depending on a mutable on-disk checkout.
func LockedManifest() (Manifest, error) { return Parse(embeddedManifest) }
