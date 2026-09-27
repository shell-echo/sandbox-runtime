package phase6security

import "strings"

const (
	ImageIdentityLocalConfig = "local_config"
	ImageIdentityOCIManifest = "oci_manifest"
	ImageIdentityOCIIndex    = "oci_index"
)

type ImageDescriptor struct {
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func expectedImageDescriptor(kind, digest string) ImageDescriptor {
	switch kind {
	case ImageIdentityOCIIndex:
		return ImageDescriptor{MediaType: "application/vnd.oci.image.index.v1+json", Digest: digest}
	case ImageIdentityOCIManifest:
		return ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: digest}
	default:
		return ImageDescriptor{}
	}
}

// Kind names the OCI object type; location names how it is addressed. A
// containerd-backed local candidate may be a manifest or index and is launched
// by its full store descriptor digest, never a tag. local_config is reserved
// for a separately proven classic-store config-addressable path.
func validImageIdentity(location, kind, reference, digest, platform, selectedManifest, configDigest string) bool {
	if !digestPattern.MatchString(digest) || !imagePlatformPattern.MatchString(platform) {
		return false
	}
	switch location {
	case "local":
		if reference != digest {
			return false
		}
	case "registry":
		if !imagePattern.MatchString(reference) || !strings.HasSuffix(reference, "@"+digest) || kind == ImageIdentityLocalConfig {
			return false
		}
	default:
		return false
	}
	switch kind {
	case ImageIdentityLocalConfig:
		return location == "local" && selectedManifest == "" && configDigest == ""
	case ImageIdentityOCIManifest:
		return selectedManifest == "" && digestPattern.MatchString(configDigest) && configDigest != digest
	case ImageIdentityOCIIndex:
		return digestPattern.MatchString(selectedManifest) && selectedManifest != digest &&
			digestPattern.MatchString(configDigest) && configDigest != selectedManifest && configDigest != digest
	default:
		return false
	}
}
