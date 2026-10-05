package image

// These values are from the published OCI index and its two selected manifest
// config descriptors. They are not derived from the local daemon's index ID or
// the caller's environment. A new image publication must update this lock.
const (
	PublishedDescriptorSize    int64 = 670
	PublishedManifestSize      int64 = 668
	PublishedAMD64ConfigDigest       = "sha256:e30a8623754c11150c90ce242202aed45e0fa3b9c07f033f10aa0b01c2a1461a"
	PublishedARM64ConfigDigest       = "sha256:eb764728c62bef0c3ad87bf76d51e7c06e652c4e8ba77656520e9d8abadce97c"
	PublishedImagePath               = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

func LockedConfigDigest(platform string) string {
	switch platform {
	case "linux/amd64":
		return PublishedAMD64ConfigDigest
	case "linux/arm64/v8":
		return PublishedARM64ConfigDigest
	default:
		return ""
	}
}

func LockedRuntimeEnvironment() []string {
	return []string{"PATH=" + PublishedImagePath, "HOME=/workspace", "SHELL=/bin/sh", "TMPDIR=/tmp"}
}
