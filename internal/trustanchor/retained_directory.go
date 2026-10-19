package trustanchor

// FileIdentity is the observed kernel identity of a retained CA directory or
// its sole bundle. Mode contains permission and special bits, without type.
type FileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
}

// DirectoryObservation contains only metadata and the digest of original CA
// bytes. It is evidence about one retained mount, not startup authority.
type DirectoryObservation struct {
	BundleDigest string       `json:"bundle_digest"`
	Directory    FileIdentity `json:"directory"`
	File         FileIdentity `json:"file"`
	MountID      uint64       `json:"mount_id"`
}
