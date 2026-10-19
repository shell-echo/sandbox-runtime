//go:build darwin || linux

package controlstorage

const kernelRootProtocol = "sandbox-runtime.control-storage-kernel-root.v1"

// Persistent identity deliberately omits mount ID: a new mount namespace may
// remount the SAME filesystem root. None of these facts attests external quota
// enforcement, exclusive Docker ownership or absence of host-level writers.
type kernelRootIdentity struct {
	Protocol     string   `json:"protocol"`
	Root         identity `json:"root"`
	Filesystem   string   `json:"filesystem"`
	FilesystemID [2]int32 `json:"filesystem_id"`
	SourceDigest string   `json:"source_digest"`
	DataBytes    int64    `json:"data_bytes"`
	BlockBytes   int64    `json:"block_bytes"`
	Inodes       uint64   `json:"inodes"`
	MountFlags   uint64   `json:"mount_flags"`
}

type kernelRootSession struct {
	Identity kernelRootIdentity
	MountID  uint64
}

func (s *Store) bindKernelRoot(initial bool) error {
	observed, available, err := readKernelRoot(s.fd, s.path)
	if err != nil || observed.Identity.Root != s.root || (initial && available < s.current.Binding.Layout.Coding.CodingQuotaBytes) {
		return ErrInvalid
	}
	s.kernel = &observed
	return nil
}

func (s *Store) checkKernelRoot() error {
	if s.kernel == nil {
		return ErrInvalid
	}
	observed, _, err := readKernelRoot(s.fd, s.path)
	if err != nil || observed != *s.kernel {
		return ErrInvalid
	}
	return nil
}
