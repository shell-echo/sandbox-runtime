package controlstorage

// Host directories are not Linux Control mount evidence.
func readKernelRoot(int, string) (kernelRootSession, int64, error) {
	return kernelRootSession{}, 0, ErrInvalid
}
