//go:build !linux

package phase6guestreceipt

import "os"

// Slice 6 private receipt emission is admitted only in the Linux local
// candidate; other hosts fail closed rather than mutating stdout flags.
func openIndependentNonblockingPipe(*os.File) (int, error) {
	return -1, ErrUnavailable
}
