//go:build !darwin && !linux

package qualificationsupervisor

import "os"

func spawnProcess(*launchCore) (*os.Process, error)   { return nil, ErrUnsupportedPlatform }
func terminateProcess(*os.Process, int) (bool, error) { return false, ErrUnsupportedPlatform }
func processGroupAbsent(int) bool                     { return false }
func pollProcessExit(*os.Process, int) (bool, bool, error) {
	return false, false, ErrUnsupportedPlatform
}
