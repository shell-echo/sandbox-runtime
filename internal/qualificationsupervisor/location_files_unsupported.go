//go:build !darwin && !linux

package qualificationsupervisor

import (
	"context"
	"os"
)

func openDirectoryPin(context.Context, string) (*directoryPin, error) {
	return nil, ErrUnsupportedPlatform
}
func admissibleProfile(os.FileInfo) bool                    { return false }
func admissibleDirectory(os.FileInfo, bool) bool            { return false }
func sameDirectory(os.FileInfo, os.FileInfo) bool           { return false }
func sameProfileSnapshot(os.FileInfo, os.FileInfo) bool     { return false }
func createStateDirectory(*os.File, string) (bool, error)   { return false, ErrUnsupportedPlatform }
func stateMatchesParent(*os.File, string, os.FileInfo) bool { return false }
