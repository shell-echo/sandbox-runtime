//go:build !darwin && !linux

package qualificationsupervisor

import "os"

func openNoFollow(string) (*os.File, error)  { return nil, ErrUnsupportedPlatform }
func admissibleFile(os.FileInfo, int64) bool { return false }
