package main

import "golang.org/x/sys/unix"

// Explicit fresh diagnostic mode; never repairs or upgrades a legacy seal.
type backendPolicy struct {
	protocol               string
	gid, dirMode, fileMode uint32
}

func backendMode(mode string) (backendPolicy, error) {
	switch mode {
	case "legacy":
		return backendPolicy{"sandbox-runtime.control-backend-provision.v1", 0, 0o700, 0o600}, nil
	case "source-v2":
		return backendPolicy{"sandbox-runtime.control-backend-source-provision.v2", 57011, 0o750, 0o640}, nil
	default:
		return backendPolicy{}, invalid
	}
}
func (p backendPolicy) privateFile(s unix.Stat_t) bool {
	if p.gid == 0 {
		return privateFile(s)
	}
	return s.Mode == unix.S_IFREG|p.fileMode && s.Uid == 0 && s.Gid == p.gid && s.Nlink == 1
}
