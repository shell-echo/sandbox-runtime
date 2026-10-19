// Package phase6process collects bounded operator evidence of namespace PID 1.
// It is not runtime admission: a trusted operator must also bracket the probe
// with daemon container ID, image, PID and StartedAt observations. Docker exec
// is an explicit operator action, never part of the GET-only runtime collector.
package phase6process

import (
	"errors"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrIdentity = errors.New("service process identity unavailable")

type Observation struct {
	Executable      string   `json:"executable"`
	Digest          string   `json:"digest"`
	Device          uint64   `json:"device"`
	Inode           uint64   `json:"inode"`
	StartTicks      uint64   `json:"start_ticks"`
	Args            []string `json:"args"`
	UIDs            []uint32 `json:"uids"`
	GIDs            []uint32 `json:"gids"`
	Groups          []uint32 `json:"groups"`
	NamespacePIDs   []uint32 `json:"namespace_pids"`
	Capabilities    []uint64 `json:"capabilities"`
	NoNewPrivileges uint32   `json:"no_new_privileges"`
	Seccomp         uint32   `json:"seccomp"`
}

// Verify distinguishes the one-shot loader from the role. Neither is a
// service-ready claim, source provenance, or proof of the full consumer graph.
func Verify(o Observation, s phase6security.ControlServiceIdentityV1, stage string) error {
	path, digest, args := phase6fdloader.RolePath, s.Launch.ExecutableDigest, s.ProcessArgs
	if stage == "loader" && s.Launch.LoaderDigest != "" {
		path, digest, args = phase6fdloader.LoaderPath, s.Launch.LoaderDigest, []string{phase6fdloader.LoaderPath}
	} else if stage != "role" {
		return ErrIdentity
	}
	if o.Executable != path || o.Digest != digest || o.Inode == 0 || o.StartTicks == 0 || !slices.Equal(o.Args, args) || !slices.Equal(o.UIDs, []uint32{s.Principal.UID, s.Principal.UID, s.Principal.UID, s.Principal.UID}) || !slices.Equal(o.GIDs, []uint32{s.Principal.GID, s.Principal.GID, s.Principal.GID, s.Principal.GID}) || !slices.Equal(o.Groups, s.Groups) || len(o.NamespacePIDs) == 0 || o.NamespacePIDs[len(o.NamespacePIDs)-1] != 1 || !slices.Equal(o.Capabilities, []uint64{0, 0, 0, 0, 0}) || o.NoNewPrivileges != 1 || o.Seccomp != 2 {
		return ErrIdentity
	}
	return nil
}
