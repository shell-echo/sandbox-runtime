package main

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestSourceModeCannotAcceptLegacyPermissions(t *testing.T) {
	old, _ := backendMode("legacy")
	next, _ := backendMode("source-v2")
	a := unix.Stat_t{Mode: unix.S_IFREG | 0o600, Nlink: 1}
	b := unix.Stat_t{Mode: unix.S_IFREG | 0o640, Gid: 57011, Nlink: 1}
	if !old.privateFile(a) || next.privateFile(a) || old.privateFile(b) || !next.privateFile(b) || old.protocol == next.protocol {
		t.Fatal("source mode promoted legacy")
	}
	for _, mode := range []string{"", "source", "v2"} {
		if _, e := backendMode(mode); e == nil {
			t.Fatal("ambiguous mode")
		}
	}
	b.Uid = 57010
	if next.privateFile(b) {
		t.Fatal("Control can chmod source into writable")
	}
}
