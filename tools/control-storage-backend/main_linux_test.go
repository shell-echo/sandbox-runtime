package main

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestLoopBindingRejectsReplacementAndLazyDetach(t *testing.T) {
	r := record{FileDevice: 123, FileInode: 456, Bytes: size}
	s := unix.LoopInfo64{Device: 123, Inode: 456, Number: 7, Sizelimit: size}
	if !sameBacking(r, s, 7) {
		t.Fatal("exact synthetic mapping rejected")
	}
	for name, change := range map[string]func(*unix.LoopInfo64){
		"backing inode": func(s *unix.LoopInfo64) { s.Inode++ }, "backing device": func(s *unix.LoopInfo64) { s.Device++ },
		"wrong loop": func(s *unix.LoopInfo64) { s.Number++ }, "offset": func(s *unix.LoopInfo64) { s.Offset = 4096 },
		"unbounded": func(s *unix.LoopInfo64) { s.Sizelimit = 0 }, "resize": func(s *unix.LoopInfo64) { s.Sizelimit++ },
		"lazy autoclear": func(s *unix.LoopInfo64) { s.Flags = unix.LO_FLAGS_AUTOCLEAR },
	} {
		t.Run(name, func(t *testing.T) {
			v := s
			change(&v)
			if sameBacking(r, v, 7) {
				t.Fatal("unsafe mapping accepted")
			}
		})
	}
}
