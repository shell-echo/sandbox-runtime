//go:build darwin || linux

// Local subprocess probe, not an external caller or protocol implementation.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var mode = "hang"

func main() {
	report := struct {
		Args, Env                                    []string
		Cwd                                          string
		Entries                                      int
		NewGroup, Directions, NoInput, WitnessClosed bool
	}{Args: os.Args, Env: os.Environ(), Directions: true, NoInput: true}
	var err error
	report.Cwd, err = os.Getwd()
	if err != nil {
		os.Exit(2)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		os.Exit(2)
	}
	report.Entries = len(entries)
	group, err := unix.Getpgid(0)
	report.NewGroup = err == nil && group == os.Getpid()
	for fd := 0; fd < 11; fd++ {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		read := fd == 0 || fd >= 3
		want := unix.O_WRONLY
		if read {
			want = unix.O_RDONLY
		}
		if err != nil || flags&unix.O_ACCMODE != want {
			report.Directions = false
		}
		if read {
			if unix.SetNonblock(fd, true) != nil {
				os.Exit(2)
			}
			var b [1]byte
			n, err := unix.Read(fd, b[:])
			if n > 0 || !errors.Is(err, unix.EAGAIN) {
				report.NoInput = false
			}
			if unix.SetNonblock(fd, false) != nil {
				os.Exit(2)
			}
		}
	}
	_, err = unix.FcntlInt(64, unix.F_GETFD, 0)
	report.WitnessClosed = errors.Is(err, unix.EBADF)
	// Publish the private stderr evidence before the stdout report. Tests that
	// consume the report can then know the evidence write happened without
	// relying on scheduler ordering between the two independent pipes.
	fmt.Fprintln(os.Stderr, "probe-stderr")
	if json.NewEncoder(os.Stdout).Encode(report) != nil {
		os.Exit(2)
	}
	if mode == "exit" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}
