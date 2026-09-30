//go:build linux

// This probe is used only by the opt-in Docker component test. It exercises
// safe self-process memory syscalls under an explicitly supplied seccomp JSON.
package main

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		panic(err)
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(status), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found {
			fields[key] = strings.TrimSpace(value)
		}
	}
	// RemoteIovec stores a uintptr, which cannot keep a Go stack address
	// stable across a syscall. Use a fixed mmap page for the self target.
	page, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		panic(err)
	}
	defer unix.Munmap(page)
	remote := page[:6]
	copy(remote, "phase6")
	local := make([]byte, len(remote))
	readLocal := unix.Iovec{Base: &local[0]}
	readLocal.SetLen(len(local))
	readRemote := unix.RemoteIovec{Base: uintptr(unsafe.Pointer(&remote[0])), Len: len(remote)}
	readCount, readErr := unix.ProcessVMReadv(os.Getpid(), []unix.Iovec{readLocal}, []unix.RemoteIovec{readRemote}, 0)
	writeLocal := unix.Iovec{Base: &local[0]}
	writeLocal.SetLen(len(local))
	writeRemote := unix.RemoteIovec{Base: uintptr(unsafe.Pointer(&remote[0])), Len: len(remote)}
	writeCount, writeErr := unix.ProcessVMWritev(os.Getpid(), []unix.Iovec{writeLocal}, []unix.RemoteIovec{writeRemote}, 0)
	// PTRACE_TRACEME requests tracing only of this probe itself. Keep it last
	// so the successful baseline control cannot affect the memory syscalls.
	_, _, ptraceErr := unix.RawSyscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
	ptraceText := ""
	if ptraceErr != 0 {
		ptraceText = ptraceErr.Error()
	}
	runtime.KeepAlive(remote)
	runtime.KeepAlive(local)
	result := struct {
		UID         string `json:"uid"`
		GID         string `json:"gid"`
		CapEff      string `json:"cap_eff"`
		NoNewPrivs  string `json:"no_new_privs"`
		Seccomp     string `json:"seccomp"`
		ReadCount   int    `json:"read_count"`
		ReadError   string `json:"read_error"`
		WriteCount  int    `json:"write_count"`
		WriteError  string `json:"write_error"`
		PtraceError string `json:"ptrace_error"`
	}{UID: fields["Uid"], GID: fields["Gid"], CapEff: fields["CapEff"],
		NoNewPrivs: fields["NoNewPrivs"], Seccomp: fields["Seccomp"],
		ReadCount: readCount, ReadError: errorText(readErr), WriteCount: writeCount,
		WriteError: errorText(writeErr), PtraceError: ptraceText}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
