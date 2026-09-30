//go:build linux

package phase6fdloader

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const startupDeadline = 30 * time.Second

var (
	ErrStartupInput = errors.New("phase6-fd-loader: input")
	ErrStartupFD    = errors.New("phase6-fd-loader: fd")
	ErrStartupExec  = errors.New("phase6-fd-loader: exec")
)

// Launch replaces this PID with the fixed repository-owned role executable.
// The operator must create a non-restarting, non-TTY container, inspect its
// full ID/image/entrypoint, attach one bounded envelope, then close stdin.
func Launch() error {
	if len(os.Args) != 1 {
		return ErrStartupInput
	}
	if verifyReservedSlots() != nil || unsafeStartupEnvironment(os.Environ()) {
		return ErrStartupFD
	}
	hostname, err := os.Hostname()
	if err != nil {
		return ErrStartupInput
	}
	expected := Expected{RunID: os.Getenv("SR_PHASE6_FD_RUN_ID"),
		Target: os.Getenv("SR_PHASE6_FD_TARGET"), Nonce: os.Getenv("SR_PHASE6_FD_NONCE"),
		ContainerHostname: hostname}
	if _, ok := SpecificationFor(expected.Target); !ok {
		return ErrStartupInput
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, startupDeadline)
	defer cancel()
	readFinished := make(chan struct{})
	readWatcherDone := make(chan struct{})
	go func() {
		defer close(readWatcherDone)
		select {
		case <-ctx.Done():
			_ = os.Stdin.Close()
		case <-readFinished:
		}
	}()
	value, err := Decode(os.Stdin, expected)
	close(readFinished)
	<-readWatcherDone
	if err != nil || ctx.Err() != nil {
		value.Destroy()
		return ErrStartupInput
	}
	defer value.Destroy()
	if err := execWithSealedFDs(ctx, value); err != nil {
		return err
	}
	return nil // syscall.Exec cannot return on success.
}

type sealedFD struct {
	destination int
	source      int
}

func execWithSealedFDs(ctx context.Context, value Envelope) error {
	spec, ok := SpecificationFor(value.Target)
	if !ok || len(value.Files) != len(spec.Descriptors) {
		return ErrStartupFD
	}
	files := make([]sealedFD, 0, 1+len(value.Files))
	defer func() {
		for _, file := range files {
			if file.source >= 0 {
				_ = unix.Close(file.source)
			}
		}
	}()
	inputs := make([]struct {
		fd   int
		name string
		data []byte
	}, 0, 1+len(value.Files))
	inputs = append(inputs, struct {
		fd   int
		name string
		data []byte
	}{0, "canonical-config", value.Config})
	for index, file := range value.Files {
		inputs = append(inputs, struct {
			fd   int
			name string
			data []byte
		}{file.FD, spec.Descriptors[index].Purpose, file.Data})
	}
	for _, input := range inputs {
		if ctx.Err() != nil {
			return ErrStartupFD
		}
		source, err := sealedPrivateMemFD(input.name, input.data)
		if err != nil {
			return ErrStartupFD
		}
		files = append(files, sealedFD{destination: input.fd, source: source})
	}
	if ctx.Err() != nil {
		return ErrStartupFD
	}
	environment := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SR_PHASE6_FD_") {
			environment = append(environment, entry)
		}
	}
	if ctx.Err() != nil {
		return ErrStartupFD
	}
	value.Destroy()
	// A fixed pre-Go shell trampoline has reserved FD3..FD6 as /dev/null;
	// the Go runtime cannot own these numbers. Unused slots stay reserved until
	// exec and are removed from the role by FD_CLOEXEC.
	mapped := make([]int, 0, len(files))
	for _, file := range files {
		if err := unix.Dup3(file.source, file.destination, 0); err != nil {
			for _, fd := range mapped {
				_ = unix.Close(fd)
			}
			return ErrStartupFD
		}
		mapped = append(mapped, file.destination)
	}
	for index := range files {
		_ = unix.Close(files[index].source)
		files[index].source = -1
	}
	for fd := 3; fd <= 6; fd++ {
		used := false
		for _, file := range mapped {
			if file == fd {
				used = true
			}
		}
		if !used {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
				for _, mappedFD := range mapped {
					_ = unix.Close(mappedFD)
				}
				return ErrStartupFD
			}
		}
	}
	if ctx.Err() != nil {
		for _, fd := range mapped {
			_ = unix.Close(fd)
		}
		return ErrStartupFD
	}
	if err := syscall.Exec(RolePath, []string{RolePath}, environment); err != nil {
		for _, fd := range mapped {
			_ = unix.Close(fd)
		}
		return ErrStartupExec
	}
	return nil
}

func verifyReservedSlots() error {
	var null unix.Stat_t
	if err := unix.Stat("/dev/null", &null); err != nil || null.Mode&unix.S_IFMT != unix.S_IFCHR {
		return ErrStartupFD
	}
	for fd := 3; fd <= 6; fd++ {
		var observed unix.Stat_t
		flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		inherit, inheritErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if unix.Fstat(fd, &observed) != nil || flagErr != nil || inheritErr != nil ||
			observed.Mode&unix.S_IFMT != unix.S_IFCHR || observed.Rdev != null.Rdev ||
			flags&unix.O_ACCMODE != unix.O_RDONLY || inherit&unix.FD_CLOEXEC != 0 {
			return ErrStartupFD
		}
	}
	return nil
}

func unsafeStartupEnvironment(entries []string) bool {
	for _, entry := range entries {
		name, _, hasValue := strings.Cut(entry, "=")
		if !hasValue || name == "ENV" || name == "BASH_ENV" || name == "ASH_ENV" || name == "IFS" ||
			strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") ||
			strings.HasPrefix(name, "MALLOC_") || name == "GCONV_PATH" || name == "GLIBC_TUNABLES" {
			return true
		}
	}
	return false
}

func sealedPrivateMemFD(name string, contents []byte) (int, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if err != nil {
		return -1, err
	}
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return -1, err
	}
	for remaining := contents; len(remaining) != 0; {
		count, err := unix.Write(fd, remaining)
		if err == unix.EINTR {
			continue
		}
		if err != nil || count < 1 {
			return -1, ErrStartupFD
		}
		remaining = remaining[count:]
	}
	if offset, err := unix.Seek(fd, 0, io.SeekStart); err != nil || offset != 0 {
		return -1, ErrStartupFD
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		return -1, err
	}
	if observed, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0); err != nil || observed != seals {
		return -1, ErrStartupFD
	}
	reserved, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 32)
	if err != nil || reserved < 32 {
		return -1, ErrStartupFD
	}
	return reserved, nil
}
