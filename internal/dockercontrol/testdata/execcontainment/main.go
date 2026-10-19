//go:build linux

// This adversarial fixture is never installed in a product image. It forks a
// new session twice, orphans a writer, and closes inherited output streams so
// neither exec attach EOF nor the direct child's exit can stand for quiescence.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type identity struct {
	PID, PPID, SID, UID, GID int
	PIDNamespace             string
}

func main() {
	// Even failed assertions or a lost Docker response leave bounded work.
	time.AfterFunc(90*time.Second, func() { os.Exit(124) })
	if len(os.Args) != 3 || os.Getuid() != 57000 || os.Getgid() != 58000 {
		os.Exit(100)
	}
	mode, dir := os.Args[1], os.Args[2]
	if dir != "/probe/negative" && dir != "/probe/killed" && dir != "/probe/natural" {
		os.Exit(101)
	}
	if err := run(mode, dir); err != nil {
		// No raw host paths, process environments, or daemon diagnostics.
		fmt.Fprintln(os.Stderr, "containment fixture failed")
		os.Exit(102)
	}
}

func run(mode, dir string) error {
	switch mode {
	case "park":
		for {
			time.Sleep(time.Hour)
		}
	case "fork":
		if err := spawn("leaf", dir); err != nil {
			return err
		}
		return await(filepath.Join(dir, "leaf.json"))
	case "direct", "command":
		if mode == "command" && os.Getpid() != 1 {
			return fmt.Errorf("command is not PID 1")
		}
		if err := record(filepath.Join(dir, mode+".json")); err != nil {
			return err
		}
		if err := spawn("fork", dir); err != nil {
			return err
		}
		if err := await(filepath.Join(dir, "leaf.json")); err != nil {
			return err
		}
		for {
			if mode == "command" {
				if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
					return nil
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	case "leaf":
		// A direct-child TERM cannot reach this detached, orphaned process.
		signal.Ignore(syscall.SIGTERM)
		deadline := time.Now().Add(5 * time.Second)
		for os.Getppid() != 1 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
			// The intermediary waits for this marker before exiting.
			if err := record(filepath.Join(dir, "leaf.json")); err != nil {
				return err
			}
		}
		if os.Getppid() != 1 {
			return fmt.Errorf("writer was not orphaned")
		}
		if err := record(filepath.Join(dir, "leaf.json")); err != nil {
			return err
		}
		for n := uint64(1); ; n++ {
			if err := atomicFile(filepath.Join(dir, "counter"), []byte(strconv.FormatUint(n, 10))); err != nil {
				return err
			}
			time.Sleep(20 * time.Millisecond)
		}
	default:
		return fmt.Errorf("unknown fixture mode")
	}
}

func spawn(mode, dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, mode, dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// nil stdio goes to /dev/null, not the wrapper's capture connection.
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func record(path string) error {
	sid, _, errno := syscall.Syscall(syscall.SYS_GETSID, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	ns, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return err
	}
	b, err := json.Marshal(identity{os.Getpid(), os.Getppid(), int(sid), os.Getuid(), os.Getgid(), ns})
	if err != nil {
		return err
	}
	return atomicFile(path, b)
}

func atomicFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".counter-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func await(path string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("fixture readiness deadline")
}
