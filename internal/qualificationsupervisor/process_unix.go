//go:build darwin || linux

package qualificationsupervisor

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func spawnProcess(l *launchCore) (*os.Process, error) {
	return os.StartProcess(l.path, append([]string{}, l.argv...), &os.ProcAttr{
		Dir: l.directory, Env: append([]string{}, l.environment...), Files: l.child[:],
		Sys: &syscall.SysProcAttr{Setpgid: true},
	})
}

func terminateProcess(p *os.Process, pid int) (bool, error) {
	errGroup := unix.Kill(-pid, unix.SIGKILL)
	errChild := p.Kill()
	// Darwin can return EPERM for a group whose leader has already exited.
	// Do not ignore permission denial: require observed group absence AFTER
	// reaping the owned child. The follow-up signal 0 cannot kill reused PIDs.
	needsAbsence := errors.Is(errGroup, unix.EPERM)
	if errGroup != nil && !errors.Is(errGroup, unix.ESRCH) && !needsAbsence {
		return false, ErrProcessCleanup
	}
	if errChild != nil && !errors.Is(errChild, os.ErrProcessDone) && !errors.Is(errChild, unix.ESRCH) {
		return needsAbsence, ErrProcessCleanup
	}
	return needsAbsence, nil
}

func processGroupAbsent(pid int) bool {
	return errors.Is(unix.Kill(-pid, 0), unix.ESRCH)
}

func pollProcessExit(p *os.Process, pid int) (bool, bool, error) {
	var status unix.WaitStatus
	for {
		waited, err := unix.Wait4(pid, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, false, err
		}
		if waited == 0 {
			return false, false, nil
		}
		if waited != pid {
			return false, false, ErrProcessCleanup
		}
		_ = p.Release()
		return true, status.Exited() && status.ExitStatus() == 0, nil
	}
}
