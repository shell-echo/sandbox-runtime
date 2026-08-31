package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	execWrapper   = `pid_file="$1"; shift; "$@" & child=$!; printf '%s\n' "$child" > "$pid_file" || exit 125; wait "$child"; status=$?; rm -f "$pid_file"; exit "$status"`
	cancelWrapper = `test -r "$1" || exit 3; pid=$(cat "$1") || exit 4; kill -TERM "$pid"`
)

func main() {
	var err error
	switch filepath.Base(os.Args[0]) {
	case "sh":
		err = runProviderShell(os.Args[1:])
	case "e2e-workload":
		err = runWorkload(os.Args[1:])
	case "e2e-shell":
		err = runTerminalShell()
	default:
		err = errors.New("unknown reference runtime entrypoint")
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runProviderShell(args []string) error {
	if len(args) < 2 || args[0] != "-c" {
		return errors.New("reference /bin/sh accepts only the Provider wrapper form")
	}
	script := args[1]
	switch {
	case strings.HasPrefix(script, "trap 'exit 0' TERM INT; while :;"):
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
		<-signals
		return nil
	case script == execWrapper:
		return runExecWrapper(args[2:])
	case script == cancelWrapper:
		return runCancelWrapper(args[2:])
	default:
		return errors.New("reference /bin/sh rejected an unknown script")
	}
}

func runExecWrapper(args []string) error {
	if len(args) < 3 || args[0] != "sandbox-runtime-exec" {
		return errors.New("invalid Provider exec wrapper arguments")
	}
	pidFile := args[1]
	command := exec.Command(args[2], args[3:]...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return err
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(command.Process.Pid)+"\n"), 0o600); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return err
	}
	err := command.Wait()
	_ = os.Remove(pidFile)
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		os.Exit(exitError.ExitCode())
	}
	return err
}

func runCancelWrapper(args []string) error {
	if len(args) != 2 || args[0] != "sandbox-runtime-cancel" {
		return errors.New("invalid Provider cancel wrapper arguments")
	}
	content, err := os.ReadFile(args[1])
	if err != nil {
		os.Exit(3)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || pid < 1 {
		os.Exit(4)
	}
	return syscall.Kill(pid, syscall.SIGTERM)
}

func runWorkload(args []string) error {
	if len(args) == 0 {
		return errors.New("reference workload command is required")
	}
	switch args[0] {
	case "write-output":
		if err := os.WriteFile("/outputs/report.json", []byte("{\"ok\":true}\n"), 0o600); err != nil {
			return err
		}
		_, err := fmt.Fprintln(os.Stdout, "exec-ok")
		return err
	case "sleep":
		if len(args) != 2 {
			return errors.New("sleep duration is required")
		}
		seconds, err := strconv.Atoi(args[1])
		if err != nil || seconds < 1 || seconds > 60 {
			return errors.New("sleep duration is invalid")
		}
		time.Sleep(time.Duration(seconds) * time.Second)
		return nil
	case "true":
		return nil
	default:
		return errors.New("unknown reference workload command")
	}
}

func runTerminalShell() error {
	reader := bufio.NewReaderSize(os.Stdin, 64<<10)
	marker := ""
	_, _ = fmt.Fprint(os.Stdout, "$ ")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "exit":
			return nil
		case strings.Contains(line, "export E2E_RESTART_MARKER=survived") && strings.Contains(line, "initial:%s"):
			marker = "survived"
			_, err = fmt.Fprintf(os.Stdout, "initial:%s\r\n", marker)
		case strings.Contains(line, "resume:%s"):
			_, err = fmt.Fprintf(os.Stdout, "resume:%s\r\n", marker)
		case strings.Contains(line, "revoke-ready"):
			_, err = fmt.Fprint(os.Stdout, "revoke-ready\r\n")
		default:
			_, err = fmt.Fprint(os.Stdout, "unsupported\r\n")
		}
		if err != nil {
			return err
		}
		_, _ = fmt.Fprint(os.Stdout, "$ ")
	}
}
