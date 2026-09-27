package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
)

func main() {
	var source, output string
	flag.StringVar(&source, "allowlist", "", "absolute private canonical account allowlist")
	flag.StringVar(&output, "output", "", "absolute private new build context")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected Desktop Phase 6 account build arguments")
		os.Exit(1)
	}
	if err := run(source, output); err != nil {
		fmt.Fprintf(os.Stderr, "invalid Desktop Phase 6 account build input: %v\n", err)
		os.Exit(1)
	}
}

func run(source, output string) error {
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return fmt.Errorf("build context path: %w", desktopcandidate.ErrInvalidAccounts)
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("build context mode: %w", desktopcandidate.ErrInvalidAccounts)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return fmt.Errorf("build context owner: %w", desktopcandidate.ErrInvalidAccounts)
	}
	accounts, err := desktopcandidate.LoadAccountAllowlist(source)
	if err != nil {
		return fmt.Errorf("load allowlist: %w", err)
	}
	passwd, group, err := accounts.NSSFragments()
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(accounts)
	if err != nil {
		return err
	}
	for name, contents := range map[string][]byte{
		"workload-accounts.json": canonical,
		"workload.passwd":        passwd,
		"workload.group":         group,
	} {
		file, openErr := os.OpenFile(filepath.Join(output, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if openErr != nil {
			return openErr
		}
		if _, writeErr := file.Write(contents); writeErr != nil {
			file.Close()
			return writeErr
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return err
		}
	}
	digest, err := accounts.Digest()
	if err != nil {
		return err
	}
	fmt.Println("workload_account_digest=" + digest)
	return nil
}
