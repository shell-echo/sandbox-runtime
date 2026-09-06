package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	providercaller "github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "", "downstream-fencing caller JSON configuration")
	providerBootstrapConfigPath := flag.String("provider-bootstrap-config", "", "Browser Provider bootstrap JSON configuration")
	flag.Parse()
	if *configPath == "" || *providerBootstrapConfigPath == "" || flag.NArg() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing caller configuration required")
		return 2
	}
	provisioningFiles, err := caller.OpenInheritedProvisioning()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing caller provisioning required")
		return 2
	}
	defer provisioningFiles.Close()
	config, configErr := caller.LoadBootstrapCallerConfig(*configPath)
	providerConfig, providerConfigErr := providercaller.LoadBrowserBootstrapConfig(*providerBootstrapConfigPath)
	if configErr != nil || providerConfigErr != nil {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing caller configuration invalid")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	stopInputCloser := make(chan struct{})
	defer close(stopInputCloser)
	go func() {
		select {
		case <-ctx.Done():
			_ = os.Stdin.Close()
		case <-stopInputCloser:
		}
	}()
	if err := caller.RunProvisioned(ctx, config, providerConfig, provisioningFiles, os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing caller failed")
		return 1
	}
	return 0
}
