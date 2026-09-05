package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/gatewaystack"
)

func main() {
	configPath := flag.String("config", "", "downstream-fencing Gateway JSON configuration")
	flag.Parse()
	if *configPath == "" || flag.NArg() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, "exactly one -config value is required")
		os.Exit(2)
	}
	config, err := gatewaystack.LoadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing Gateway configuration rejected")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	stack, err := gatewaystack.Open(ctx, config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing Gateway startup failed")
		os.Exit(1)
	}
	if err := errors.Join(stack.Run(ctx), stack.Close()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "downstream-fencing Gateway stopped with an error")
		os.Exit(1)
	}
}
