package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/stack"
)

func main() {
	configPath := flag.String("config", "", "reference stack JSON configuration")
	flag.Parse()
	if *configPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}
	config, err := stack.LoadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	reference, err := stack.Open(ctx, config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	err = errors.Join(reference.Run(ctx, config.GatewayCertificateFile, config.GatewayPrivateKeyFile), reference.Close())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
