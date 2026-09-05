package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	sharedstack "github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/stack"
)

func main() {
	configPath := flag.String("config", "", "shared-capacity Gateway JSON configuration")
	flag.Parse()
	if *configPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}
	config, err := sharedstack.LoadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	stack, err := sharedstack.Open(ctx, config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := errors.Join(stack.Run(ctx), stack.Close()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
